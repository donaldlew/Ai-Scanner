import os
import sys
import argparse
import json
import re
from dotenv import load_dotenv
from openai import OpenAI
from pydantic import BaseModel, Field

# Load environment variables from .env
load_dotenv()

# Initialize OpenAI client configured for OpenRouter
client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=os.getenv("OPENROUTER_API_KEY"),
)

# Pydantic schema for structured security findings
class SecurityFinding(BaseModel):
    vulnerability_name: str = Field(description="Name of the vulnerability, e.g., SQL Injection")
    cwe_id: str = Field(description="Associated CWE identifier, e.g., CWE-89")
    severity: str = Field(description="Severity level: Low, Medium, High, or Critical")
    explanation: str = Field(description="Brief explanation of why this code is vulnerable")
    secure_code_fix: str = Field(description="The corrected, secure version of the code snippet")

# Fallback model pipeline (tries active free models in order of reliability)
PRIMARY_MODELS = [
    "nvidia/nemotron-3.5-lightning:free",
    "thinkingmachines/inkling-small:free",
    "google/gemma-4-31b-it:free",
    "openrouter/free"  # Ultimate fallback auto-router
]

# Directories to ignore during recursive scans
IGNORED_DIRS = {".git", ".github", "venv", ".venv", "__pycache__", "node_modules", "build", "dist"}

# Binary, media, and archive extensions to skip (blacklist approach)
IGNORED_EXTENSIONS = {
    # Images & Media
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".mp4", ".mp3",
    # Binaries & Executables
    ".exe", ".dll", ".so", ".bin", ".o", ".pyc",
    # Archives & Compressed
    ".zip", ".tar", ".gz", ".rar", ".7z",
    # Documents & Fonts
    ".pdf", ".docx", ".xlsx", ".ttf", ".woff", ".woff2"
}

# Specific administrative or environment files to ignore locally
IGNORED_FILES = {".env", ".gitignore", "readme.md", "license", "package-lock.json"}

def analyze_code_content(file_path, code_content):
    """Sends code content to OpenRouter with fallback logic and returns the structured finding."""
    for model_name in PRIMARY_MODELS:
        try:
            print(f"  Attempting scan with model: {model_name}...")
            
            response = client.beta.chat.completions.parse(
                model=model_name,
                messages=[
                    {
                        "role": "system", 
                        "content": "You are an expert Application Security Engineer. Analyze code strictly for vulnerabilities and output structured data."
                    },
                    {
                        "role": "user", 
                        "content": f"Analyze this code for security vulnerabilities:\n\n{code_content}"
                    }
                ],
                response_format=SecurityFinding,
            )
            
            print(f"  ✅ Model used: {response.model}")
            return response.choices[0].message.parsed

        except Exception as e:
            print(f"  ⚠️ Model '{model_name}' failed schema parsing: {e}. Trying next model...")

    print(f"  ❌ All models failed for file: {file_path}")
    return None

def scan_single_file(file_path):
    """Scans an individual file and returns whether a high/critical vuln was found."""
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.")
        return False

    print(f"\n==========================================")
    print(f" Scanning File: {file_path}")
    print(f"==========================================\n")

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            code_content = f.read()
    except Exception as e:
        print(f"Error reading file '{file_path}': {e}")
        return False

    finding = analyze_code_content(file_path, code_content)
    if finding:
        print("\n--- Structured JSON Security Analysis ---")
        print(finding.model_dump_json(indent=2))
        
        severity_lower = finding.severity.lower()
        if "high" in severity_lower or "critical" in severity_lower:
            return True
            
    return False

def scan_directory(dir_path):
    """Recursively scans all text-based source files in a directory and enforces build failure on high/critical findings."""
    if not os.path.exists(dir_path):
        print(f"Error: Directory '{dir_path}' not found.")
        sys.exit(1)

    print(f"\n==========================================")
    print(f" Starting Directory Scan: {dir_path}")
    print(f"==========================================\n")

    scanned_count = 0
    high_critical_found = False

    for root, dirs, files in os.walk(dir_path):
        # Filter out ignored directories in-place
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]

        for file in files:
            # Skip administrative/metadata files
            if file.lower() in IGNORED_FILES:
                continue

            ext = os.path.splitext(file)[1].lower()
            
            # Skip known binary/media/archive extensions
            if ext in IGNORED_EXTENSIONS:
                continue

            full_path = os.path.join(root, file)
            
            # Try reading the file as text; skip gracefully if it's binary or unreadable
            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    code_content = f.read()
            except UnicodeDecodeError:
                continue
            except Exception:
                continue

            scanned_count += 1
            print(f"\n[{scanned_count}] Scanning: {full_path}")

            finding = analyze_code_content(full_path, code_content)
            if finding:
                print("\n--- Security Analysis Output ---")
                print(finding.model_dump_json(indent=2))
                
                # Check severity level to decide if build should fail
                severity_lower = finding.severity.lower()
                if "high" in severity_lower or "critical" in severity_lower:
                    high_critical_found = True
                    print(f"  🚨 SECURITY ALERT: {finding.severity.upper()} severity vulnerability detected in {full_path}!")

    print(f"\n✅ Completed directory scan. Total files scanned: {scanned_count}\n")

    # Enforce build failure gate
    if high_critical_found:
        print("❌ SECURITY GATE FAILED: High or Critical vulnerabilities detected. Blocking build.")
        sys.exit(1)
    else:
        print("🟢 SECURITY GATE PASSED: No High or Critical vulnerabilities found.")
        sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI-powered code security vulnerability scanner.")
    parser.add_argument("--file", help="Path to a single code file to scan.")
    parser.add_argument("--dir", help="Path to a directory/repo to recursively scan.")

    args = parser.parse_args()

    if args.file:
        failed = scan_single_file(args.file)
        sys.exit(1 if failed else 0)
    elif args.dir:
        scan_directory(args.dir)
    else:
        print("Error: Please specify either --file <path> or --dir <path>")
        sys.exit(1)