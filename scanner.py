import os
import sys
import argparse
import json
import re
from typing import TypedDict, List, Literal
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

# Pydantic schema for individual security findings with strict Literal severity
class SecurityFinding(BaseModel):
    vulnerability_name: str = Field(description="Name of the vulnerability, e.g., SQL Injection")
    cwe_id: str = Field(description="Associated CWE identifier, e.g., CWE-89")
    
    # Strictly constrain severity to exact supported values
    severity: Literal["Low", "Medium", "High", "Critical"] = Field(
        description="Severity level must be exactly one of: Low, Medium, High, or Critical"
    )
    
    explanation: str = Field(description="Brief explanation of why this code is vulnerable")
    secure_code_fix: str = Field(description="The corrected, secure version of the code snippet")

# Container model for zero, one, or multiple findings from the LLM
class ScanResults(BaseModel):
    findings: list[SecurityFinding] = Field(description="List of security vulnerabilities found in the code. Empty list if code is secure.")

# TypedDict for explicit type safety on local report items
class ReportFinding(TypedDict):
    file: str
    finding: SecurityFinding

# Fallback model pipeline (tries active free models in order of reliability)
PRIMARY_MODELS = [
    "nvidia/nemotron-3.5-lightning:free",
    "thinkingmachines/inkling-small:free",
    "google/gemma-4-31b-it:free",
    "openrouter/free"  # Ultimate fallback auto-router
]

# Directories to ignore during recursive scans
IGNORED_DIRS = {".git", ".github", "venv", ".venv", "__pycache__", "node_modules", "build", "dist", "security-reports"}

# Binary, media, archive, and documentation extensions to skip
IGNORED_EXTENSIONS = {
    # Images & Media
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".mp4", ".mp3",
    # Binaries & Executables
    ".exe", ".dll", ".so", ".bin", ".o", ".pyc",
    # Archives & Compressed
    ".zip", ".tar", ".gz", ".rar", ".7z",
    # Documents, Fonts & Markdown Documentation
    ".pdf", ".docx", ".xlsx", ".ttf", ".woff", ".woff2", ".md"
}

# Specific administrative or environment files to ignore locally
IGNORED_FILES = {".env", ".gitignore", "license", "package-lock.json"}

# Maximum file size limit (500 KB)
MAX_FILE_SIZE = 500 * 1024

def analyze_code_content(file_path, code_content):
    """Sends code content to OpenRouter with fallback logic. Returns a list of findings, or None if all models fail."""
    for model_name in PRIMARY_MODELS:
        try:
            print(f"  Attempting scan with model: {model_name}...")
            
            response = client.beta.chat.completions.parse(
                model=model_name,
                messages=[
                    {
                        "role": "system", 
                        "content": "You are an expert Application Security Engineer. Analyze code strictly for vulnerabilities and return structured data. If no vulnerabilities exist, return an empty findings list."
                    },
                    {
                        "role": "user", 
                        "content": f"Analyze this code for security vulnerabilities:\n\n{code_content}"
                    }
                ],
                response_format=ScanResults,
            )
            
            print(f"  ✅ Model used: {response.model}")
            return response.choices[0].message.parsed.findings

        except Exception as e:
            print(f"  ⚠️ Model '{model_name}' failed schema parsing: {e}. Trying next model...")

    print(f"  ❌ All models failed for file: {file_path}")
    return None  # Return None explicitly to indicate an analysis failure

def scan_directory(dir_path):
    """Recursively scans all valid source files and generates a markdown report in a dedicated folder."""
    if not os.path.exists(dir_path):
        print(f"Error: Directory '{dir_path}' not found.")
        sys.exit(1)

    print(f"\n==========================================")
    print(f" Starting Directory Scan: {dir_path}")
    print(f"==========================================\n")

    scanned_count = 0
    high_critical_found = False
    scan_failed_count = 0  # Track files that completely failed analysis
    
    # Type-annotated list utilizing our ReportFinding TypedDict
    all_report_findings: list[ReportFinding] = []

    for root, dirs, files in os.walk(dir_path):
        # Filter out ignored directories in-place (including the reports folder)
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]

        for file in files:
            if file.lower() in IGNORED_FILES:
                continue

            ext = os.path.splitext(file)[1].lower()
            if ext in IGNORED_EXTENSIONS:
                continue

            full_path = os.path.join(root, file)

            if os.path.getsize(full_path) > MAX_FILE_SIZE:
                print(f"\n  ⏩ Skipping (exceeds 500 KB limit): {full_path}")
                continue
            
            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    code_content = f.read()
            except UnicodeDecodeError:
                continue
            except Exception:
                continue

            scanned_count += 1
            print(f"\n[{scanned_count}] Scanning: {full_path}")

            findings_list = analyze_code_content(full_path, code_content)
            
            # Check if all models failed (returns None instead of a list)
            if findings_list is None:
                scan_failed_count += 1
                print(f"  🚨 ERROR: Could not analyze {full_path} due to model failures.")
            elif findings_list:
                print(f"  ⚠️ Found {len(findings_list)} vulnerability(ies) in {full_path}")
                for finding in findings_list:
                    print(f"    - [{finding.severity}] {finding.vulnerability_name} ({finding.cwe_id})")
                    
                    # Append strictly matching the ReportFinding TypedDict structure
                    all_report_findings.append({
                        "file": full_path,
                        "finding": finding
                    })

                    # Clean, exact membership check
                    if finding.severity in {"High", "Critical"}:
                        high_critical_found = True
            else:
                print(f"  🟢 Clean: No vulnerabilities detected.")

    # Generate Markdown Report File in dedicated folder (skipped entirely if empty)
    generate_markdown_report(all_report_findings, scanned_count, high_critical_found or scan_failed_count > 0)

    print(f"\n✅ Completed directory scan. Total files scanned: {scanned_count}\n")

    # Fail the gate if either High/Critical findings exist OR any file failed analysis
    if high_critical_found or scan_failed_count > 0:
        print("❌ SECURITY GATE FAILED: High/Critical vulnerabilities detected or files failed analysis. Blocking build.")
        sys.exit(1)
    else:
        print("🟢 SECURITY GATE PASSED: All files scanned successfully with no High/Critical vulnerabilities.")
        sys.exit(0)

def generate_markdown_report(findings: list[ReportFinding], scanned_count: int, failed: bool):
    """Writes a structured markdown summary report into a dedicated security-reports directory if findings exist."""
    reports_dir = "security-reports"
    os.makedirs(reports_dir, exist_ok=True)
    report_path = os.path.join(reports_dir, "security_report.md")
    
    # If no findings exist, ensure clean state and skip report creation (silent success)
    if not findings:
        if os.path.exists(report_path):
            os.remove(report_path)
        print("🟢 No vulnerabilities found globally. Skipping report generation.")
        return

    status_emoji = "❌ **FAILED** (High/Critical Vulnerabilities Detected or Scan Errors)"
    
    report_lines = [
        "# 🛡️ AI Security Scan Report",
        f"**Status:** {status_emoji}",
        f"**Total Files Scanned:** {scanned_count}",
        "",
        "---",
        "### 🔍 Detailed Findings"
    ]

    for item in findings:
        f = item["finding"]
        clean_fix = f.secure_code_fix.replace("```python", "").replace("```", "").strip()
        
        report_lines.extend([
            f"",
            f"#### 📁 File: `{item['file']}`",
            f"- **Vulnerability:** {f.vulnerability_name} (`{f.cwe_id}`)",
            f"- **Severity:** **{f.severity}**",
            f"- **Explanation:** {f.explanation}",
            f"- **Suggested Fix:**",
            f"```python",
            f"{clean_fix}",
            f"```",
            f""
        ])

    report_content = "\n".join(report_lines)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)
    print(f"📝 Generated report successfully at: {report_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI-powered code security vulnerability scanner.")
    parser.add_argument("--dir", help="Path to a directory/repo to recursively scan.")

    args = parser.parse_args()

    if args.dir:
        scan_directory(args.dir)
    else:
        print("Error: Please specify --dir <path>")
        sys.exit(1)