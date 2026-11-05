import argparse
import json
import os
import sys
from typing import List, Optional
from dotenv import load_dotenv
from openai import OpenAI
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Load Environment Variables
# ---------------------------------------------------------------------------
load_dotenv()
API_KEY = os.getenv("OPENROUTER_API_KEY")

if not API_KEY:
    print("❌ ERROR: OPENROUTER_API_KEY is not set in environment variables.")
    sys.exit(1)

client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=API_KEY,
)

# ---------------------------------------------------------------------------
# Model Fallback Pipeline
# ---------------------------------------------------------------------------
MODEL_PIPELINE = [
    "nvidia/nemotron-3.5-lightning:free",
    "inkling/inkling-v1:free",
    "google/gemma-2-9b-it:free",
    "openrouter/auto",
]

# ---------------------------------------------------------------------------
# Scope & Filtering Constraints
# ---------------------------------------------------------------------------
IGNORED_DIRS = {
    ".git", ".github", "venv", ".venv", "__pycache__", "node_modules",
    "dist", "build", ".pytest_cache", ".idea", ".vscode"
}

IGNORED_EXTENSIONS = {
    # Images & Media
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf", ".zip", ".tar", ".gz",
    # Compiled & Binary
    ".pyc", ".pyo", ".exe", ".dll", ".so", ".dylib", ".class",
    # Data & Environment
    ".db", ".sqlite", ".env", ".lock"
}

IGNORED_FILES = {
    ".env", ".gitignore", "license", "package-lock.json",
    "readme.md", "security_report.md", "set up guide.md", "scanner.py"
}

MAX_FILE_SIZE = 500 * 1024  # 500 KB limit per file

# ---------------------------------------------------------------------------
# Structured Output Schema (Pydantic)
# ---------------------------------------------------------------------------
class VulnerabilityFinding(BaseModel):
    vulnerability_name: str = Field(description="Name of the security vulnerability detected.")
    severity: str = Field(description="Severity level: Low, Medium, High, or Critical.")
    cwe_id: str = Field(description="Common Weakness Enumeration ID (e.g., CWE-89, CWE-79).")
    explanation: str = Field(description="Detailed explanation of the issue and why it poses a security risk.")
    suggested_fix: str = Field(description="Clear code or architectural remediation steps to fix the flaw.")

class ScanReport(BaseModel):
    findings: List[VulnerabilityFinding] = Field(default_factory=list, description="List of security findings.")

# ---------------------------------------------------------------------------
# Core Analysis Engine
# ---------------------------------------------------------------------------
def analyze_code_content(file_path: str, code_content: str) -> Optional[List[VulnerabilityFinding]]:
    """Analyzes a single file's source code using the LLM fallback pipeline."""
    system_prompt = (
        "You are an expert Application Security Architect performing a static analysis review.\n"
        "Analyze the provided source code for logic vulnerabilities, injection flaws, authentication bugs, "
        "or unsafe design patterns.\n\n"
        "CRITICAL INSTRUCTION: If a file contains multiple distinct vulnerable functions, endpoints, or query constructions, "
        "you MUST report each individual vulnerability separately in the findings array. Do not group or summarize them into a single finding.\n\n"
        "Ignore dependencies, cross-file imports, and framework boilerplate. Focus strictly on source code logic.\n\n"
        "Your output MUST be a JSON object adhering strictly to this schema:\n"
        "{\n"
        '  "findings": [\n'
        "    {\n"
        '      "vulnerability_name": "string",\n'
        '      "severity": "Low | Medium | High | Critical",\n'
        '      "cwe_id": "string (e.g. CWE-89)",\n'
        '      "explanation": "string",\n'
        '      "suggested_fix": "string"\n'
        "    }\n"
        "  ]\n"
        "}\n"
        "If no security issues are found, return {\"findings\": []}."
    )

    user_prompt = f"File: {file_path}\n\nCode Content:\n```\n{code_content}\n```"

    for model_name in MODEL_PIPELINE:
        print(f"  Attempting scan with model: {model_name}...")
        try:
            response = client.chat.completions.create(
                model=model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                response_format={"type": "json_object"},
                temperature=0.1,
            )

            raw_json = response.choices[0].message.content
            report = ScanReport.model_validate_json(raw_json)
            print(f"  ✅ Model used: {model_name}")
            return report.findings

        except Exception as e:
            print(f"  ⚠️ Model '{model_name}' failed or returned invalid schema. Trying next model...")

    return None  # All models in pipeline failed

# ---------------------------------------------------------------------------
# Markdown Report Generation
# ---------------------------------------------------------------------------
def generate_markdown_report(all_findings: list, total_scanned: int, gate_failed: bool):
    """Generates an executive Markdown report summarizing scan findings."""
    os.makedirs("security-reports", exist_ok=True)
    report_path = os.path.join("security-reports", "security_report.md")

    status_badge = "❌ **SECURITY GATE: FAILED**" if gate_failed else "🟢 **SECURITY GATE: PASSED**"

    md = [
        "# 🛡️ AI Security Scan Report",
        "",
        f"**Status:** {status_badge}",
        f"**Total Files Scanned:** {total_scanned}",
        f"**Total Findings:** {len(all_findings)}",
        "",
        "---",
        "",
        "## Summary of Findings",
        ""
    ]

    if not all_findings:
        md.append("🟢 **No vulnerabilities were detected across all scanned files.**")
    else:
        md.append("| File | Severity | Vulnerability | CWE |")
        md.append("| :--- | :--- | :--- | :--- |")
        for item in all_findings:
            f_path = item["file"]
            finding = item["finding"]
            md.append(f"| `{f_path}` | **{finding.severity}** | {finding.vulnerability_name} | {finding.cwe_id} |")

        md.extend(["", "---", "", "## Detailed Findings", ""])

        for item in all_findings:
            f_path = item["file"]
            finding = item["finding"]
            md.extend([
                f"### 📁 File: `{f_path}`",
                f"- **Vulnerability:** {finding.vulnerability_name} (`{finding.cwe_id}`)",
                f"- **Severity:** {finding.severity}",
                f"- **Explanation:** {finding.explanation}",
                "- **Suggested Fix:**",
                "```",
                f"{finding.suggested_fix}",
                "```",
                ""
            ])

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md))

    print(f"\n📝 Generated report successfully at: {report_path}")

# ---------------------------------------------------------------------------
# Directory Scan Workflow
# ---------------------------------------------------------------------------
def scan_directory(target_dir: str):
    """Recursively scans a target directory for security vulnerabilities."""
    print(f"\n==========================================")
    print(f" Starting Directory Scan: {target_dir}")
    print(f"==========================================\n")

    if not os.path.exists(target_dir):
        print(f"❌ Error: Target directory '{target_dir}' does not exist.")
        sys.exit(1)

    scanned_count = 0
    high_critical_found = False
    scan_failed_count = 0
    all_report_findings = []

    for root, dirs, files in os.walk(target_dir):
        # Prune ignored directories in place
        dirs[:] = [d for d in dirs if d.lower() not in IGNORED_DIRS]

        for file in files:
            file_name_lower = file.lower()
            if file_name_lower in IGNORED_FILES:
                continue

            ext = os.path.splitext(file)[1].lower()
            if ext in IGNORED_EXTENSIONS:
                continue

            file_path = os.path.join(root, file)

            if os.path.getsize(file_path) > MAX_FILE_SIZE:
                print(f"\n  ⏩ Skipping (exceeds 500 KB limit): {file_path}")
                continue

            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    code_content = f.read()
            except (UnicodeDecodeError, Exception):
                continue

            scanned_count += 1
            print(f"\n[{scanned_count}] Scanning: {file_path}")

            findings_list = analyze_code_content(file_path, code_content)

            if findings_list is None:
                scan_failed_count += 1
                print(f"  🚨 ERROR: Could not analyze {file_path} due to model failures.")
            elif findings_list:
                print(f"  ⚠️ Found {len(findings_list)} vulnerability(ies) in {file_path}")
                for finding in findings_list:
                    print(f"    - [{finding.severity}] {finding.vulnerability_name} ({finding.cwe_id})")
                    all_report_findings.append({
                        "file": file_path,
                        "finding": finding
                    })
                    if finding.severity in {"High", "Critical"}:
                        high_critical_found = True
            else:
                print(f"  🟢 Clean: No vulnerabilities detected.")

    generate_markdown_report(all_report_findings, scanned_count, high_critical_found or scan_failed_count > 0)

    print(f"\n✅ Completed directory scan. Total files scanned: {scanned_count}\n")

    if high_critical_found or scan_failed_count > 0:
        print("❌ SECURITY GATE FAILED: High/Critical vulnerabilities or scan failures detected.")
        sys.exit(1)
    else:
        print("🟢 SECURITY GATE PASSED: Codebase is clean.")
        sys.exit(0)

# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="AI Security Scanner - Multi-model static analysis tool using OpenRouter."
    )
    parser.add_argument(
        "--dir",
        type=str,
        default=".",
        help="Target directory to scan (default: current directory '.')"
    )

    args = parser.parse_args()
    scan_directory(args.dir)

if __name__ == "__main__":
    main()