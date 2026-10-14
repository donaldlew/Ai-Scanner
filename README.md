AI Security Vulnerability Scanner
An automated Application Security (AppSec) tool that analyzes source code for security vulnerabilities, maps findings to standard CWE classifications, and outputs structured, machine-readable data with remediation fixes.

Purpose
This tool acts as a proof-of-concept automated security scanning engine. Designed to shift security left, it evaluates source code for OWASP Top 10 risks (such as SQL Injection, Cross-Site Scripting, and Hardcoded Secrets) and provides precise, actionable remediation guidance.

By leveraging structured JSON schemas, the output is designed to be easily integrated into automated pipelines (like CI/CD gates) to block vulnerable code before it reaches production.

Model Used
Model Identifier: gemini-3.5-flash

Prerequisites
1. Python 3.10+ installed on your machine
2. An active OpenRouter API key.

How to Run the Scanner:
1. Installation & Setup
Clone or save the project files locally.
2. Install the required packages via command line:
pip install openai python-dotenv pydantic
3. Configure your API Key:
Create a file named .env in the same directory as your script and add your OpenRouter API key:
4. Execute the script from your terminal: 
python scanner.py