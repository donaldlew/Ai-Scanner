AI Security Vulnerability Scanner (Local PoC)
A lightweight, local command-line script that utilizes Google’s Gemini API to scan code snippets for common software vulnerabilities.

Purpose
This tool acts as a proof-of-concept automated code review assistant. It programmatically runs targeted security analysis against known vulnerability patterns—such as SQL Injection (SQLi), Cross-Site Scripting (XSS), and Hardcoded Secrets—providing rapid developer feedback directly in the terminal.

Model Used
Model Identifier: gemini-3.5-flash

Prerequisites
1. Python 3.10+ installed on your machine
2. A Google Gemini API key.

How to Run the Scanner:
1. Installation & Setup
Clone or save the script locally as scanner.py.
2. Install the official Google GenAI SDK and python-dotenv: 
pip install google-genai python-dotenv
3. Configure your API Key:
Create a file named .env in the same directory as your script and add your Gemini API key:
GEMINI_API_KEY=your_actual_api_key_here
4. Execute the script from your terminal: 
python scanner.py