import os
import argparse
from dotenv import load_dotenv
from openai import OpenAI
from pydantic import BaseModel, Field

# Load environment variables from .env
load_dotenv()

# Initialize the OpenAI client configured for OpenRouter
client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=os.getenv("OPENROUTER_API_KEY"),
)

# Define the exact JSON schema structure using Pydantic
class SecurityFinding(BaseModel):
    vulnerability_name: str = Field(description="Name of the vulnerability, e.g., SQL Injection")
    cwe_id: str = Field(description="Associated CWE identifier, e.g., CWE-89")
    severity: str = Field(description="Severity level: Low, Medium, High, or Critical")
    explanation: str = Field(description="Brief explanation of why this code is vulnerable")
    secure_code_fix: str = Field(description="The corrected, secure version of the code snippet")

def scan_code_file(file_path):
    if not os.path.exists(file_path):
        print(f"Error: The file '{file_path}' was not found.")
        return

    # Read the code from the target file
    with open(file_path, "r", encoding="utf-8") as f:
        code_content = f.read()

    print(f"\nScanning file: {file_path} via OpenRouter...\n")

    try:
        response = client.beta.chat.completions.parse(
            model="openrouter/free",
            messages=[
                {"role": "system", "content": "You are an expert Application Security Engineer. Analyze code strictly for vulnerabilities and output structured data."},
                {"role": "user", "content": f"Analyze this code for security vulnerabilities:\n\n{code_content}"}
            ],
            response_format=SecurityFinding,
        )
        
        finding = response.choices[0].message.parsed
        
        print("--- Structured JSON Security Analysis ---")
        print(finding.model_dump_json(indent=2))
        
    except Exception as e:
        print(f"Error calling OpenRouter API: {e}")

if __name__ == "__main__":
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="AI-powered local code security vulnerability scanner.")
    parser.add_argument("--file", required=True, help="Path to the code file you want to scan.")
    
    args = parser.parse_args()
    scan_code_file(args.file)