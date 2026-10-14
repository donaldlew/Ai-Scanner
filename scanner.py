import os
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

print("Starting AI Security Scanning Pipeline via OpenRouter...\n")

sample_code = "query = f\"SELECT * FROM users WHERE username = '{user_input}'\""

try:
    # You can change the model string to any model on OpenRouter (e.g., google/gemini-flash-1.5, meta-llama/llama-3.3-70b-instruct, etc.)
    response = client.beta.chat.completions.parse(
        model="openrouter/free",  
        messages=[
            {"role": "system", "content": "You are an expert Application Security Engineer. Analyze code strictly for vulnerabilities and output structured data."},
            {"role": "user", "content": f"Analyze this code for security vulnerabilities: {sample_code}"}
        ],
        response_format=SecurityFinding,
    )
    
    # Extract the parsed Pydantic object directly
    finding = response.choices[0].message.parsed
    
    print("--- Structured JSON Security Analysis ---")
    print(finding.model_dump_json(indent=2))
    
except Exception as e:
    print(f"Error calling OpenRouter API: {e}")