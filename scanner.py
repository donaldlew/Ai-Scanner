import os
from dotenv import load_dotenv
from google import genai

# Load secret API key from the local .env file
load_dotenv()

# Initialize the Gemini client
client = genai.Client()

# Define 3 distinct cybersecurity vulnerability inputs
test_cases = [
    {
        "id": "Test Case 1: SQL Injection",
        "code": "query = f\"SELECT * FROM users WHERE username = '{user_input}'\""
    },
    {
        "id": "Test Case 2: Cross-Site Scripting (XSS)",
        "code": "return f\"<h1>Welcome, {user_input}!</h1>\""
    },
    {
        "id": "Test Case 3: Hardcoded Credentials",
        "code": "def connect_database():\n    db_password = 'SuperSecretPassword123!'\n    return create_connection(password=db_password)"
    }
]

print("Starting AI Security Scanning Pipeline...\n")

# Loop through each test case and ask Gemini for an analysis
for case in test_cases:
    print(f"=========================================")
    print(f"Running {case['id']}...")
    print(f"Code to analyze: {case['code']}\n")
    
    prompt = f"Analyze this Python snippet for security vulnerabilities. Be concise: {case['code']}"
    
    try:
        response = client.models.generate_content(
            model="gemini-3.5-flash",
            contents=prompt,
        )
        print("--- Gemini Security Analysis ---")
        print(response.text)
    except Exception as e:
        print(f"Error calling API for this case: {e}")
        
    print(f"=========================================\n")
