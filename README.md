# Assignment 1: Gemini Security Scanner

## Setup Instructions
1. Install dependencies: `pip install google-genai python-dotenv`
2. Add your API key to a local `.env` file as `GEMINI_API_KEY`.
3. Run the script: `python scanner.py`

## Results & Reflection
* **Test 1 (SQLi):** Gemini correctly flagged the string formatting vulnerability.
* **Test 2 (XSS):** Gemini accurately spotted that unescaped user input in HTML allows script injection.
* **Test 3 (Hardcoded Credentials):** Gemini correctly warned against storing plain-text passwords in code.
* **Reflection:** The AI is highly accurate at catching classic vulnerabilities, but it works best as a helper rather than a definitive security authority.
