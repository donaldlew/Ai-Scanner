# AI Security Gate (Project One) 🛡️

An automated, lightweight Static Application Security Testing (SAST) tool powered by OpenRouter and Pydantic. It recursively scans your repository for security vulnerabilities and enforces a blocking gate on High and Critical findings inside GitHub Actions.

---

## Prerequisites

* A **GitHub** repository.
* An **OpenRouter API Key** (you can grab a free-tier key from [openrouter.ai](https://openrouter.ai/)).

---

## Installation & Setup

### Step 1: Add the Scanner Script
Place the `scanner.py` script at the root of your project directory. 

### Step 2: Create the GitHub Actions Workflow
Create a workflow file in your repository at `.github/workflows/security-scan.yml` with the following configuration:

```yaml
name: AI Security Gate

on:
  push:
    branches: [ "main", "master", "feature/*" ]
  pull_request:
    branches: [ "main", "master" ]

jobs:
  security-scan:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.10'

      - name: Install Dependencies
        run: |
          python -m pip install --upgrade pip
          pip install openai pydantic python-dotenv

      - name: Run AI Vulnerability Scanner on Repository
        env:
          OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}
        run: |
          python scanner.py --dir .

---

### Step 3: Configure Your Repository Secret
For the GitHub Action to run, it needs access to your OpenRouter API key:
1. Go to your GitHub repository and click Settings.
2. In the left sidebar, expand Secrets and variables, then click Actions.
3. Click New repository secret.
4. Name the secret OPENROUTER_API_KEY and paste your OpenRouter API key into the value field.
5. Click Add secret

Local Usage
If you want to run the security scan locally on your machine before pushing code:
1. Create a .env file at your project root and add your OpenRouter key.
2. Run the scanner against a single file or an entire directory using the scanner.py file in commmand line.

Features & Architecture
Multi-Model Fallback Pipeline: Automatically switches between free-tier models on OpenRouter if a rate limit or error is hit.
Smart File Filtering: Automatically bypasses binaries, images, archives, and administrative metadata files (.gitignore, README.md) to minimize noise.
Structured JSON Output: Enforces strict Pydantic schemas to output clean vulnerability names, CWE IDs, severity levels, explanations, and secure code fixes.
CI/CD Enforcement: Exits with code 1 upon detecting High or Critical vulnerabilities, automatically failing the workflow run.