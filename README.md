Executive Summary
This tool is a lightweight, automated security assistant that scans your code for security risks before it ever reaches production. It runs both locally on your computer and automatically inside your GitHub workflow, acting as an instant second pair of eyes. If it spots a serious vulnerability, it blocks the code from being merged and automatically leaves a helpful comment on your pull request explaining the fix, keeping your pipeline secure without slowing down development speed.

Scope (What it covers & limitations)
1. What's In Scope: 
Real-time analysis of your application source code logic, detecting common security risks, and enforcing automated quality/security gates in CI/CD pipelines.
2. What's Out of Scope (By Design):
Dependencies: It does not scan third-party package libraries (requirements.txt, package.json), which are best handled by dedicated tools like Dependabot.
Complex Data Flows: Files are evaluated individually for speed and efficiency, meaning multi-file data tracking is intentionally left out.

## System Architecture & Data Flow

Here is how the system orchestrates security checks across local and CI/CD environments:

```mermaid
graph TD
    Dev[Developer Workstation] --> Local[Local CLI Execution]
    Dev --> GitHub[GitHub Actions CI/CD]

    subgraph "Local Workflow"
        Local --> LocalCLI
        LocalCLI --> LocalFilter
        LocalFilter --> RunLLM{"Run Model Pipeline"}
        RunLLM --> LocalReport["Generates Local<br/>Markdown Report"]
    end

    subgraph "GitHub CI/CD Workflow"
        GitHub --> GHA["Trigger on Push<br/>or PR"]
        GHA --> RunLLM{"Run Model Pipeline"}
        RunLLM --> GHAGate{"High / Critical<br/>Findings?"}
        GHAGate --> Fail["❌ Fail Build<br/>& Block PR"]
        GHAGate --> Pass["🟢 Pass Gate<br/>& Complete"]
    end

```

Features
1. Dual-Layer Scanning: Run quick checks locally on your machine before committing, or let it run automatically inside your GitHub workflow.
2. Resilient AI Routing: Automatically switches between available free models if a rate limit or gateway error occurs.
A model pipeline is used to ensure if a free model is unavailable, back up options are called. In the event that all 3 models isted are unable, an OpenRouter route plug is used to call the best available model.
Models:
    nvidia/nemotron-3.5-lightning:free,
    thinkingmachines/inkling-small:free,
    google/gemma-4-31b-it:free,
    openrouter/free 
3. Inline PR Remediation: Posts clean, actionable security reports and exact code fixes directly onto your pull requests.
4. Fail-Safe Gates: Automatically blocks code from merging if a serious vulnerability is found or if a file fails to analyze.

See the Setup Guide for installation and local usage instructions.
