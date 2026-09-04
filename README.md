# Sentinel 🛡️

### Autonomous AI-Powered Dynamic Application Security Testing

Sentinel is an AI-powered application security platform that autonomously discovers an application's attack surface, selects security tests, executes them in a controlled environment, validates vulnerabilities using evidence, and continuously monitors for security regressions.

## What Sentinel Does

- 🔎 Dynamic web reconnaissance
- 🧠 AI-assisted security reasoning
- ⚡ Adaptive DAST testing
- 🔐 Authentication testing
- 🛡️ Authorization and IDOR testing
- 🔬 Static security analysis
- ✅ Evidence-based vulnerability validation
- 🔗 Runtime + code evidence correlation
- 📊 Security findings and risk analysis
- ♻️ Continuous security monitoring
- 🤖 LangGraph-based agent orchestration

## Architecture

``` text
Target Application
        │
        ▼
   Web Recon
        │
        ▼
 Security Testing
        │
        ▼
 Adaptive DAST
        │
        ▼
 Authentication
        │
        ▼
 Authorization
        │
        ▼
 Autonomous Reasoning
        │
        ▼
   Static Analysis
        │
        ▼
   AI Security Agent
        │
        ▼
   Correlation Engine
        │
        ▼
 Security Findings
```


## Tech Stack

Backend

Python
FastAPI
LangChain
LangGraph
HTTPX
AI
Featherless AI
Qwen

Frontend

HTML
CSS
JavaScript
Supabase Authentication

Project Structure
```text 
Sentinel/
├── backend/
│   ├── agents/
│   ├── orchestration/
│   ├── sandbox/
│   ├── tools/
│   ├── demo_target.py
│   ├── llm.py
│   ├── main.py
│   └── run_agent.py
│
├── frontEnd/
│   ├── assets/
│   ├── index.html
│   ├── main.js
│   └── styles.css
│
├── test_targets/
│   ├── vulnerable_target.py
│   ├── clean_target.py
│   └── chaos_target.py
│
└── README.md
```
Running Locally

Backend

cd /d D:\sentinel\backend
venv311\Scripts\activate
uvicorn main:app --reload --port 8000

Frontend

cd /d D:\sentinel\frontend
python -m http.server 5500

Open:

http://127.0.0.1:5500
Demo Target
cd /d D:\sentinel\backend
venv311\Scripts\activate
python demo_target.py

The vulnerable demo target runs on:

http://127.0.0.1:9000
Environment Variables

Create a .env file inside backend/.

Never commit real API keys or secrets.

Example:

FEATHERLESS_API_KEY=
FEATHERLESS_MODEL=Qwen/Qwen3.5-9B

SUPABASE_URL=
SUPABASE_ANON_KEY=
Security

Sentinel is designed for authorized security testing only.

Only scan applications that you own or have explicit permission to test.

Project Status

🚧 Hackathon prototype

Sentinel is actively being developed toward autonomous, evidence-driven application security testing and continuous security validation.

License

This project is currently intended as a hackathon prototype.

