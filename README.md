# AI PR Guard

AI-powered PR security review tool that automates code analysis, detects vulnerabilities, and provides actionable feedback on GitHub pull requests.

## 🚀 Features

- **Automated PR Reviews**: AI analyzes code changes and finds bugs, security issues, and maintainability problems
- **Security Scanning**: Detects hardcoded secrets, SQL injection, XSS, command injection, and more
- **Risk Scoring**: Provides risk levels (Low/Medium/High/Critical) and security scores
- **Context-Aware Reviews**: Compares with previous commits and understands project structure
- **Toil Reduction Metrics**: Tracks time saved and automation impact
- **Sentinel Integration**: Microsoft Sentinel alerts and security compliance tracking
- **Web Dashboard**: User-friendly interface to view reviews and manage settings
- **GitHub Integration**: Webhooks and API integration for real-time reviews

## 📦 Installation

### Prerequisites
- Python 3.8+
- GitHub Personal Access Token
- OpenAI API key (or Ollama for local models)

### Quick Setup
```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements.txt
```

## ⚙️ Configuration

1. **Connect to GitHub**:
   
```bash
   python -m ai_pr_guard connect
   
```

2. **Select Repository**:
   
```bash
   python -m ai_pr_guard select-repo
   
```

3. **Choose Base Branch**:
   
```bash
   python -m ai_pr_guard select-branch
   
```

## 🚀 Usage

### Review a PR
```bash
python -m ai_pr_guard review-pr 123
```

### Start Webhook Server
```bash
python -m ai_pr_guard run-webhook
```

### Launch Dashboard
```bash
python -m ai_pr_guard run-dashboard
```

### Continuous Monitoring
```bash
python -m ai_pr_guard run-poller
```

## 🔍 How It Works

1. **PR Detection**: Monitors GitHub for new pull requests via webhooks or polling
2. **Code Analysis**: AI examines diff changes using OpenAI GPT or local Ollama models
3. **Security Scanning**: Detects 15+ vulnerability types including secrets, injection attacks, and insecure patterns
4. **Risk Assessment**: Calculates risk scores and provides severity levels
5. **Feedback**: Posts detailed comments on PRs with findings and suggestions
6. **Learning**: Improves recommendations based on user feedback

## 📊 Dashboard Features

- **Security Overview**: Total issues, risk distribution, security scores
- **Time Saved**: Tracks automation impact (e.g., "30 minutes saved")
- **PR History**: Review all past PR analyses
- **Metrics**: Security trends and toil reduction statistics
- **Configuration**: Manage repositories, branches, and LLM settings

## 🛡️ Security Patterns Detected

- **Secrets**: API keys, tokens, passwords, certificates
- **Injection Attacks**: SQL injection, command injection, XSS
- **Authentication**: Weak hashing, missing auth checks
- **File Security**: Path traversal, insecure file operations
- **Code Quality**: TODOs, dead code, style violations

## 📈 Metrics Explained

- **Total Issues**: Count of all security findings
- **Risk Distribution**: Percentage breakdown by severity (Critical/High/Medium/Low)
- **Security Score**: 0-100 scale (higher = more secure)
- **Time Saved**: Estimated hours saved from manual reviews

---

**Ready to secure your PRs?** Start with `python -m ai_pr_guard connect` and automate your code review process!
