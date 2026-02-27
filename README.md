# AI PR Guard

AI PR Guard is an intelligent tool designed to automate code review processes for GitHub pull requests (PRs). It leverages Large Language Models (LLMs) to analyze code changes, identify potential issues, and provide actionable feedback. The tool integrates seamlessly with GitHub via APIs and webhooks, offering both a command-line interface (CLI) and a web-based dashboard for managing reviews.

## Features

- **Automated PR Reviews**: Automatically review PRs using AI-powered analysis to detect bugs, security issues, maintainability concerns, and more.
- **GitHub Integration**: Connect to GitHub repositories, list PRs, and post review comments directly on PRs.
- **LLM Support**: Supports multiple LLM providers, including OpenAI (GPT models) and Ollama (local models like Llama).
- **Webhook Support**: Receive real-time notifications for PR events via GitHub webhooks.
- **Web Dashboard**: A user-friendly web interface to view reviews, manage configurations, and monitor activity.
- **Feedback Learning**: Learn from user feedback on review findings to improve future analyses.
- **Configurable**: Easily configure repositories, branches, LLM settings, and more via CLI or environment variables.
- **Local Storage**: Uses SQLite for storing review data and configurations.
- **Security**: Supports GitHub webhook signature verification for secure integrations.

## Installation

### Prerequisites

- Python 3.8 or higher
- GitHub Personal Access Token (PAT) with appropriate permissions (e.g., `repo` scope for private repos)
- For Ollama: Install Ollama and pull a model (e.g., `ollama pull llama3.1`)
- For OpenAI: An API key from OpenAI

### Install from Source

1. Clone the repository:
   
```bash
   git clone https://github.com/your-username/ai-pr-guard.git
   cd ai-pr-guard
   
```

2. Install dependencies:
   
```bash
   pip install -r requirements.txt
   
```

3. (Optional) Set up a virtual environment:
   
```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   
```

## Configuration

AI PR Guard uses a local configuration file stored in your user config directory (e.g., `~/.config/ai-pr-guard/config.json` on Linux/Mac, or `C:\Users\YourUser\AppData\Local\ai-pr-guard\config.json` on Windows).

### Initial Setup

1. **Connect to GitHub**:
   
```bash
   python -m ai_pr_guard connect
   
```
   This prompts for your GitHub PAT and validates it.

2. **Select Repository**:
   
```bash
   python -m ai_pr_guard select-repo
   
```
   Lists accessible repos and allows selection.

3. **Select Base Branch**:
   
```bash
   python -m ai_pr_guard select-branch
   
```
   Lists branches in the selected repo and sets the base branch for reviews.

### Environment Variables

You can override configurations using environment variables:

- `GITHUB_TOKEN`: GitHub PAT
- `REPO_FULL_NAME`: Repository in "owner/repo" format
- `BASE_BRANCH`: Base branch for PRs
- `LLM_PROVIDER`: "openai" or "ollama"
- `OPENAI_API_KEY`: OpenAI API key
- `OPENAI_BASE_URL`: Custom OpenAI base URL (for proxies or local servers)
- `OPENAI_MODEL`: Model name (e.g., "gpt-4o-mini")
- `OLLAMA_BASE_URL`: Ollama server URL (default: http://localhost:11434)
- `OLLAMA_MODEL`: Ollama model name (e.g., "llama3.1")
- `GITHUB_WEBHOOK_SECRET`: Secret for webhook verification
- `MAX_DIFF_CHARS`: Maximum characters in PR diff to analyze (default: 120000)

### LLM Configuration

- **OpenAI**: Set `LLM_PROVIDER=openai` and provide `OPENAI_API_KEY`.
- **Ollama**: Set `LLM_PROVIDER=ollama` and ensure Ollama is running locally.

## Usage

### Command-Line Interface (CLI)

AI PR Guard provides a Typer-based CLI for all operations.

#### Review a Specific PR
```bash
python -m ai_pr_guard review-pr 123
```
Reviews PR #123 in the configured repo and posts a comment with findings.

Options:
- `--repo`: Override repo (e.g., `--repo owner/repo`)
- `--base-branch`: Override base branch
- `--no-comment`: Dry run (analyze without posting comment)

#### Sync Feedback
```bash
python -m ai_pr_guard sync-feedback 123
```
Fetches the latest review comment on PR #123 and learns from checked (accepted) findings.

#### Run Poller
```bash
python -m ai_pr_guard run-poller
```
Continuously polls for open PRs and reviews new commits.

Options:
- `--interval-seconds`: Polling interval (default: 300 seconds)
- `--once`: Run one cycle and exit

#### Run Webhook Server
```bash
python -m ai_pr_guard run-webhook
```
Starts a FastAPI server to handle GitHub webhooks at `/github/webhook`.

Options:
- `--host`: Host (default: 127.0.0.1)
- `--port`: Port (default: 8080)

#### Run Dashboard
```bash
python -m ai_pr_guard run-dashboard
```
Starts the web dashboard for viewing reviews and configurations.

### Web Dashboard

The dashboard provides a graphical interface to:
- View past reviews
- Manage repository and branch settings
- Monitor webhook activity
- Review detailed findings

Access it at `http://localhost:8080` after running `run-dashboard` or `run-webhook`.

### Webhook Integration

1. Set up a webhook in your GitHub repo settings:
   - URL: `https://your-domain.com/github/webhook` (or `http://localhost:8080/github/webhook` for local testing)
   - Content type: `application/json`
   - Secret: Your configured `GITHUB_WEBHOOK_SECRET`
   - Events: Select "Pull requests"

2. Run the webhook server:
   
```bash
   python -m ai_pr_guard run-webhook
   
```

3. Ensure the server is accessible (use ngrok or similar for public exposure).

## How It Works

1. **PR Detection**: Monitors open PRs via polling or webhooks.
2. **Diff Analysis**: Fetches PR diffs and analyzes changes using the configured LLM.
3. **Issue Identification**: LLM identifies potential problems like bugs, security vulnerabilities, style issues, etc.
4. **Feedback Posting**: Posts structured comments on PRs with findings, severity levels, and suggestions.
5. **Learning**: Incorporates user feedback to refine future reviews.

### Review Process

- Extracts code changes from PR diffs.
- Sends prompts to LLM with context (repo, PR number, base branch, team style notes).
- Parses LLM response for structured findings (ID, severity, title, details, suggestion, style rule).
- Stores results in local SQLite database.
- Optionally posts to GitHub.

### Scoring and Storage

- Findings are scored by severity (low, medium, high, critical).
- Static analysis complements LLM reviews.
- Data is stored locally for privacy and offline operation.

## Project Structure

```
ai_pr_guard/
├── __init__.py          # Package initialization
├── __main__.py          # Entry point
├── cli.py               # Command-line interface
├── config.py            # Configuration management
├── github_api.py        # GitHub API client
├── llm.py               # LLM integration (OpenAI/Ollama)
├── review.py            # Core review logic
├── scoring.py           # Finding scoring
├── sentinel.py          # Review sentinel logic
├── storage.py           # Database operations
├── webhook.py           # FastAPI webhook server
├── dashboard.py         # Dashboard logic
├── templates/           # Jinja2 HTML templates
│   ├── base.html
│   ├── connect.html
│   ├── dashboard.html
│   ├── dashboard_check.txt
│   ├── review_detail.html
│   ├── reviews.html
│   ├── select_branch.html
│   └── select_repo.html
└── requirements.txt     # Python dependencies
```

## Contributing

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit changes: `git commit -am 'Add your feature'`
4. Push to branch: `git push origin feature/your-feature`
5. Submit a pull request.

### Development Setup

- Install dev dependencies (if any).
- Run tests (add tests as needed).
- Follow PEP 8 style guidelines.

## License

This project is licensed under the MIT License. See `LICENSE` for details.

## Support

For issues or questions:
- Open an issue on GitHub.
- Check the documentation in this README.
- Ensure your GitHub token has the correct permissions.

## Changelog

- **v0.1.0**: Initial release with CLI, LLM integration, and basic webhook support.
