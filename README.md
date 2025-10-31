# Git Secrets Scanner

A Python-based tool for detecting leaked credentials and secrets in Git repositories using pattern matching and optional LLM analysis.

## Overview

This scanner analyzes Git commit history to identify potentially leaked secrets such as API keys, tokens, passwords, and private keys. It combines heuristic-based pattern matching with optional AI-powered context analysis to reduce false positives.

**Key Features:**
- Pattern-based detection for 40+ secret types
- Entropy analysis for identifying high-randomness strings
- Optional LLM integration (OpenAI GPT or local Ollama) for context-aware validation
- False positive filtering for test data and examples
- Support for both local and remote repositories
- JSON output format for CI/CD integration

## Architecture

The scanner operates in two stages:

1. **Heuristic Analysis**: Fast pattern matching using regex to identify potential secrets
2. **LLM Validation** (optional): Contextual analysis to reduce false positives

Detection methods include:
- Regex pattern matching against known secret formats
- Shannon entropy calculation for random-looking strings
- Context analysis to filter test data and placeholders

## Installation

### Requirements
- Python 3.8+
- Git
- (Optional) Ollama for local LLM analysis
- (Optional) OpenAI API key for cloud-based analysis

### Setup

```bash
# Install Python dependencies
pip install -r requirements.txt

# Optional: Set up Ollama for local LLM
curl -fsSL https://ollama.com/install.sh | sh
ollama serve > /tmp/ollama.log 2>&1 &
ollama pull llama3.2:3b

# Optional: Configure OpenAI
export OPENAI_API_KEY="your-api-key"
```

## Usage

### Command Line Interface

Basic scan without LLM:
```bash
python3 git_secrets_scanner.py --repo . --n 50 --out scan.json
```

Scan with Ollama:
```bash
python3 git_secrets_scanner.py --repo . --n 50 --enable-llm --provider ollama --out scan.json
```

Scan with OpenAI:
```bash
python3 git_secrets_scanner.py --repo . --n 50 --enable-llm --provider openai --out scan.json
```

Scan remote repository:
```bash
python3 git_secrets_scanner.py --repo https://github.com/user/repo --n 100 --out scan.json
```

### Interactive Mode

For guided scanning with prompts:
```bash
python3 interactive_scanner.py
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--repo` | Repository path or URL | Required |
| `--n` | Number of commits to scan | 50 |
| `--out` | Output JSON file | scans/report.json |
| `--enable-llm` | Enable LLM analysis | False |
| `--provider` | LLM provider (ollama/openai) | openai |
| `--ollama-model` | Ollama model name | llama3.2:3b |
| `--ollama-url` | Ollama API endpoint | http://localhost:11434/api/chat |

## Detected Secret Types

### Cloud Providers
AWS (Access Keys, Secret Keys, Account IDs), Google Cloud (API Keys, OAuth), Azure (Connection Strings), Heroku

### Version Control Systems
GitHub (Personal Tokens, OAuth, App Tokens, Fine-grained), GitLab

### Payment Services
Stripe (Live Keys, Restricted Keys), PayPal Braintree, Square

### Communication Platforms
Slack (Tokens, Webhooks), Twilio, SendGrid, Mailgun

### Databases
PostgreSQL, MySQL, MongoDB, Redis, MSSQL connection strings

### Package Managers
NPM, PyPI tokens

### Cryptographic Material
RSA, EC, OpenSSH private keys, SSH keys, PGP keys

### Authentication
JWT tokens, Bearer tokens, Basic Auth, Generic API keys

## Output Format

Results are saved in JSON format:

```json
{
  "repo": "/path/to/repository",
  "scan_date": "2024-10-31T10:30:00",
  "commits_scanned": 50,
  "findings": [
    {
      "commit_hash": "abc123...",
      "file_path": "config/settings.py",
      "line_number": 15,
      "finding_type": "aws_access_key",
      "confidence": "high",
      "snippet": "AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'",
      "rationale": "Matches AWS access key pattern",
      "heuristic_match": "aws_access_key"
    }
  ],
  "statistics": {
    "total_findings": 1,
    "high_confidence": 1,
    "medium_confidence": 0,
    "low_confidence": 0
  }
}
```

## CI/CD Integration

The scanner exits with status code 1 when secrets are found, making it suitable for CI/CD pipelines:

```bash
python3 git_secrets_scanner.py --repo . --n 50 --out scan.json
if [ $? -eq 1 ]; then
    echo "Secrets detected!"
    cat scan.json
    exit 1
fi
```

### GitHub Actions Example

```yaml
name: Secret Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 100
      - uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      - run: pip install -r requirements.txt
      - run: |
          python3 git_secrets_scanner.py --repo . --n 50 --out scan.json
          if [ $? -eq 1 ]; then
            cat scan.json
            exit 1
          fi
```

## Testing

A test repository with intentionally leaked fake credentials is available for validation:

```bash
python3 git_secrets_scanner.py \
  --repo https://github.com/Hotmansifu/Fake-repositories-scanner \
  --n 20 \
  --enable-llm \
  --provider ollama \
  --out test-scan.json
```

Test repository: https://github.com/Hotmansifu/Fake-repositories-scanner

## Performance Considerations

| Mode | Scan Time (100 commits) | Memory Usage | Accuracy |
|------|------------------------|--------------|----------|
| Heuristics only | ~5 seconds | Low | Good |
| Ollama (3B model) | ~30 seconds | 2GB RAM | Very Good |
| Ollama (8B model) | ~60 seconds | 6GB RAM | Excellent |
| OpenAI GPT | ~45 seconds | Low (API) | Excellent |

## Troubleshooting

### Ollama Connection Issues
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Restart Ollama
pkill ollama
ollama serve > /tmp/ollama.log 2>&1 &

# Verify model is installed
ollama list
```

### OpenAI API Issues
```bash
# Verify API key is set
echo $OPENAI_API_KEY

# Test API connection
curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer $OPENAI_API_KEY"
```

## Limitations

- Does not scan encrypted or binary files
- Pattern matching may produce false positives for similar-looking strings
- LLM analysis adds latency and cost (for OpenAI)
- Entropy-based detection may miss low-entropy secrets (e.g., "password123")
- Remote repository scanning limited to most recent 100 commits by default

## Technical Stack

- **Language**: Python 3.8+
- **Core Libraries**: subprocess, re, json, pathlib
- **External Dependencies**: requests, openai
- **LLM Backends**: OpenAI GPT-3.5, Ollama (Llama 3.x)

## Project Structure

```
LLMScaner/
├── git_secrets_scanner.py      # Main CLI scanner
├── interactive_scanner.py      # Interactive mode interface
├── requirements.txt            # Python dependencies
├── README.md                   # Documentation
└── gitignore                   # Git ignore patterns
```

## License

MIT License - See LICENSE file for details

## Author

Luka Andghuladze for JetBrains 
