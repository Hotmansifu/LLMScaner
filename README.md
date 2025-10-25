# Git Secrets Scanner

Scan Git repositories for leaked secrets using pattern matching + optional LLM analysis.

## Quick Install

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Start Ollama
ollama serve > /tmp/ollama.log 2>&1 &

# Pull model
ollama pull llama3.2:3b

# Install Python dependencies
pip install -r requirements.txt
```

### Optional: OpenAI Setup

```bash
# If you want to use OpenAI instead of Ollama
export OPENAI_API_KEY="sk-your-api-key-here"
```

## Usage

### CLI Mode (Automated)

```bash
# Basic scan (no AI, fast)
python3 git_secrets_scanner.py --repo . --n 20 --out scan.json

# With Ollama AI (local, free)
python3 git_secrets_scanner.py --repo . --n 20 --enable-llm --provider ollama --out scan.json

# With OpenAI (cloud, paid)
export OPENAI_API_KEY="sk-your-key"
python3 git_secrets_scanner.py --repo . --n 20 --enable-llm --provider openai --out scan.json

# Scan remote repository
python3 git_secrets_scanner.py --repo https://github.com/user/repo --n 50 --out scan.json

# Scan with custom Ollama model
python3 git_secrets_scanner.py --repo . --n 20 --enable-llm --provider ollama --ollama-model llama3.2:3b --out scan.json
```

### Interactive Mode (Guided)

```bash
python3 interactive_scanner.py
```

Follow the prompts:
- Repo path: `.` (current dir) or URL
- Commits: `20`
- LLM: `2` (Ollama)
- Model: press Enter for default
- Output: `scans/report.json`

## CLI Options

```
--repo          Repository path or URL (required)
--n             Number of commits to scan (default: 50)
--out           Output JSON file (default: scans/report.json)
--enable-llm    Enable AI analysis
--provider      LLM provider: ollama or openai (default: openai)
--ollama-model  Ollama model name (default: llama3.2:3b)
--ollama-url    Ollama API URL (default: http://localhost:11434/api/chat)
```

## Testing

To test the scanner, we've created fake repositories with intentionally leaked fake API keys and secrets:

**Test Repository**: [https://github.com/Hotmansifu/Fake-repositories-scanner](https://github.com/Hotmansifu/Fake-repositories-scanner/tree/main)

These repositories contain realistic-looking but completely fake credentials for testing purposes. You can use them to validate the scanner's detection capabilities without risking real secrets.

```bash
# Test with the fake repository
python3 git_secrets_scanner.py --repo https://github.com/Hotmansifu/Fake-repositories-scanner --n 20 --enable-llm --provider ollama --out test-scan.json
```

# CI/CD integration
python3 git_secrets_scanner.py --repo . --n 50 --out scan.json
if [ $? -eq 1 ]; then
    echo "Secrets found!"
    exit 1
fi
```

## Requirements

- Python 3.8+
- Git
- Ollama (for LLM analysis)
- ~2GB disk space (for model)

## Troubleshooting

```bash
# Check Ollama is running
curl http://localhost:11434/api/tags

# Restart Ollama
pkill ollama
ollama serve > /tmp/ollama.log 2>&1 &

# Check model
ollama list

# Pull model again
ollama pull llama3.2:3b
```