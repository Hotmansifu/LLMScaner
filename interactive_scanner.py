#!/usr/bin/env python3
import os
import sys
import re
import json
import time
import requests
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Dict, List, Any, Optional

HEURISTICS: Dict[str, str] = {
    'aws_access_key': r'AKIA[0-9A-Z]{16}',
    'aws_secret_key': r'aws_secret[^0-9A-Za-z]{0,5}[0-9A-Za-z/+=]{40}',
    'aws_account_id': r'\d{12}',
    'github_token': r'gh[pousr]_[0-9a-zA-Z]{36}',
    'github_oauth': r'gho_[0-9a-zA-Z]{36}',
    'github_app_token': r'(ghu|ghs)_[0-9a-zA-Z]{36}',
    'github_fine_grained': r'github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}',
    'generic_api_key': r'(?:api[_-]?key|token|secret)[^0-9A-Za-z]{0,5}["\']?([0-9A-Za-z]{20,})["\']?',
    'generic_secret': r'(?:secret|key|password)[^0-9A-Za-z]{0,5}["\']?([0-9A-Za-z]{20,})["\']?',
    'bearer_token': r'bearer\s+([a-zA-Z0-9\-._~+/]+=*)',
    'password': r'password[^0-9A-Za-z]{0,5}["\']?[0-9A-Za-z!@#$%^&*]{8,}["\']?',
    'basic_auth': r'basic\s+[A-Za-z0-9+/=]{20,}',
    'private_key': r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    'ssh_private_key': r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
    'pgp_private_key': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'stripe_api_key': r'(?:stripe[^a-z0-9]*secret|sk_live)[^0-9a-zA-Z]{0,5}(sk_live_[0-9a-zA-Z]{24,})',
    'stripe_restricted_key': r'rk_live_[0-9a-zA-Z]{24,}',
    'slack_token': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,}',
    'slack_webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
    'google_api_key': r'(AIza[0-9A-Za-z\-_]{35})',
    'google_oauth': r'ya29\.[0-9A-Za-z\-_]+',
    'azure_connection_string': r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+',
    'heroku_api_key': r'[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
    'paypal_braintree': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'square_access_token': r'sq0atp-[0-9A-Za-z\-_]{22}',
    'square_oauth_secret': r'sq0csp-[0-9A-Za-z\-_]{43}',
    'jwt': r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
    'connection_string': r'(?:mongodb|postgres|mysql|redis|mssql)://[^\s]+:[^\s]+@',
    'postgres_connection': r'postgres(?:ql)?://[^:\s]+:[^@\s]+@[^/\s]+',
    'mysql_connection': r'mysql://[^:\s]+:[^@\s]+@[^/\s]+',
    'mongodb_connection': r'mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@',
    'twilio_api_key': r'SK[0-9a-fA-F]{32}',
    'twilio_account_sid': r'AC[a-zA-Z0-9_\-]{32}',
    'mailgun_api_key': r'key-[0-9a-zA-Z]{32}',
    'sendgrid_api_key': r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}',
    'facebook_access_token': r'EAACEdEose0cBA[0-9A-Za-z]+',
    'twitter_api_key': r'[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}',
    'linkedin_client_secret': r'linkedin(.{0,20})?[0-9a-z]{16}',
    'docker_swarm_token': r'SWMTKN-1-[0-9a-z]{50}-[0-9a-z]{50}',
    'npm_token': r'npm_[A-Za-z0-9]{36}',
    'pypi_token': r'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,}',
    'generic_token': r'[a|A]ccess[_]?[t|T]oken[^0-9A-Za-z]{0,5}([0-9A-Za-z]{20,})',
    'generic_client_secret': r'client[_-]?secret[^0-9A-Za-z]{0,5}([0-9A-Za-z]{20,})',
    'encryption_key': r'(?:encryption[_-]?key|cipher[_-]?key)[^0-9A-Za-z]{0,5}([0-9A-Fa-f]{32,})',
}

OLLAMA_API_URL_DEFAULT = "http://localhost:11434/api/chat"
OLLAMA_MODEL_DEFAULT = "llama3.2:3b"
OPENAI_MODEL_DEFAULT = "gpt-3.5-turbo-0125"


def ask(prompt: str, default: Optional[str] = None) -> str:
    if default is None:
        ans = input(f"{prompt}: ").strip()
    else:
        ans = input(f"{prompt} [{default}]: ").strip()
        if ans == "":
            ans = default
    return ans

def ask_int(prompt: str, default: int) -> int:
    while True:
        ans = input(f"{prompt} [{default}]: ").strip()
        if ans == "":
            return default
        try:
            return int(ans)
        except ValueError:
            print("Please enter a valid integer.")

def ask_choice(prompt: str, choices: Dict[str, str], default_key: str) -> str:
    options = " / ".join([f"{k}:{v}" for k, v in choices.items()])
    while True:
        ans = input(f"{prompt} ({options}) [{default_key}]: ").strip()
        if ans == "":
            return default_key
        if ans in choices:
            return ans
        print(f"Please choose one of: {', '.join(choices.keys())}")

def is_url(s: str) -> bool:
    return s.startswith(("http://", "https://", "git@"))


class SecretsScanner:
    def __init__(
        self,
        use_llm: bool,
        provider: Optional[str] = None,
        ollama_url: str = OLLAMA_API_URL_DEFAULT,
        ollama_model: str = OLLAMA_MODEL_DEFAULT,
        openai_model: str = OPENAI_MODEL_DEFAULT,
        openai_key: Optional[str] = None,
    ):
        self.use_llm = use_llm
        self.provider = (provider or "").lower() if use_llm else ""
        self.ollama_url = ollama_url
        self.ollama_model = ollama_model
        self.openai_model = openai_model
        self.openai_key = openai_key or os.environ.get("OPENAI_API_KEY")

        if self.use_llm:
            if self.provider == "ollama":
                print(f"[INFO] Using Ollama at {self.ollama_url} (model: {self.ollama_model})")
            elif self.provider == "openai":
                if not self.openai_key:
                    print("[WARN] OPENAI_API_KEY missing; will fall back to local simulation.")
            else:
                print("[INFO] LLM disabled (heuristics only).")

    def scan_repo(self, repo: str, n_commits: int) -> dict:
        if is_url(repo):
            return self._scan_remote(repo, n_commits)
        return self._scan_local(repo, n_commits)

    def _scan_remote(self, repo_url: str, n_commits: int) -> dict:
        print(f"Cloning {repo_url} ...")
        try:
            with TemporaryDirectory() as tmp:
                subprocess.run(
                    ['git', 'clone', '--depth', '100', repo_url, tmp],
                    check=True, capture_output=True, text=True, timeout=300
                )
                return self._scan_git_history(Path(tmp), repo_url, n_commits, is_remote=True)
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Clone failed: {e.stderr}", file=sys.stderr)
            return {'repo': repo_url, 'status': 'failed', 'error': 'Clone failed'}
        except Exception as e:
            print(f"[ERROR] Unexpected error during clone: {e}", file=sys.stderr)
            return {'repo': repo_url, 'status': 'failed', 'error': str(e)}

    def _scan_local(self, repo_path: str, n_commits: int) -> dict:
        repo = Path(repo_path)
        if not (repo / '.git').exists():
            print(f"[ERROR] {repo} is not a Git repository.", file=sys.stderr)
            return {'repo': str(repo), 'status': 'failed', 'error': 'Not a Git repository'}
        print(f"Scanning local repo {repo} ...")
        return self._scan_git_history(repo, str(repo), n_commits, is_remote=False)

    def _scan_git_history(self, repo_path: Path, repo_identifier: str, n_commits: int, is_remote: bool) -> dict:
        prev_cwd = Path.cwd()
        scan = {
            'repo_identifier': repo_identifier,
            'is_remote': is_remote,
            'commits_scanned': 0,
            'total_secrets_found': 0,
            'findings': []
        }
        try:
            os.chdir(repo_path)
            commits = self._get_commits(n_commits)
            scan['commits_scanned'] = len(commits)
            print(f"Analyzing {len(commits)} commit(s)...")

            for i, chash in enumerate(commits, 1):
                print(f"  [{i}/{len(commits)}] {chash[:8]} ...")
                diff = self._diff_commit(chash)
                findings = self._run_heuristics_with_locations(diff)

                for f in findings:
                    llm = self._analyze_with_llm(
                        snippet=f['secret_value'],
                        context=f['line_snippet'],
                        heuristic_type=f['type']
                    )
                    f.update(llm)
                    f['commit_hash'] = chash
                    scan['findings'].append(f)
                    scan['total_secrets_found'] += 1

            print(f"Done. Total findings: {scan['total_secrets_found']}")
            return {'repo': repo_identifier, 'status': 'success', 'data': scan}
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Git error: {e.stderr}", file=sys.stderr)
            return {'repo': repo_identifier, 'status': 'failed', 'error': 'Git error'}
        except Exception as e:
            print(f"[ERROR] Unexpected scan error: {e}", file=sys.stderr)
            return {'repo': repo_identifier, 'status': 'failed', 'error': str(e)}
        finally:
            os.chdir(prev_cwd)

    def _get_commits(self, n_commits: int) -> List[str]:
        res = subprocess.run(['git', 'log', f'-n{n_commits}', '--pretty=format:%H'],
                             capture_output=True, text=True, check=True)
        out = res.stdout.strip()
        return out.splitlines() if out else []

    def _diff_commit(self, commit_hash: str) -> str:
        res = subprocess.run(['git', 'show', '--pretty=format:', '--unified=0', commit_hash],
                             capture_output=True, text=True, check=True)
        return res.stdout

    def _run_heuristics_with_locations(self, diff_content: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        current_file: Optional[str] = None
        current_line: Optional[int] = None
        hunk_re = re.compile(r'@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@')

        for raw in diff_content.splitlines():
            if raw.startswith('diff --git'):
                parts = raw.split()
                current_file = parts[3][2:] if len(parts) >= 4 and parts[3].startswith('b/') else None
                current_line = None
            elif raw.startswith('@@'):
                m = hunk_re.search(raw)
                if m:
                    current_line = int(m.group(1))
            elif raw.startswith('+') and not raw.startswith('+++'):
                line_content = raw[1:]
                for htype, pattern in HEURISTICS.items():
                    for match in re.finditer(pattern, line_content):
                        val = match.group(0)
                        snippet_lower = line_content.lower()
                        if any(x in snippet_lower for x in ["test", "example", "placeholder", "dummy", "sample"]):
                            continue
                        findings.append({
                            'type': htype,
                            'file': current_file,
                            'line': current_line,
                            'line_snippet': line_content[:200],
                            'secret_value': val
                        })
                if current_line is not None:
                    current_line += 1
            else:
                if current_line is not None and not raw.startswith('-') and not raw.startswith('\\'):
                    current_line += 1

        return findings

    def _analyze_with_llm(self, snippet: str, context: str, heuristic_type: str) -> dict:
        if not self.use_llm or not self.provider:
            return self._local_llm(snippet, context, heuristic_type)

        prompt = f"""
Analyze the following potentially leaked secret and its context.

Heuristic Type: {heuristic_type}
Secret Value: {snippet}

Context:
---
{context}
---

Respond with TWO lines only:
1) Confidence: high|medium|low
2) Rationale: one concise sentence
"""
        try:
            if self.provider == "ollama":
                return self._ollama_chat(prompt, snippet, context)
            elif self.provider == "openai":
                return self._openai_chat(prompt, snippet, context)
            else:
                return self._local_llm(snippet, context, heuristic_type)
        except Exception as e:
            print(f"[WARN] LLM error: {e}. Falling back to local simulation.", file=sys.stderr)
            return self._local_llm(snippet, context, heuristic_type)

    def _local_llm(self, snippet: str, context: str, heuristic_type: str) -> dict:
        time.sleep(0.05)
        if any(x in snippet.lower() for x in ["example", "test", "placeholder", "dummy", "sample"]):
            return {'confidence': 'low', 'rationale': 'Looks like a placeholder/test value.'}
        return {'confidence': 'medium', 'rationale': 'Heuristic match without evidence of being benign.'}

    def _ollama_chat(self, prompt: str, snippet: str, context: str) -> dict:
        payload = {
            "model": self.ollama_model,
            "messages": [
                {"role": "system", "content": "Answer succinctly."},
                {"role": "user", "content": prompt}
            ],
            "stream": False
        }
        resp = requests.post(self.ollama_url, json=payload, timeout=60)
        if resp.status_code != 200:
            raise RuntimeError(f"Ollama HTTP {resp.status_code}: {resp.text[:200]}")
        data = resp.json()
        content = None
        if isinstance(data, dict):
            if "message" in data and isinstance(data["message"], dict):
                content = data["message"].get("content")
            if content is None:
                content = data.get("content")
        if not content:
            raise RuntimeError("Ollama: missing content")
        parsed = self._parse_two_line(content)
        if parsed:
            return parsed
        try:
            obj = json.loads(content)
            return {'confidence': str(obj.get('confidence', 'medium')).lower(),
                    'rationale': obj.get('rationale', 'LLM returned JSON without rationale.')}
        except Exception:
            return {'confidence': 'medium', 'rationale': content[:200]}

    def _openai_chat(self, prompt: str, snippet: str, context: str) -> dict:
        if not self.openai_key:
            return self._local_llm(snippet, context, "N/A")
        headers = {"Authorization": f"Bearer {self.openai_key}", "Content-Type": "application/json"}
        data = {"model": OPENAI_MODEL_DEFAULT, "messages": [{"role": "user", "content": prompt}], "temperature": 0.0}
        for attempt in range(3):
            try:
                resp = requests.post("https://api.openai.com/v1/chat/completions",
                                     headers=headers, json=data, timeout=30)
                resp.raise_for_status()
                content = resp.json()["choices"][0]["message"]["content"].strip()
                parsed = self._parse_two_line(content)
                if parsed:
                    return parsed
                try:
                    obj = json.loads(content)
                    return {'confidence': str(obj.get('confidence', 'medium')).lower(),
                            'rationale': obj.get('rationale', 'LLM returned JSON without rationale.')}
                except Exception:
                    return {'confidence': 'medium', 'rationale': content[:200]}
            except requests.exceptions.HTTPError as e:
                if resp.status_code == 429:
                    print("[WARN] OpenAI rate-limited; falling back.", file=sys.stderr)
                    return self._local_llm(snippet, context, "N/A")
                if attempt < 2:
                    time.sleep(2 ** (attempt + 1))
                    continue
                return self._local_llm(snippet, context, "N/A")
            except Exception:
                return self._local_llm(snippet, context, "N/A")

    @staticmethod
    def _parse_two_line(text: str) -> Optional[dict]:
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        if len(lines) >= 2 and lines[0].lower().startswith("confidence:"):
            conf = lines[0].split(":", 1)[1].strip().lower()
            if conf in {"high", "medium", "low"}:
                rationale = lines[1]
                if rationale.lower().startswith("rationale:"):
                    rationale = rationale.split(":", 1)[1].strip()
                return {'confidence': conf, 'rationale': rationale}
        return None


def interactive_main():
    print("\nInteractive LLM-Powered Git Secrets Scanner\n")
    print("Press Enter to use default values (shown in brackets)\n")

    repo = ask("Repo path or URL")
    n_commits = ask_int("Number of commits to scan", 20)

    llm_choice = ask_choice(
        "Use LLM?",
        {"1": "No (heuristics only)", "2": "Ollama (local)", "3": "OpenAI (cloud)"},
        "2"
    )

    use_llm = llm_choice != "1"
    provider = None
    ollama_url = OLLAMA_API_URL_DEFAULT
    ollama_model = OLLAMA_MODEL_DEFAULT
    openai_model = OPENAI_MODEL_DEFAULT
    openai_key = None

    if llm_choice == "2":
        provider = "ollama"
        ollama_model = ask("Ollama model", OLLAMA_MODEL_DEFAULT)
        ollama_url = ask("Ollama URL", OLLAMA_API_URL_DEFAULT)
    elif llm_choice == "3":
        provider = "openai"
        openai_model = ask("OpenAI model", OPENAI_MODEL_DEFAULT)
        openai_key_env = os.environ.get("OPENAI_API_KEY")
        if openai_key_env:
            print("[INFO] OPENAI_API_KEY found in environment.")
            openai_key = openai_key_env
        else:
            openai_key = ask("Enter OPENAI_API_KEY (or leave empty to fall back)", "")

    out_path = ask("Output JSON path", "scans/report.json")

    scanner = SecretsScanner(
        use_llm=use_llm,
        provider=provider,
        ollama_url=ollama_url,
        ollama_model=ollama_model,
        openai_model=openai_model,
        openai_key=openai_key
    )

    result = scanner.scan_repo(repo, n_commits)

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open('w') as f:
        json.dump(result, f, indent=2)
    print(f"\n[SUCCESS] Report saved to: {out}")

    if result.get('status') == 'success':
        findings = result['data']['findings']
        high = sum(1 for f in findings if f.get('confidence') == 'high')
        med = sum(1 for f in findings if f.get('confidence') == 'medium')
        low = sum(1 for f in findings if f.get('confidence') == 'low')
        print(f"\nSummary - High: {high}, Medium: {med}, Low: {low}")
        if high > 0:
            print(f"[ALERT] {high} high-confidence finding(s).")
    else:
        print(f"[ERROR] Scan failed: {result.get('error')}")


if __name__ == "__main__":
    interactive_main()