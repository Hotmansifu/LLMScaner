#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys
import math
import tempfile
import shutil
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import subprocess
import requests

# API კონფიგურაცია - ძველი მოდელი უფრო იაფია
OPENAI_MODEL = "gpt-3.5-turbo-0125"
OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
OLLAMA_MODEL_DEFAULT = "llama3.1:8b"
OLLAMA_API_URL_DEFAULT = "http://localhost:11434/api/chat"


@dataclass
class Finding:
    commit_hash: str
    file_path: str
    line_number: Optional[int]
    snippet: str
    finding_type: str
    rationale: str
    confidence: str
    heuristic_match: Optional[str] = None


class SecretPatterns:
    # სხვადასხვა საიდუმლოებების პატერნები
    # შეიძლება იყოს false positive-ებიც, ამიტომ კონტექსტიც უნდა შევამოწმოთ
    PATTERNS = {
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

    # საერთო პატერნები რომლებიც ჩვეულებრივ არის ტესტური მონაცემები
    FALSE_POSITIVE_INDICATORS = [
        r'example\.com',
        r'example\.org',
        r'localhost',
        r'127\.0\.0\.1',
        r'test[_-]?(?:key|token)',
        r'fake[_-]?key',
        r'sample[_-]?key',
        r'dummy',
        r'placeholder',
        r'your[_-]?(?:key|token|secret|password)',
        r'xxx+',
        r'000+',
        r'123456',
        r'abcdef',
        r'replace[_-]?me',
        r'change[_-]?me',
        r'insert[_-]?here',
        r'<.*>',
        r'\{.*\}',
        r'\$\{.*\}',
        r'%.*%',
    ]


class GitSecretsScanner:

    def __init__(
        self,
        repo_path: str,
        n_commits: int,
        use_llm: bool = False,
        llm_provider: str = "openai",
        ollama_api_url: Optional[str] = None,
        ollama_model: Optional[str] = None
    ):
        self.repo_path = Path(repo_path).resolve()
        self.n_commits = n_commits
        self.use_llm = use_llm
        self.llm_provider = llm_provider
        self.findings: List[Finding] = []
        self.is_temp_repo = False
        self.api_key_set = False
        self.ollama_api_url = ollama_api_url or os.getenv("OLLAMA_API_URL", OLLAMA_API_URL_DEFAULT)
        self.ollama_model = ollama_model or os.getenv("OLLAMA_MODEL", OLLAMA_MODEL_DEFAULT)

        # API გამოყენების თვალყურის დევნება რომ არ გავაჭარბოთ request-ებს
        self.api_call_count = 0
        self.last_api_call = 0

        if self.use_llm:
            if self.llm_provider == 'openai':
                if os.getenv('OPENAI_API_KEY'):
                    self.api_key_set = True
                else:
                    print("WARN: OPENAI_API_KEY not set. Using local LLM simulation.", file=sys.stderr)
            elif self.llm_provider == 'ollama':
                print(f"INFO: Using Ollama at {self.ollama_api_url} with model '{self.ollama_model}'", file=sys.stderr)

    def calculate_entropy(self, string: str) -> float:
        # შენონის ენტროპია - ეხმარება იდენტიფიცირებაში რანდომულად გამოიყურება თუ არა
        # მაღალი ენტროპია = უფრო რანდომული
        if not string:
            return 0.0

        entropy = 0.0
        for char in set(string):
            p_x = string.count(char) / len(string)
            entropy += -p_x * math.log2(p_x)

        return entropy

    def is_high_entropy(self, string: str, threshold: float = 4.5) -> bool:
        # ამოწმებს აქვს თუ არა ეჭვიანად მაღალი ენტროპია
        if len(string) < 20:
            return False
        return self.calculate_entropy(string) > threshold

    def is_likely_false_positive(self, text: str) -> bool:
        # სწრაფი შემოწმება ტესტური მონაცემების გასაფილტრად
        text_lower = text.lower()
        return any(re.search(pattern, text_lower, re.IGNORECASE)
                   for pattern in SecretPatterns.FALSE_POSITIVE_INDICATORS)

    def scan_with_heuristics(self, text: str) -> List[Dict[str, Any]]:
        # პირველი გავლა: პატერნებზე დაფუძნებული დეტექცია
        # აბრუნებს კანდიდატებს რომლებსაც შემდგომი ანალიზი სჭირდება
        candidates = []

        # ყველა ცნობილი საიდუმლოების პატერნის შემოწმება
        for secret_type, pattern in SecretPatterns.PATTERNS.items():
            for match in re.finditer(pattern, text, re.IGNORECASE):
                try:
                    matched_text = match.group(1) if match.groups() else match.group(0)
                except IndexError:
                    matched_text = match.group(0)

                full_snippet = match.group(0)

                if not self.is_likely_false_positive(full_snippet):
                    candidates.append({
                        'type': secret_type,
                        'text': matched_text,
                        'full_snippet': full_snippet,
                        'start': match.start(),
                        'end': match.end()
                    })

        # მაღალი ენტროპიის სტრინგების შემოწმება ცვლადების მინიჭებაში
        # ეს იჭერს საიდუმლოებებს რომლებიც არ ემთხვევა ცნობილ პატერნებს
        var_pattern = r'[\w_]+\s*[=:]\s*["\']([A-Za-z0-9+/=_-]{20,})["\']'
        for match in re.finditer(var_pattern, text):
            value = match.group(1)
            full_snippet = match.group(0)
            if self.is_high_entropy(value) and not self.is_likely_false_positive(full_snippet):
                candidates.append({
                    'type': 'high_entropy_string',
                    'text': value,
                    'full_snippet': full_snippet,
                    'start': match.start(),
                    'end': match.end()
                })

        return candidates

    def call_openai_api(self, snippet: str, context: str) -> Optional[Dict[str, Any]]:
        # გაგზავნა OpenAI-ში რომ გაანალიზოს რეალურია თუ არა საიდუმლოება
        if not self.api_key_set:
            # თუ API key არ არის, ვიყენებთ სიმულაციას
            return self.simulate_llm_analysis(snippet, context)

        # მარტივი rate limiting რომ API-ს ზედმეტად არ დავტვირთოთ
        current_time = time.time()
        if current_time - self.last_api_call < 0.5:
            time.sleep(0.5)

        self.last_api_call = current_time
        self.api_call_count += 1

        prompt = f"""Analyze this code snippet for potential secrets or credentials.

Snippet: {snippet}
Context: {context}

Is this a real secret/credential or a false positive (test data, placeholder, example)?
Respond with JSON only:
{{
  "is_secret": true/false,
  "confidence": "high"/"medium"/"low",
  "finding_type": "type of secret",
  "rationale": "brief explanation"
}}"""

        try:
            response = requests.post(
                OPENAI_API_URL,
                headers={
                    "Authorization": f"Bearer {os.getenv('OPENAI_API_KEY')}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": OPENAI_MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.3,
                    "max_tokens": 200
                },
                timeout=30
            )

            if response.status_code != 200:
                print(f"WARN: API returned status {response.status_code}", file=sys.stderr)
                return None

            content = response.json()['choices'][0]['message']['content'].strip()
            
            # JSON რესპონსის დაპარსვა
            if content.startswith('```'):
                content = content.split('```')[1]
                if content.startswith('json'):
                    content = content[4:]
            
            return json.loads(content)

        except requests.exceptions.Timeout:
            print("WARN: API request timed out", file=sys.stderr)
            return None
        except Exception as e:
            print(f"WARN: API call failed: {e}", file=sys.stderr)
            return None

    def call_ollama_api(self, snippet: str, context: str) -> Optional[Dict[str, Any]]:
        # ლოკალური Ollama instance-ის გამოძახება LLM ანალიზისთვის
        prompt = f"""Analyze this code snippet for potential secrets or credentials.

Snippet: {snippet}
Context: {context}

Is this a real secret/credential or a false positive (test data, placeholder, example)?
Respond with JSON only:
{{
  "is_secret": true/false,
  "confidence": "high"/"medium"/"low",
  "finding_type": "type of secret",
  "rationale": "brief explanation"
}}"""

        try:
            response = requests.post(
                self.ollama_api_url,
                json={
                    "model": self.ollama_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                    "options": {
                        "temperature": 0.3,
                        "num_predict": 200
                    }
                },
                timeout=60
            )

            if response.status_code != 200:
                print(f"WARN: Ollama returned status {response.status_code}", file=sys.stderr)
                return None

            content = response.json()['message']['content'].strip()
            
            # რესპონსის გასუფთავება
            if content.startswith('```'):
                content = content.split('```')[1]
                if content.startswith('json'):
                    content = content[4:]
            
            return json.loads(content)

        except requests.exceptions.Timeout:
            print("WARN: Ollama request timed out", file=sys.stderr)
            return None
        except Exception as e:
            print(f"WARN: Ollama call failed: {e}", file=sys.stderr)
            return None

    def simulate_llm_analysis(self, snippet: str, context: str) -> Dict[str, Any]:
        # როცა რეალურ LLM-ს ვერ ვიყენებთ
        # ვაკეთებთ ძირითად ჰევრისტიკებს რაც LLM-მა შეიძლება თქვას
        snippet_lower = snippet.lower()
        context_lower = context.lower()

        # აშკარა false positive-ების შემოწმება
        false_positive_keywords = ['test', 'example', 'fake', 'dummy', 'placeholder', 'sample']
        if any(kw in snippet_lower or kw in context_lower for kw in false_positive_keywords):
            return {
                "is_secret": False,
                "confidence": "high",
                "finding_type": "test_data",
                "rationale": "Contains test/example keywords"
            }

        # თუ რეალურ საიდუმლოების პატერნს ჰგავს
        if len(snippet) > 30 and self.is_high_entropy(snippet):
            return {
                "is_secret": True,
                "confidence": "medium",
                "finding_type": "potential_secret",
                "rationale": "High entropy string without obvious false positive markers"
            }

        # ნაგულისხმევი: ალბათ არ არის საიდუმლოება
        return {
            "is_secret": False,
            "confidence": "low",
            "finding_type": "unknown",
            "rationale": "Insufficient evidence of real secret"
        }

    def analyze_with_llm(self, snippet: str, context: str) -> Optional[Dict[str, Any]]:
        # შესაბამისი LLM პროვაიდერისკენ მიმართვა
        if self.llm_provider == 'openai':
            return self.call_openai_api(snippet, context)
        elif self.llm_provider == 'ollama':
            return self.call_ollama_api(snippet, context)
        else:
            print(f"WARN: Unknown provider {self.llm_provider}", file=sys.stderr)
            return None

    def get_commits(self) -> List[Dict[str, str]]:
        # ბოლო N კომიტის მოძიება რეპოდან
        try:
            result = subprocess.run(
                ['git', '-C', str(self.repo_path), 'log', f'-{self.n_commits}', '--pretty=format:%H||%s'],
                capture_output=True,
                text=True,
                check=True
            )

            commits = []
            for line in result.stdout.strip().split('\n'):
                if '||' in line:
                    hash_part, message = line.split('||', 1)
                    commits.append({
                        'hash': hash_part,
                        'message': message
                    })

            return commits

        except subprocess.CalledProcessError as e:
            print(f"ERROR: Failed to get commits: {e.stderr}", file=sys.stderr)
            sys.exit(1)

    def get_commit_changes(self, commit_hash: str) -> List[Dict[str, Any]]:
        # კონკრეტული კომიტის diff-ის მოძიება
        try:
            result = subprocess.run(
                ['git', '-C', str(self.repo_path), 'show', '--pretty=format:', '--unified=0', commit_hash],
                capture_output=True,
                text=True,
                check=True
            )

            changes = []
            current_file = None
            current_changes = []

            # git diff output-ის დაპარსვა
            for line in result.stdout.split('\n'):
                if line.startswith('diff --git'):
                    if current_file and current_changes:
                        changes.append({
                            'file': current_file,
                            'content': '\n'.join(current_changes)
                        })
                    # ფაილის სახელის ამოღება diff ხაზიდან
                    parts = line.split()
                    if len(parts) >= 4:
                        current_file = parts[3].lstrip('b/')
                    current_changes = []
                elif line.startswith('+') and not line.startswith('+++'):
                    current_changes.append(line[1:])

            # ბოლო ფაილი არ დაგვავიწყდეს
            if current_file and current_changes:
                changes.append({
                    'file': current_file,
                    'content': '\n'.join(current_changes)
                })

            return changes

        except subprocess.CalledProcessError as e:
            print(f"WARN: Could not get changes for {commit_hash[:8]}: {e}", file=sys.stderr)
            return []

    def scan_commit(self, commit: Dict[str, str]) -> None:
        # ერთი კომიტის სკანირება საიდუმლოებებზე
        changes = self.get_commit_changes(commit['hash'])

        for change in changes:
            # ფაილები რომლებშიც ნაკლებად სავარაუდოა საიდუმლოებები
            if any(change['file'].endswith(ext) for ext in ['.png', '.jpg', '.gif', '.pdf', '.zip', '.exe']):
                continue

            # პირველ რიგში ჰევრისტიკული სკანირება
            candidates = self.scan_with_heuristics(change['content'])

            for candidate in candidates:
                # თუ LLM ჩართულია, მეორე აზრს ვითხოვთ
                if self.use_llm:
                    llm_result = self.analyze_with_llm(
                        candidate['full_snippet'],
                        change['content'][:500]  # ცოტა კონტექსტს ვაძლევთ, მთელ ფაილს არა
                    )

                    if llm_result and llm_result.get('is_secret'):
                        # LLM ფიქრობს რომ რეალურია, ქმნით finding-ს
                        finding = Finding(
                            commit_hash=commit['hash'],
                            file_path=change['file'],
                            line_number=None,  # We could calculate this but it's extra work
                            snippet=candidate['full_snippet'],
                            finding_type=llm_result.get('finding_type', candidate['type']),
                            rationale=llm_result.get('rationale', 'Pattern match'),
                            confidence=llm_result.get('confidence', 'medium'),
                            heuristic_match=candidate['type']
                        )
                        self.findings.append(finding)
                        print(f"  FOUND: {finding.finding_type} in {change['file']} (C:{finding.confidence})")
                    else:
                        print(f"  FLTR: {candidate['type']} in {change['file']} (LLM Rationale: {llm_result.get('rationale') if llm_result else 'None'})")
                else:
                    # LLM გარეშე, უბრალოდ ჰევრისტიკებს ვენდობით
                    finding = Finding(
                        commit_hash=commit['hash'],
                        file_path=change['file'],
                        line_number=None,
                        snippet=candidate['full_snippet'],
                        finding_type=candidate['type'],
                        rationale='Heuristic pattern match',
                        confidence='medium',
                        heuristic_match=candidate['type']
                    )
                    self.findings.append(finding)
                    print(f"  FOUND: {finding.finding_type} in {change['file']} (C:{finding.confidence})")

    def cleanup(self) -> None:
        # დროებითი რეპოების გაწმენდა დასრულების შემდეგ
        if self.is_temp_repo and self.repo_path.exists():
            try:
                shutil.rmtree(self.repo_path)
                print(f"Cleaned up temporary repository")
            except Exception as e:
                print(f"WARN: Could not clean up {self.repo_path}: {e}", file=sys.stderr)

    def scan(self) -> List[Finding]:
        # მთავარი სკანირების ფუნქცია - ყველაფერს აკორდინირებს
        print(f"Scanning last {self.n_commits} commits in {self.repo_path}")
        print(f"LLM Analysis: {'Enabled' if self.use_llm else 'Disabled'}")
        if self.use_llm:
            print(f"Provider: {self.llm_provider}")
            if self.llm_provider == 'openai' and self.api_key_set:
                print(f"Status: Using real {self.llm_provider.upper()} API (Model: {OPENAI_MODEL})")
            elif self.llm_provider == 'openai' and not self.api_key_set:
                print(f"Status: Using LOCAL SIMULATION due to missing API key")
            elif self.llm_provider == 'ollama':
                print(f"Status: Using Ollama at {self.ollama_api_url} (Model: {self.ollama_model})")

        print()

        commits = self.get_commits()
        print(f"Analyzing {len(commits)} commits...")

        for i, commit in enumerate(commits, 1):
            print(f"[{i}/{len(commits)}] Scanning commit {commit['hash'][:8]}...")
            self.scan_commit(commit)

        if self.use_llm and self.llm_provider == 'openai' and self.api_key_set:
            print(f"\nTotal API calls made: {self.api_call_count}")

        return self.findings

    def generate_report(self, output_path: str) -> None:
        # JSON რეპორტის გენერირება ყველა შედეგით
        report = {
            'scan_info': {
                'repository': str(self.repo_path),
                'commits_scanned': self.n_commits,
                'llm_enabled': self.use_llm,
                'llm_provider': self.llm_provider if self.use_llm else None,
                'total_findings': len(self.findings),
                'api_calls_made': self.api_call_count if self.use_llm else 0
            },
            'findings': [asdict(f) for f in self.findings]
        }

        output_file = Path(output_path)

        # თუ საჭიროა scans დირექტორიის შექმნა
        if 'scans/' in str(output_file) or output_file.parent.name == 'scans':
            output_file.parent.mkdir(parents=True, exist_ok=True)

        if output_file.parent == Path('.'):
            scans_dir = Path('scans')
            scans_dir.mkdir(exist_ok=True)
            output_file = scans_dir / output_file

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\nReport saved to: {output_file}")
        print(f"Total findings: {len(self.findings)}")

        # მოკლე შეჯამება
        if self.findings:
            print("\nSummary by confidence:")
            high = sum(1 for f in self.findings if f.confidence == 'high')
            medium = sum(1 for f in self.findings if f.confidence == 'medium')
            low = sum(1 for f in self.findings if f.confidence == 'low')
            print(f"High: {high}, Medium: {medium}, Low: {low}")


def clone_remote_repo(url: str) -> Tuple[Path, bool]:
    # დისტანციური რეპოს დროებით დირექტორიაში კლონირება სკანირებისთვის
    if not (url.startswith('http://') or url.startswith('https://') or url.startswith('git@')):
        return Path(url), False

    print(f"Cloning remote repository: {url}")

    temp_dir = tempfile.mkdtemp(prefix='git_secrets_scan_')
    temp_path = Path(temp_dir)

    try:
        # --depth 100 ვიყენებთ რომ კლონი ნაკლები იყოს
        result = subprocess.run(
            ['git', 'clone', '--depth', '100', url, str(temp_path)],
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode != 0:
            shutil.rmtree(temp_path)
            raise RuntimeError(f"Git clone failed: {result.stderr}")

        print(f"Repository cloned to: {temp_path}")
        return temp_path, True

    except subprocess.TimeoutExpired:
        if temp_path.exists():
            shutil.rmtree(temp_path)
        raise RuntimeError("Repository clone timed out (>5 minutes)")
    except Exception as e:
        if temp_path.exists():
            shutil.rmtree(temp_path)
        raise RuntimeError(f"Failed to clone repository: {e}")

def main():
    parser = argparse.ArgumentParser(
        description='LLM-Powered Git Secrets Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --repo /path/to/repo --n 10 --out report.json
  %(prog)s --repo . --n 50 --out quick-scan.json
  %(prog)s --repo https://github.com/user/repo --n 20 --enable-llm --provider openai
  %(prog)s --repo . --n 20 --out scans/report.json --enable-llm --provider ollama --ollama-model llama3.1:8b
        """
    )

    parser.add_argument('--repo', required=True, help='Path or URL to Git repository')
    parser.add_argument('--n', type=int, default=50, help='Number of recent commits to scan (default: 50)')
    parser.add_argument('--out', default='scans/report.json', help='Output JSON report file (default: scans/report.json)')

    parser.add_argument(
        '--enable-llm',
        action='store_true',
        default=False,
        help='Explicitly enable LLM analysis for deeper secret detection (disabled by default).'
    )

    parser.add_argument('--provider', choices=['openai', 'anthropic', 'ollama'], default='openai',
                        help='LLM provider to use (default: openai)')

    parser.add_argument('--ollama-url', default=os.getenv("OLLAMA_API_URL", OLLAMA_API_URL_DEFAULT),
                        help=f'Ollama chat endpoint (default env OLLAMA_API_URL or {OLLAMA_API_URL_DEFAULT})')
    parser.add_argument('--ollama-model', default=os.getenv("OLLAMA_MODEL", OLLAMA_MODEL_DEFAULT),
                        help=f'Ollama model name (default env OLLAMA_MODEL or {OLLAMA_MODEL_DEFAULT})')

    args = parser.parse_args()

    repo_path, is_temp = Path(args.repo), False
    try:
        if args.repo.startswith('http') or args.repo.startswith('git@'):
            repo_path, is_temp = clone_remote_repo(args.repo)
        elif not Path(args.repo).exists():
            if not (Path.cwd() / args.repo).exists():
                raise RuntimeError(f"Local repository path not found: {args.repo}")
            else:
                repo_path = Path.cwd() / args.repo
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    scanner = None
    try:
        scanner = GitSecretsScanner(
            repo_path=str(repo_path),
            n_commits=args.n,
            use_llm=args.enable_llm,
            llm_provider=args.provider,
            ollama_api_url=args.ollama_url,
            ollama_model=args.ollama_model
        )
        scanner.is_temp_repo = is_temp

        scanner.scan()
        scanner.generate_report(args.out)

        high_confidence = sum(1 for f in scanner.findings if f.confidence == 'high')
        if high_confidence > 0:
            print(f"\n[!] {high_confidence} high-confidence secret(s) found!")
            exit_code = 1
        else:
            exit_code = 0

    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        exit_code = 130
    except Exception as e:
        print(f"\nERROR: {e}", file=sys.stderr)
        exit_code = 1
    finally:
        if scanner and scanner.is_temp_repo:
            scanner.cleanup()

    sys.exit(exit_code)


if __name__ == '__main__':
    main()