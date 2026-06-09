#!/usr/bin/env python3
"""Lightweight, dependency-free secret scanner.

Always-available fallback for when gitleaks/Docker are not present. Scans a
single file and prints findings as `LINE:RULE:MASKED` to stdout.
Not a replacement for gitleaks -- just a fast safety net for vibe-coding.
"""
import re
import sys

# (rule name, compiled regex). Patterns favour low false-positives.
RULES = [
    ("AWS Access Key ID", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("AWS Secret Access Key", re.compile(r"(?i)aws.{0,20}?(secret|key).{0,20}?['\"][0-9a-zA-Z/+]{40}['\"]")),
    ("Private Key Block", re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP)? ?PRIVATE KEY-----")),
    ("GitHub Token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b")),
    ("GitHub Fine-grained PAT", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{22,}\b")),
    ("GitLab PAT", re.compile(r"\bglpat-[0-9A-Za-z_\-]{20}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("Slack Webhook", re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+")),
    ("Stripe Secret Key", re.compile(r"\b(sk|rk)_(live|test)_[0-9A-Za-z]{16,}\b")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("OpenAI API Key", re.compile(r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b")),
    ("Anthropic API Key", re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{90,}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("Generic API/Secret Assignment",
     re.compile(r"(?i)(api[_-]?key|secret|passwd|password|token|access[_-]?key)\s*[:=]\s*['\"][0-9a-zA-Z!@#$%^&*\-_./+]{12,}['\"]")),
    ("Postgres/MySQL URL with password",
     re.compile(r"(?i)\b(postgres|postgresql|mysql|mongodb(\+srv)?)://[^:/\s]+:[^@/\s]+@")),
]

# Ignore obvious placeholders to cut noise.
PLACEHOLDER = re.compile(r"(?i)(your[_-]?|example|placeholder|changeme|xxxx|<.*?>|dummy|sample|fake|test123|\.\.\.|\*{4,})")


def mask(s: str) -> str:
    s = s.strip()
    if len(s) <= 12:
        return s[:2] + "***"
    return s[:6] + "…" + s[-4:]


def main() -> int:
    if len(sys.argv) < 2:
        return 0
    path = sys.argv[1]
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return 0

    found = 0
    for i, line in enumerate(lines, 1):
        if len(line) > 2000:  # skip minified / data lines
            continue
        for name, rx in RULES:
            m = rx.search(line)
            if not m:
                continue
            hit = m.group(0)
            if PLACEHOLDER.search(hit):
                continue
            print(f"{i}:{name}:{mask(hit)}")
            found += 1
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
