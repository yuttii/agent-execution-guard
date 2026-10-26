from __future__ import annotations

import re

DEFAULT_SECRET_PATTERNS: dict[str, str] = {
    'aws access key': r'\bAKIA[0-9A-Z]{16}\b',
    'private key block': r'-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----',
    'github token': r'\bgh[pousr]_[A-Za-z0-9]{36,}\b',
    'sk- api key': r'\bsk-[A-Za-z0-9_-]{20,}\b',
    'jwt': r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b',
    'key=value secret': r'\b(?:api[_-]?key|secret|token|password)\b\s*[:=]\s*\S{8,}',
}

DEFAULT_INJECTION_PATTERNS = [
    r'\bignore (?:all |the |any )?(?:previous|prior|above|earlier) (?:instructions|rules|messages)\b',
    r'\bdisregard\b.{0,30}\b(?:instructions|rules|system prompt)\b',
    r'\b(?:new|updated) (?:instructions|system prompt)\s*:',
    r'\byou are now\b',
    r'\bdo not (?:tell|inform|mention)\b.{0,30}\buser\b',
    r'\b(?:send|forward|upload|post|email)\b.{0,60}\b(?:api[_ ]?keys?|credentials?|passwords?|secrets?|\.env)\b',
]


class OutputInspector:
    def __init__(self, secret_patterns: dict[str, str] | None = None,
                 injection_patterns: list[str] | None = None):
        self.secrets = {
            name: re.compile(p, re.I)
            for name, p in (secret_patterns or DEFAULT_SECRET_PATTERNS).items()
        }
        self.injections = [
            re.compile(p, re.I | re.S)
            for p in (injection_patterns or DEFAULT_INJECTION_PATTERNS)
        ]

    def check(self, text: str) -> list[str]:
        out = [f'secret in tool output: {n}' for n, rx in self.secrets.items() if rx.search(text)]
        out += [f'possible prompt injection /{rx.pattern}/' for rx in self.injections if rx.search(text)]
        return out

    def has_injection(self, text: str) -> bool:
        return any(rx.search(text) for rx in self.injections)

    def redact(self, text: str) -> str:
        for rx in self.secrets.values():
            text = rx.sub('[REDACTED]', text)
        return text
