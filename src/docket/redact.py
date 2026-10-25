"""Secret redaction. Applied to everything sent to a judge/AI provider, and to reports by default."""
from __future__ import annotations

import hashlib
import re

PATTERNS = [
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.S)),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*\b")),
    ("bearer", re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/\-]{16,}=*")),
    ("assigned-secret", re.compile(r"(?i)\b((?:api[_-]?key|secret|token|passwd|password|authorization)[\"']?\s*[:=]\s*[\"']?)([^\s\"',;]{8,})")),
]


def _tag(kind, value):
    return f"[REDACTED:{kind}:{hashlib.sha256(value.encode()).hexdigest()[:6]}]"


def redact_text(s: str) -> str:
    if not isinstance(s, str) or not s:
        return s
    for kind, rx in PATTERNS:
        if kind == "assigned-secret":
            s = rx.sub(lambda m: m.group(1) + _tag(kind, m.group(2)), s)
        elif kind == "bearer":
            s = rx.sub(lambda m: m.group(1) + " " + _tag(kind, m.group(0)), s)
        else:
            s = rx.sub(lambda m: _tag(kind, m.group(0)), s)
    return s


def redact_obj(o):
    if isinstance(o, str):
        return redact_text(o)
    if isinstance(o, list):
        return [redact_obj(x) for x in o]
    if isinstance(o, dict):
        return {k: redact_obj(v) for k, v in o.items()}
    return o
