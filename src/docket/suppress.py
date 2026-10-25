"""Audited suppressions: a human decision with a reason, an author and (optionally) an expiry. Never silent."""
from __future__ import annotations

import json
from datetime import date

KEYS = {"fingerprint", "id", "title_contains", "reason", "author", "expires"}


def load(path):
    rules = json.load(open(path, encoding="utf-8"))
    rules = rules.get("suppressions", rules) if isinstance(rules, dict) else rules
    if not isinstance(rules, list):
        raise ValueError("suppressions file must be a list of rules")
    for i, r in enumerate(rules, 1):
        if not isinstance(r, dict):
            raise ValueError(f"suppression #{i} must be an object")
        extra = set(r) - KEYS
        if extra:
            raise ValueError(f"suppression #{i} has unknown keys: {', '.join(sorted(extra))}")
        if not r.get("reason") or not r.get("author"):
            raise ValueError(f"suppression #{i} needs both 'reason' and 'author'")
        if not (r.get("fingerprint") or r.get("id") or r.get("title_contains")):
            raise ValueError(f"suppression #{i} needs one of fingerprint, id, title_contains")
        if r.get("expires"):
            try:
                date.fromisoformat(str(r["expires"]))
            except ValueError:
                raise ValueError(f"suppression #{i} has an invalid 'expires' date (use YYYY-MM-DD)")
    return rules


def match(rules, finding, fp, today=None):
    """Return (rule or None, stale_rules). Expired rules never match and are reported as stale."""
    today = today or date.today()
    stale = []
    for r in rules:
        if r.get("expires") and date.fromisoformat(str(r["expires"])) < today:
            stale.append(r)
            continue
        ok = []
        if r.get("fingerprint"):
            ok.append(r["fingerprint"] == fp)
        if r.get("id"):
            ok.append(r["id"] == finding.id)
        if r.get("title_contains"):
            ok.append(r["title_contains"].lower() in finding.title.lower())
        if ok and all(ok):
            return r, stale
    return None, stale
