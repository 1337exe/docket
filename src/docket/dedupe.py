"""Duplicates and known issues: the same root cause found twice (or already reported) is not new work."""
from __future__ import annotations

import hashlib
import re


def _norm(s):
    return " ".join(re.findall(r"[a-z0-9]+", s.lower()))


def fingerprint(f) -> str:
    rc = f.root_cause or {}
    if rc.get("file") and rc.get("line"):
        key = f"{rc['file']}|{rc.get('line')}|{_norm(str(rc.get('quote', '')))}|{f.impact}|{f.vuln_class}"
    elif rc.get("fact_path"):
        key = f"{rc['fact_path']}|{f.impact}|{f.vuln_class}"
    else:
        key = f"{_norm(f.title)}|{f.impact}|{f.target}"
    return hashlib.sha1(key.encode()).hexdigest()[:12]


def find_duplicates(findings, known_fingerprints=(), known_phrases=()):
    """Return {finding.id: (fingerprint, duplicate_of or '')}. First occurrence wins."""
    first, out = {}, {}
    phrases = [p.lower() for p in known_phrases]
    for f in findings:
        fp = fingerprint(f)
        dup = ""
        if fp in known_fingerprints:
            dup = "known:" + fp
        elif any(p in f.title.lower() for p in phrases):
            dup = "known issue (scope)"
        elif fp in first:
            dup = first[fp]
        else:
            first[fp] = f.id
        out[f.id] = (fp, dup)
    return out
