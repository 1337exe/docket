"""Tamper-evident audit log: every verdict is chained to the previous one by a hash (tamper-evident, not tamper-proof)."""
from __future__ import annotations

import hashlib
import json
import time

from . import __version__


def _h(prev, rec):
    return hashlib.sha256((prev + json.dumps(rec, sort_keys=True)).encode()).hexdigest()


def _last(path):
    prev, seq = "0" * 64, 0
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    r = json.loads(line)
                    prev, seq = r["hash"], r["seq"]
    except FileNotFoundError:
        pass
    return prev, seq


def append(path, verdicts, scope_sha=""):
    prev, seq = _last(path)
    with open(path, "a", encoding="utf-8") as fh:
        for v in verdicts:
            seq += 1
            rec = {"seq": seq, "ts": int(time.time()), "docket": __version__, "scope_sha": scope_sha, "id": v.finding.id,
                   "fingerprint": v.fingerprint, "outcome": v.outcome, "killed_by": v.killed_by, "prev": prev}
            rec["hash"] = _h(prev, rec)
            prev = rec["hash"]
            fh.write(json.dumps(rec) + "\n")


def verify(path):
    prev, n = "0" * 64, 0
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            r = json.loads(line)
            h = r.pop("hash")
            if r["prev"] != prev or _h(prev, r) != h:
                return False, n, f"chain broken at record {r.get('seq')}"
            prev, n = h, n + 1
    return True, n, ""
