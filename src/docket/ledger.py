"""A running ledger of verdicts, so you can measure which finder (model/tool) wastes your time."""
from __future__ import annotations

import json
import time
from collections import Counter, defaultdict


def append(path, verdicts):
    with open(path, "a", encoding="utf-8") as fh:
        for v in verdicts:
            fh.write(json.dumps({"ts": int(time.time()), "fingerprint": v.fingerprint, "id": v.finding.id,
                                 "found_by": v.finding.found_by or "unknown", "impact": v.finding.impact,
                                 "outcome": v.outcome, "killed_by": v.killed_by}) + "\n")


def stats(path):
    by = defaultdict(Counter)
    kills = defaultdict(Counter)
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            try:
                r = json.loads(line)
            except ValueError:
                continue
            by[r["found_by"]][r["outcome"]] += 1
            if r["outcome"] == "killed":
                kills[r["found_by"]][r["killed_by"]] += 1
    rows = []
    for who, c in sorted(by.items()):
        total = sum(c.values())
        judged = total - c["duplicate"]
        rows.append({"found_by": who, "total": total, "survived": c["survived"], "needs_human": c["needs-human"],
                     "killed": c["killed"], "duplicate": c["duplicate"],
                     "survival_rate": round(c["survived"] / judged, 3) if judged else 0.0,
                     "top_kill_reason": kills[who].most_common(1)[0][0] if kills[who] else ""})
    return rows
