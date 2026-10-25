"""Record/replay: judge votes, live probe results and AI reviews are saved so a run can be replayed offline
and produce the same verdicts (judges and live targets are not deterministic; the record makes them so)."""
from __future__ import annotations


class Record:
    def __init__(self, data=None):
        self.data = data or {"judge": {}, "probes": {}, "ai": {}}

    def put_judge(self, fid, votes):
        self.data["judge"][fid] = votes

    def put_probes(self, fid, results):
        self.data["probes"][fid] = [list(r) for r in results]

    def put_ai(self, fid, review):
        self.data["ai"][fid] = review
