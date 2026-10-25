from __future__ import annotations

from dataclasses import dataclass, field

PASS, FAIL, UNVERIFIED, SKIPPED = "pass", "fail", "unverified", "skipped"
CHECKS = ["reachability", "impact", "proof", "judge", "reconstruct", "ai-review"]


@dataclass
class Finding:
    id: str
    title: str
    impact: str = "unspecified"
    severity: str = ""
    target: str = ""
    vuln_class: str = ""     # sqli, idor, auth-bypass, xss, ssrf, rce, ssti, file-upload, logic
    assumptions: list = field(default_factory=list)
    evidence: list = field(default_factory=list)   # observed proof (request/response pairs, timings, callbacks)
    probes: list = field(default_factory=list)     # live re-tests the court runs itself (--active)
    root_cause: dict | None = None
    repro_steps: list = field(default_factory=list)
    reasoning: str = ""      # the finder's own story; the blind judge never sees it
    found_by: str = ""       # model/tool name, used to enforce judge independence

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        if not isinstance(d, dict) or not d.get("id") or not d.get("title"):
            raise ValueError("each finding needs at least 'id' and 'title'")
        lst = lambda k: [x for x in (d.get(k) or []) if isinstance(x, dict)] if isinstance(d.get(k), list) else []
        steps = d.get("repro_steps") or []
        return cls(
            id=str(d["id"]), title=str(d["title"]), impact=str(d.get("impact") or "unspecified"),
            severity=str(d.get("severity") or ""), target=str(d.get("target") or ""),
            vuln_class=str(d.get("vuln_class") or "").lower(),
            assumptions=lst("assumptions"), evidence=lst("evidence"), probes=lst("probes"),
            root_cause=d.get("root_cause") if isinstance(d.get("root_cause"), dict) else None,
            repro_steps=[str(s) for s in steps] if isinstance(steps, list) else [],
            reasoning=str(d.get("reasoning") or ""), found_by=str(d.get("found_by") or ""))


@dataclass
class CheckResult:
    name: str
    status: str
    reason: str
    details: list = field(default_factory=list)

    def to_dict(self):
        return {"name": self.name, "status": self.status, "reason": self.reason, "details": self.details}


@dataclass
class Verdict:
    finding: Finding
    checks: list
    outcome: str         # survived | needs-human | killed | duplicate | suppressed
    killed_by: str = ""  # first failing check
    duplicate_of: str = ""
    fingerprint: str = ""
    note: str = ""       # suppression reason etc.
    next_steps: list = field(default_factory=list)

    def to_dict(self):
        f = self.finding
        return {"id": f.id, "title": f.title, "impact": f.impact, "severity": f.severity, "target": f.target,
                "vuln_class": f.vuln_class, "found_by": f.found_by, "outcome": self.outcome,
                "killed_by": self.killed_by, "duplicate_of": self.duplicate_of, "fingerprint": self.fingerprint,
                "note": self.note, "next_steps": self.next_steps,
                "root_cause": f.root_cause, "checks": [c.to_dict() for c in self.checks]}
