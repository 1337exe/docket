"""The scope contract: what the client/program accepts, and what attackers may start as."""
from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field


@dataclass
class Scope:
    accepted_impacts: list = field(default_factory=list)
    out_of_scope_impacts: list = field(default_factory=list)
    ineligible_patterns: list = field(default_factory=list)  # regexes on titles (program "ineligible" lists)
    known_issues: list = field(default_factory=list)         # fingerprints or title fragments already reported
    attacker_states: list = field(default_factory=lambda: ["unauthenticated"])
    forbidden_states: list = field(default_factory=list)     # states the protocol never allows (keywords)
    in_scope_targets: list = field(default_factory=list)     # glob patterns; empty = anything
    active_hosts: list = field(default_factory=list)         # hosts live probes may touch (your own infra only)
    max_repro_steps: int = 8
    require_proof: bool = False   # classed findings with no evidence become needs-human
    require_judge: bool = True    # no judge configured -> needs-human (False: the check is skipped)
    judge_quorum: str = "majority"  # majority | unanimous | any
    impact_map: dict = field(default_factory=dict)          # vuln_class -> impact, for scanner imports that state none
    external_verifiers: dict = field(default_factory=dict)  # name -> command (plugin verifiers, no shell)
    ai_can_reject: bool = False   # an --escalate AI may kill a needs-human finding it is confident is false (never approve)

    @classmethod
    def from_dict(cls, d: dict) -> "Scope":
        d = d or {}
        s = cls()
        for k in ("accepted_impacts", "out_of_scope_impacts", "ineligible_patterns", "known_issues",
                  "attacker_states", "forbidden_states", "in_scope_targets", "active_hosts"):
            if k in d:
                setattr(s, k, [str(x) for x in d[k]])
        s.max_repro_steps = int(d.get("max_repro_steps", 8))
        s.require_proof = bool(d.get("require_proof", False))
        s.require_judge = bool(d.get("require_judge", True))
        s.impact_map = {str(k): str(v) for k, v in (d.get("impact_map") or {}).items()}
        s.external_verifiers = {str(k): str(v) for k, v in (d.get("external_verifiers") or {}).items()}
        s.ai_can_reject = bool(d.get("ai_can_reject", False))
        s.judge_quorum = str(d.get("judge_quorum", "majority"))
        if s.judge_quorum not in ("majority", "unanimous", "any"):
            raise ValueError("judge_quorum must be majority, unanimous or any")
        return s

    @classmethod
    def load(cls, path) -> "Scope":
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))

    def target_in_scope(self, target: str) -> bool:
        if not self.in_scope_targets or not target:
            return True
        return any(fnmatch.fnmatch(target, p) for p in self.in_scope_targets)

    def host_allowed(self, host: str) -> bool:
        return bool(host) and host.lower() in {h.lower() for h in self.active_hosts}
