from __future__ import annotations

import json
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import date

from . import active as active_mod
from . import suppress as suppress_mod
from .autoverify import add_auto_assumptions
from .dedupe import find_duplicates, fingerprint
from .hints import hints_for
from .judge import blind_payload
from .models import (CHECKS, FAIL, PASS, SKIPPED, UNVERIFIED, CheckResult, Finding, Verdict)
from .proof import check_proof
from .record import Record
from .redact import redact_obj
from .scope import Scope
from .verifiers import safe_join, verify_assumption


@dataclass
class Env:
    scope: Scope
    judges: list = field(default_factory=list)
    facts: dict = field(default_factory=dict)
    target_dir: object = None
    canary_log: object = None
    active: bool = False
    canary: object = None            # Canary instance, used by ssrf_probe
    ai_client: object = None         # providers.Client for --escalate
    record: Record = field(default_factory=Record)
    replay: Record = None            # when set, judges/probes/AI are answered from this record (no network)
    probe_budget: list = field(default_factory=lambda: [300])
    probe_delay: float = 0.0
    auto_verify: bool = False
    ai_threshold: float = 0.8


def guarded(name):
    """A check that crashes on malformed input must become 'unverified', never an exception and never a pass."""
    def deco(fn):
        def wrapper(*a, **k):
            try:
                return fn(*a, **k)
            except Exception as e:  # noqa: BLE001 - deliberate: hostile input must not crash the court
                return CheckResult(name, UNVERIFIED, f"check could not run on this input ({type(e).__name__})")
        wrapper.__name__ = fn.__name__
        return wrapper
    return deco


def _combine(results):
    fails = [r for s, r in results if s == FAIL]
    if fails:
        return FAIL, "; ".join(fails)
    unv = [r for s, r in results if s == UNVERIFIED]
    if unv:
        return UNVERIFIED, "; ".join(unv)
    return PASS, "; ".join(r for _, r in results)


# assumptions that only say where an attacker could stand or that code is called; they never show exploitability
WEAK_KINDS = {"production_code", "attacker_state", "entrypoint_reaches", "file_contains", "fact", "flag_enabled"}


@guarded("reachability")
def check_reachability(f, env):
    if not env.scope.target_in_scope(f.target):
        return CheckResult("reachability", FAIL, f"target '{f.target}' is outside the allowed targets")
    if not f.assumptions:
        return CheckResult("reachability", UNVERIFIED, "finding declares no assumptions, so none can be checked")
    res = [verify_assumption(a, env.scope, env.facts, env.target_dir) for a in f.assumptions]
    status, reason = _combine(res)
    if status == PASS and not f.evidence and not f.probes and all(a.get("kind") in WEAK_KINDS for a in f.assumptions):
        status, reason = UNVERIFIED, reason + " - but nothing here shows the input is attacker-controlled or the flaw exploitable " \
            "(reachability alone is not evidence); add a taint_flow check, a probe or proof"
    return CheckResult("reachability", status, reason,
                       [{"assumption": a.get("text") or a.get("kind"), "status": s, "reason": r, "auto": bool(a.get("auto"))}
                        for a, (s, r) in zip(f.assumptions, res)])


@guarded("impact")
def check_impact(f, scope):
    for pat in scope.ineligible_patterns:
        try:
            if re.search(pat, f.title, re.I):
                return CheckResult("impact", FAIL, f"title matches the ineligible list ({pat})")
        except re.error:
            continue
    if f.impact in ("", "unspecified"):
        return CheckResult("impact", UNVERIFIED, "no impact stated (scanners rarely say): set scope.impact_map or --default-impact, "
                           "or state the impact the finding would have")
    if f.impact in scope.out_of_scope_impacts:
        return CheckResult("impact", FAIL, f"'{f.impact}' is explicitly out of scope")
    if not scope.accepted_impacts:
        return CheckResult("impact", UNVERIFIED, "scope lists no accepted impacts")
    if f.impact in scope.accepted_impacts:
        return CheckResult("impact", PASS, f"'{f.impact}' is an accepted impact")
    return CheckResult("impact", FAIL, f"'{f.impact}' is not an accepted impact (interesting is not enough)")


def run_probes(f, env):
    if env.replay is not None:
        return [tuple(r) for r in env.replay.data["probes"].get(f.id, [])]
    out = []
    for p in f.probes:
        if not env.active:
            out.append((UNVERIFIED, "live probing is off (use --active)"))
            continue
        if p.get("kind") == "ssrf_probe" and env.canary is None:
            out.append((UNVERIFIED, "no canary listener available"))
            continue
        cost = active_mod.probe_cost(p)
        if env.probe_budget[0] < cost:
            out.append((UNVERIFIED, "probe request budget exhausted (--max-probe-requests)"))
            continue
        env.probe_budget[0] -= cost
        try:
            out.append(active_mod.run_probe(p, env.scope, env.canary))
        except Exception as e:  # noqa: BLE001
            out.append((UNVERIFIED, f"probe could not run ({type(e).__name__})"))
        if env.probe_delay:
            time.sleep(env.probe_delay)
    env.record.put_probes(f.id, out)
    return out


@guarded("judge")
def check_judge(f, env):
    if env.replay is not None:
        raw = list(env.replay.data["judge"].get(f.id, []))
        judges = [None] if raw or env.scope.require_judge else []
    else:
        judges, raw = env.judges, []
    if not judges and not raw:
        if not env.scope.require_judge:
            return CheckResult("judge", SKIPPED, "scope does not require an independent judge")
        return CheckResult("judge", UNVERIFIED, "no independent judge configured")
    notes = []
    if env.replay is None:
        for j in judges:
            try:
                raw.append(j(f, blind_payload(f)))
            except Exception as e:  # a failed judge must never become a pass
                notes.append(f"a judge failed ({type(e).__name__})")
        env.record.put_judge(f.id, raw)
    votes = []
    for v in raw:
        if not isinstance(v, dict):
            notes.append("a judge returned no verdict")
            continue
        model = str(v.get("model", "")).strip()
        if not model:
            notes.append("a judge did not name its model, so independence is unknown")
        elif f.found_by and model.lower() == f.found_by.lower():
            notes.append(f"judge '{model}' is the same model that found it; vote ignored")
        else:
            votes.append((model, v.get("reproduced"), str(v.get("reason", ""))[:200]))
    detail = [{"model": m, "reproduced": r, "reason": why} for m, r, why in votes]
    if not votes:
        return CheckResult("judge", UNVERIFIED, "no valid independent vote: " + "; ".join(notes), detail)
    yes, no = sum(1 for _, r, _ in votes if r is True), sum(1 for _, r, _ in votes if r is False)
    n, q = len(votes), env.scope.judge_quorum
    tally = f"{yes} yes / {no} no / {n - yes - no} unsure of {n} independent votes"
    if q == "unanimous":
        status = PASS if yes == n else FAIL if no else UNVERIFIED
    elif q == "any":
        status = PASS if yes else FAIL if no == n else UNVERIFIED
    else:
        status = PASS if yes * 2 > n else FAIL if no * 2 > n else UNVERIFIED
    return CheckResult("judge", status, f"{tally} ({q})" + (" - " + "; ".join(notes) if notes else ""), detail)


@guarded("reconstruct")
def check_reconstruct(f, scope, facts, target_dir):
    n = len(f.repro_steps)
    if n == 0 or any(not s.strip() for s in f.repro_steps):
        return CheckResult("reconstruct", FAIL, "no usable reproduction steps")
    if n > scope.max_repro_steps:
        return CheckResult("reconstruct", FAIL, f"{n} steps is too long to rebuild by hand (limit {scope.max_repro_steps})")
    rc = f.root_cause
    if not rc:
        return CheckResult("reconstruct", FAIL, "no root cause cited")
    if "fact_path" in rc:
        node = facts
        for part in str(rc["fact_path"]).split("."):
            node = node.get(part) if isinstance(node, dict) else None
        if node is None:
            return CheckResult("reconstruct", FAIL, f"cited fact '{rc['fact_path']}' does not exist")
        return CheckResult("reconstruct", PASS, f"cited fact '{rc['fact_path']}' exists; {n} steps")
    if not target_dir:
        return CheckResult("reconstruct", UNVERIFIED, "no --target directory to check the cited code against")
    p = safe_join(target_dir, rc.get("file", ""))
    if p is None or not p.is_file():
        return CheckResult("reconstruct", FAIL, f"cited file '{rc.get('file')}' does not exist")
    lines = p.read_text(errors="replace").splitlines()
    ln, quote = rc.get("line"), (rc.get("quote") or "").strip()
    if not isinstance(ln, int) or not 1 <= ln <= len(lines):
        return CheckResult("reconstruct", FAIL, f"line {ln} is not in {rc['file']} ({len(lines)} lines)")
    if not quote:
        return CheckResult("reconstruct", UNVERIFIED, "no quote given to compare with the code")
    if quote.startswith("[secret:"):  # scanners that hide the secret: only the location can be checked
        return CheckResult("reconstruct", PASS, f"cited location {rc['file']}:{ln} exists; {n} steps")
    if quote not in lines[ln - 1]:
        return CheckResult("reconstruct", FAIL, f"line {ln} of {rc['file']} does not contain the quoted code")
    return CheckResult("reconstruct", PASS, f"quoted code is at {rc['file']}:{ln}; {n} steps")


def check_ai_review(f, env, checks):
    """AI may argue against a finding or say what would settle it. It can never approve."""
    unsettled = [{"check": c.name, "reason": c.reason[:200]} for c in checks if c.status == UNVERIFIED]
    from .providers import ProviderError, review
    try:
        if env.replay is not None:
            r = env.replay.data["ai"].get(f.id)
            if r is None:
                return None
        else:
            r = review(env.ai_client, f, unsettled)
            env.record.put_ai(f.id, r)
    except ProviderError as e:
        return CheckResult("ai-review", UNVERIFIED, f"AI review unavailable: {e}")
    same = f.found_by and r.get("model", "").lower() == f.found_by.lower()
    detail = [{k: r.get(k) for k in ("model", "likely_real", "confidence", "reason", "what_would_settle_it")}]
    if same:
        return CheckResult("ai-review", UNVERIFIED, "reviewer is the same model as the finder; opinion ignored", detail)
    if r["likely_real"] is False and r["confidence"] >= env.ai_threshold:
        if env.scope.ai_can_reject:
            return CheckResult("ai-review", FAIL, f"{r['model']} is {r['confidence']:.0%} sure this is a false positive: {r['reason']}", detail)
        return CheckResult("ai-review", UNVERIFIED, f"{r['model']} suspects a false positive ({r['confidence']:.0%}): {r['reason']} "
                           "(set scope.ai_can_reject to let AI close such findings)", detail)
    return CheckResult("ai-review", UNVERIFIED, f"{r['model']} says likely_real={r['likely_real']} ({r['confidence']:.0%}); "
                       "AI opinion alone never approves a finding", detail)


def _decide(f, checks, fp):
    failed = [c for c in checks if c.status == FAIL]
    if failed:
        v = Verdict(f, checks, "killed", failed[0].name, fingerprint=fp)
    elif all(c.status in (PASS, SKIPPED) for c in checks):
        v = Verdict(f, checks, "survived", fingerprint=fp)
    else:
        v = Verdict(f, checks, "needs-human", fingerprint=fp)
    return v


def judge_finding(f, env, fp=None) -> Verdict:
    """Run all checks for one finding (no duplicate handling)."""
    probe_results = run_probes(f, env)
    log = env.canary_log or (env.canary.logfile if env.canary else None)
    try:
        proof = check_proof(f, env.scope, log, probe_results)
    except Exception as e:  # noqa: BLE001
        proof = CheckResult("proof", UNVERIFIED, f"check could not run on this input ({type(e).__name__})")
    checks = [check_reachability(f, env), check_impact(f, env.scope), proof,
              check_judge(f, env), check_reconstruct(f, env.scope, env.facts, env.target_dir)]
    v = _decide(f, checks, fp or fingerprint(f))
    if v.outcome == "needs-human" and (env.ai_client is not None or env.replay is not None):
        ai = check_ai_review(f, env, checks)
        if ai is not None:
            checks.append(ai)
            v = _decide(f, checks, v.fingerprint)
    v.next_steps = hints_for(v)
    return v


def _as_judges(judge):
    return [] if judge is None else list(judge) if isinstance(judge, (list, tuple)) else [judge]


def try_finding(f, scope, judge=None, facts=None, target_dir=None, **kw) -> Verdict:
    return judge_finding(f, Env(scope, _as_judges(judge), facts or {}, target_dir, **kw))


def apply_impact_map(findings, scope):
    for f in findings:
        if f.impact in ("", "unspecified") and f.vuln_class in scope.impact_map:
            f.impact = scope.impact_map[f.vuln_class]


def prepare(findings, env):
    apply_impact_map(findings, env.scope)
    if env.auto_verify and env.target_dir:
        for f in findings:
            try:
                add_auto_assumptions(f, env.target_dir)
            except Exception:  # noqa: BLE001
                pass


def run_court(findings, scope, judge=None, facts=None, target_dir=None, known_fingerprints=(), suppressions=(), **kw):
    env = kw.pop("env", None) or Env(scope, _as_judges(judge), facts or {}, target_dir, **kw)
    prepare(findings, env)
    dups = find_duplicates(findings, set(known_fingerprints), scope.known_issues)
    out, stale = [], []
    for f in findings:
        fp, dup = dups[f.id]
        rule, st = suppress_mod.match(suppressions, f, fp) if suppressions else (None, [])
        stale += [r for r in st if r not in stale]
        if rule:
            out.append(Verdict(f, [], "suppressed", fingerprint=fp, note=f"{rule['reason']} (by {rule['author']}"
                               + (f", expires {rule['expires']}" if rule.get("expires") else "") + ")"))
        elif dup:
            out.append(Verdict(f, [], "duplicate", duplicate_of=dup, fingerprint=fp))
        else:
            out.append(judge_finding(f, env, fp))
    run_court.stale = stale  # surfaced by the CLI as a warning
    run_court.env = env
    return out


class Court:
    """Embeddable API: one object, feed it findings as dicts, get verdict dicts back."""

    def __init__(self, scope, judges=None, facts=None, target_dir=None, active=False, canary=None, canary_log=None, ai_client=None):
        self.env = Env(scope if isinstance(scope, Scope) else Scope.from_dict(scope), _as_judges(judges),
                       facts or {}, target_dir, canary_log, active, canary, ai_client)
        self.seen = {}
        self.log = []

    def scope_summary(self) -> dict:
        s = self.env.scope
        return {"accepted_impacts": s.accepted_impacts, "out_of_scope_impacts": s.out_of_scope_impacts,
                "attacker_states": s.attacker_states, "max_repro_steps": s.max_repro_steps, "in_scope_targets": s.in_scope_targets,
                "ineligible_patterns": s.ineligible_patterns}

    def try_one(self, finding: dict) -> dict:
        f = Finding.from_dict(finding)
        prepare([f], self.env)
        fp, dup = find_duplicates([f], set(self.seen), self.env.scope.known_issues)[f.id]
        if dup:
            v = Verdict(f, [], "duplicate", duplicate_of=self.seen.get(fp, dup), fingerprint=fp)
        else:
            v = judge_finding(f, self.env, fp)
            self.seen[fp] = f.id
        self.log.append((v.outcome, v.killed_by))
        return v.to_dict()

    def stats(self) -> dict:
        o = Counter(x for x, _ in self.log)
        k = Counter(y for x, y in self.log if x == "killed")
        return {"tried": len(self.log), "by_outcome": dict(o), "killed_by": dict(k),
                "advice": "Most kills come from: " + (k.most_common(1)[0][0] if k else "nothing yet")}

    def try_many(self, findings):
        return [self.try_one(f) for f in findings]


def summarize(verdicts) -> dict:
    out = Counter(v.outcome for v in verdicts)
    killed = Counter(v.killed_by for v in verdicts if v.outcome == "killed")
    return {"total": len(verdicts), "survived": out["survived"], "needs_human": out["needs-human"],
            "killed": out["killed"], "duplicates": out["duplicate"], "suppressed": out["suppressed"],
            "killed_by": {c: killed.get(c, 0) for c in CHECKS}}


def load_findings(path, stdin=None):
    data = json.load(stdin) if path == "-" else json.load(open(path, encoding="utf-8"))
    items = data.get("findings", data) if isinstance(data, dict) else data
    return [Finding.from_dict(d) for d in items]
