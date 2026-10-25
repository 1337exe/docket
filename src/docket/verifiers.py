"""Deterministic verifiers for the assumptions a finding makes.

Each returns (status, reason). Unknown assumption kinds are 'unverified', never silently 'pass'.
"""
from __future__ import annotations

import fnmatch
import re
from pathlib import Path

from . import codeverify, depverify
from .util import safe_join  # noqa: F401  (re-exported)
from .models import FAIL, PASS, UNVERIFIED


def _as_list(v):
    return v if isinstance(v, list) else [v]


def evaluate_policy(doc: dict, action: str, resource: str):
    """Return 'allowed' | 'denied' | 'implicit-deny' | 'unknown'.

    Explicit Deny wins. Statements using Condition/NotAction/NotResource that would otherwise
    match make the answer 'unknown' instead of guessing.
    """
    stmts = doc.get("Statement", [])
    stmts = stmts if isinstance(stmts, list) else [stmts]
    allowed, unknown = False, False
    for s in stmts:
        if not isinstance(s, dict):
            continue
        if "NotAction" in s or "NotResource" in s:
            unknown = True
            continue
        acts = [a.lower() for a in _as_list(s.get("Action", []))]
        ress = _as_list(s.get("Resource", []))
        if not any(fnmatch.fnmatchcase(action.lower(), a) for a in acts):
            continue
        if not any(fnmatch.fnmatchcase(resource, r) for r in ress):
            continue
        if s.get("Condition"):
            unknown = True
            continue
        if s.get("Effect") == "Deny":
            return "denied"
        if s.get("Effect") == "Allow":
            allowed = True
    if allowed:
        return "allowed"
    return "unknown" if unknown else "implicit-deny"


def verify_assumption(a: dict, scope, facts: dict, target_dir):
    kind = a.get("kind", "")
    blob = f"{a.get('state', '')} {a.get('text', '')}".lower()
    for word in scope.forbidden_states:
        if word.lower() in blob:
            return FAIL, f"needs a state the protocol never allows ('{word}')"
    if kind == "attacker_state":
        state = a.get("state", "")
        if state in scope.attacker_states:
            return PASS, f"attacker starting as '{state}' is allowed by scope"
        return FAIL, (f"needs attacker to be '{state}', but scope only allows "
                      f"{', '.join(scope.attacker_states) or 'nothing'}")
    if kind == "aws_policy_allows":
        doc = (facts.get("policies") or {}).get(a.get("policy", ""))
        if doc is None:
            return UNVERIFIED, f"policy '{a.get('policy')}' not in facts file"
        res = evaluate_policy(doc, a.get("action", ""), a.get("resource", "*"))
        if res == "allowed":
            return PASS, f"policy '{a['policy']}' allows {a['action']} on {a.get('resource', '*')}"
        if res in ("denied", "implicit-deny"):
            return FAIL, f"policy '{a['policy']}' does not allow {a['action']} on {a.get('resource', '*')} ({res})"
        return UNVERIFIED, "policy uses Condition/NotAction/NotResource, cannot decide without simulating"
    if kind == "network_exposed":
        sg = (facts.get("security_groups") or {}).get(a.get("resource", ""))
        if sg is None:
            return UNVERIFIED, f"security group '{a.get('resource')}' not in facts file"
        port = int(a.get("port", -1))
        for r in sg.get("ingress", []):
            if r.get("cidr") in ("0.0.0.0/0", "::/0") and r.get("from", 0) <= port <= r.get("to", 65535):
                return PASS, f"{a['resource']} allows {r['cidr']} to port {port}"
        return FAIL, f"{a['resource']} has no world-open rule for port {port}"
    if kind == "fact":
        return _fact(a, facts)
    if kind == "flag_enabled":
        flags = facts.get("flags") or {}
        if a.get("name") not in flags:
            return UNVERIFIED, f"flag '{a.get('name')}' not in facts file"
        want = a.get("expect", True)
        return (PASS, f"flag {a['name']} is {flags[a['name']]}") if flags[a["name"]] == want else \
            (FAIL, f"flag {a['name']} is {flags[a['name']]}, the finding needs {want}")
    if kind == "aws_trust_allows":
        role = (facts.get("roles") or {}).get(a.get("role", ""))
        if role is None:
            return UNVERIFIED, f"role '{a.get('role')}' not in facts file"
        return _trust(role.get("trust") or {}, a.get("principal", ""))
    if kind == "production_code":
        return depverify.production_code(a, target_dir)
    if kind == "dependency_vuln":
        return depverify.dependency_vuln(a, target_dir)
    if kind == "secret_plausible":
        return depverify.secret_plausible(a, target_dir)
    if kind == "aws_s3_public":
        return depverify.s3_public(a, facts)
    if kind == "external":
        return run_external(a, scope, target_dir)
    if kind == "entrypoint_reaches":
        return codeverify.entrypoint_reaches(a, target_dir)
    if kind == "taint_flow":
        return codeverify.taint_flow(a, target_dir)
    if kind == "file_contains":
        if not target_dir:
            return UNVERIFIED, "no --target directory given"
        p = safe_join(target_dir, a.get("path", ""))
        if p is None or not p.is_file():
            return FAIL, f"file '{a.get('path')}' does not exist in target"
        try:
            hit = re.search(a.get("pattern", ""), p.read_text(errors="replace"))
        except re.error:
            return UNVERIFIED, "invalid pattern"
        return (PASS, f"pattern found in {a['path']}") if hit else (FAIL, f"pattern not found in {a['path']}")
    return UNVERIFIED, f"no verifier for assumption kind '{kind or '(none)'}': {a.get('text', '')[:120]}"


def _get(path, facts):
    node = facts
    for part in str(path).split("."):
        node = node.get(part) if isinstance(node, dict) else None
        if node is None:
            return None
    return node


def _fact(a, facts):
    got, op, want = _get(a.get("path", ""), facts), a.get("op", "equals"), a.get("value")
    if op == "exists":
        expect = True if want is None else bool(want)
        return (PASS if (got is not None) == expect else FAIL), f"fact {a.get('path')} exists={got is not None}"
    if got is None:
        return FAIL, f"fact '{a.get('path')}' does not exist"
    try:
        ok = {"equals": got == want, "contains": want in got, "gt": got > want, "lt": got < want}[op]
    except (KeyError, TypeError):
        return UNVERIFIED, f"cannot apply op '{op}' to fact '{a.get('path')}'"
    return (PASS if ok else FAIL), f"fact {a['path']} {op} {want!r}: {'yes' if ok else 'no'}"


def _trust(doc, principal):
    stmts = doc.get("Statement", [])
    stmts = stmts if isinstance(stmts, list) else [stmts]
    acct = principal.split(":")[4] if principal.count(":") >= 5 else ""
    unknown = False
    for s in stmts:
        if s.get("Effect") != "Allow":
            continue
        p = s.get("Principal")
        who = [p] if p == "*" else [x for v in (p or {}).values() for x in _as_list(v)] if isinstance(p, dict) else []
        if not any(w == "*" or w == principal or (acct and w in (f"arn:aws:iam::{acct}:root", acct)) for w in who):
            continue
        if s.get("Condition"):
            unknown = True
            continue
        return PASS, f"trust policy lets {principal or 'any principal'} assume the role"
    return (UNVERIFIED, "trust policy has Conditions, cannot decide") if unknown else (FAIL, "trust policy does not allow that principal")


def run_external(a, scope, target_dir):
    """Plugin verifier: scope.external_verifiers maps a name to a command (no shell). The command reads
    {"assumption": ..., "target": ...} on stdin and prints {"status": "pass|fail|unverified", "reason": "..."}."""
    import json
    import shlex
    import subprocess
    cmd = (scope.external_verifiers or {}).get(a.get("verifier", ""))
    if not cmd:
        return UNVERIFIED, f"no external verifier named '{a.get('verifier')}' in scope.external_verifiers"
    try:
        out = subprocess.run(shlex.split(cmd), input=json.dumps({"assumption": a, "target": str(target_dir or "")}),
                             capture_output=True, text=True, timeout=int(a.get("timeout", 60)), check=True).stdout
        r = json.loads(out)
        status = r.get("status")
        if status not in (PASS, FAIL, UNVERIFIED):
            return UNVERIFIED, "external verifier returned an invalid status"
        return status, str(r.get("reason", ""))[:300] or f"external verifier '{a.get('verifier')}' said {status}"
    except Exception as e:  # noqa: BLE001
        return UNVERIFIED, f"external verifier '{a.get('verifier')}' failed ({type(e).__name__})"
