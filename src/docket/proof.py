"""Proof rules per vulnerability class, drawn from what practitioners say counts as evidence.

A lone 200, a lone 500, a scanner alert, a reflected string, an agent's explanation or a confidence
score never count. Each class needs an observed effect plus a control that rules out coincidence.
"""
from __future__ import annotations

import re
import statistics

from .canary import read_hits
from .models import FAIL, PASS, SKIPPED, UNVERIFIED, CheckResult

NON_PROOF = {"scanner_alert", "cve_match", "status_200", "status_500", "agent_explanation", "confidence",
             "screenshot", "reflection", "error_names_host"}
DB_ERR = re.compile(r"(you have an error in your sql syntax|unterminated quoted string|ORA-\d{5}|"
                    r"SQLSTATE\[|sqlite3?\.OperationalError|psycopg2?\.errors|unclosed quotation mark)", re.I)
ACCEPTED = {
    "path-traversal": {"file_read"},
    "open-redirect": {"redirect_observed"},
    "xxe": {"file_read", "oob_callback"},
    "cors": {"cors_misconfig"},
    "jwt": {"token_accepted"},
    "mass-assignment": {"privilege_changed"},
    "rate-limit": {"no_throttle"},
    "csrf": {"cross_origin_state_change"},
    "cmdi": {"marker_output", "oob_callback"},
    "sqli": {"boolean_pair", "timing", "db_error", "oob_callback"},
    "idor": {"cross_account"},
    "auth-bypass": {"unauth_access"},
    "xss": {"dom_exec"},
    "ssrf": {"oob_callback"},
    "rce": {"marker_output", "oob_callback"},
    "ssti": {"expression_eval"},
    "file-upload": {"upload_retrieved"},
    "logic": {"sequence"},
}


def _num_list(v):
    return [float(x) for x in v] if isinstance(v, list) and all(isinstance(x, (int, float)) for x in v) else []


def validate(e: dict, canary_log=None):
    """Return (ok, reason) for one evidence item."""
    t = e.get("type", "")
    if t == "boolean_pair":
        b, tr, fa = e.get("baseline_body"), e.get("true_body"), e.get("false_body")
        if None in (b, tr, fa):
            return False, "boolean_pair needs baseline_body, true_body and false_body"
        return (tr == b and fa != b), ("true matches baseline and false differs" if tr == b and fa != b
                                       else "true/false responses are not distinguishable from the baseline")
    if t == "timing":
        base, pay, delay = _num_list(e.get("baseline_ms")), _num_list(e.get("payload_ms")), e.get("delay_ms")
        if len(base) < 3 or len(pay) < 3 or not isinstance(delay, (int, float)):
            return False, "timing needs at least 3 baseline and 3 payload samples plus delay_ms (a single delay is noise)"
        diff = statistics.median(pay) - statistics.median(base)
        return diff >= 0.8 * delay, f"median delay {diff:.0f} ms vs injected {delay} ms"
    if t == "db_error":
        return bool(DB_ERR.search(str(e.get("response_body", "")))), "database error signature " + \
            ("found" if DB_ERR.search(str(e.get("response_body", ""))) else "not found in response")
    if t == "cross_account":
        ok = e.get("status") == 200 and bool(e.get("marker")) and str(e["marker"]) in str(e.get("response_body", ""))
        return ok, "other account's marker returned" if ok else "200 without the other user's data proves nothing"
    if t == "unauth_access":
        ok = (isinstance(e.get("status"), int) and 200 <= e["status"] < 300 and bool(e.get("marker"))
              and str(e["marker"]) in str(e.get("response_body", "")) and e.get("credentials", "none") == "none")
        return ok, "protected content returned without credentials" if ok else "no protected content shown without credentials"
    if t == "dom_exec":
        ok = e.get("executed") is True and e.get("via") in ("dom", "listener")
        return ok, "script execution observed" if ok else "execution not observed (reflection is not execution)"
    if t == "oob_callback":
        if not canary_log:
            return False, "no --canary-log to verify the callback against"
        hit = read_hits(canary_log, e.get("nonce"))
        return bool(hit), "callback with this nonce is in the canary log" if hit else "nonce not found in canary log"
    if t in ("marker_output", "expression_eval"):
        exp, payload, body = e.get("expected"), str(e.get("payload", "")), str(e.get("response_body", ""))
        if not exp:
            return False, f"{t} needs 'expected' (the computed value)"
        if str(exp) in payload:
            return False, "expected value appears in the payload itself, so the response may be an echo"
        return str(exp) in body, "computed value appears only in the response" if str(exp) in body else "computed value not in response"
    if t == "upload_retrieved":
        ok = e.get("retrieve_status") == 200 and bool(e.get("marker")) and str(e["marker"]) in str(e.get("retrieve_body", ""))
        return ok, "uploaded content retrieved from served location" if ok else "file never shown to be retrievable"
    if t == "sequence":
        ok = isinstance(e.get("steps"), list) and len(e["steps"]) >= 2 and e.get("forbidden_state_reached") is True
        return ok, "ordered sequence reaches a forbidden state" if ok else "needs an ordered sequence of 2+ requests that reaches a forbidden state"
    if t == "file_read":
        marker, payload, body = e.get("marker"), str(e.get("payload", "")), str(e.get("response_body", ""))
        if not marker or str(marker) in payload:
            return False, "file_read needs a 'marker' (file content) that is not part of the payload"
        ok = e.get("status") == 200 and str(marker) in body
        return ok, "file content that the payload cannot contain was returned" if ok else "file content not found in a 200 response"
    if t == "redirect_observed":
        from urllib.parse import urlparse
        loc, mine = str(e.get("location", "")), str(e.get("attacker_host", "")).lower()
        host = (urlparse(loc).hostname or "").lower()
        ok = isinstance(e.get("status"), int) and 300 <= e["status"] < 400 and bool(mine) and host == mine
        return ok, "3xx response redirects to the attacker host" if ok else "no 3xx redirect to the attacker-controlled host"
    if t == "cors_misconfig":
        h = {str(k).lower(): str(v) for k, v in (e.get("response_headers") or {}).items()} if isinstance(e.get("response_headers"), dict) else {}
        origin, acao, acac = str(e.get("request_origin", "")), h.get("access-control-allow-origin", ""), h.get("access-control-allow-credentials", "").lower()
        if acao == "*":
            return False, "wildcard origin cannot be used with credentials, so no credentialed data can be read"
        ok = bool(origin) and acao == origin and acac == "true"
        return ok, "an arbitrary origin is reflected with credentials allowed" if ok else "origin not reflected with Allow-Credentials: true"
    if t == "token_accepted":
        ok = (e.get("status") in range(200, 300) and bool(e.get("marker")) and str(e["marker"]) in str(e.get("response_body", ""))
              and e.get("control_status") in (401, 403) and e.get("forged") is True)
        return ok, "a forged token was accepted while the no-token control was rejected" if ok else \
            "needs a forged token accepted (2xx + protected marker) AND a control without it rejected (401/403)"
    if t == "privilege_changed":
        ok = bool(e.get("sent_field")) and e.get("before") is not None and e.get("after") is not None and e["before"] != e["after"]
        return ok, "attacker-supplied field changed a protected attribute" if ok else "no before/after change tied to the field the attacker sent"
    if t == "no_throttle":
        st = e.get("statuses")
        ok = isinstance(st, list) and len(st) >= 20 and all(isinstance(x, int) for x in st) and not any(x in (423, 429) for x in st) \
            and len(set(st)) <= 2
        return ok, "20+ rapid attempts were never throttled or locked out" if ok else "needs 20+ attempt statuses with no 429/423"
    if t == "cross_origin_state_change":
        ok = all(e.get(k) is True for k in ("no_token", "cross_origin", "state_changed"))
        return ok, "a cross-origin request without a token changed state" if ok else "needs no_token, cross_origin and state_changed all true"
    return False, f"unknown evidence type '{t}'"


def check_proof(f, scope, canary_log=None, probe_results=None):
    probe_results = probe_results or []
    if not f.evidence and not probe_results:
        if f.vuln_class in ACCEPTED and scope.require_proof:
            return CheckResult("proof", UNVERIFIED, f"{f.vuln_class} finding has no evidence and scope requires proof")
        return CheckResult("proof", SKIPPED, "no evidence supplied (scope does not require proof)")
    details, passed, failed, unverified = [], [], [], []
    for e in f.evidence:
        t = e.get("type", "")
        if t in NON_PROOF:
            details.append({"evidence": t, "status": "ignored", "reason": "never counts as proof"})
            continue
        if f.vuln_class in ACCEPTED and t not in ACCEPTED[f.vuln_class]:
            failed.append(f"'{t}' is not valid proof for {f.vuln_class}")
            details.append({"evidence": t, "status": FAIL, "reason": failed[-1]})
            continue
        ok, why = validate(e, canary_log)
        (passed if ok else failed).append(why)
        details.append({"evidence": t, "status": PASS if ok else FAIL, "reason": why})
    for status, why in probe_results:
        details.append({"evidence": "live-probe", "status": status, "reason": why})
        {PASS: passed, FAIL: failed}.get(status, unverified).append(why)
    if failed and not (passed and not any(d["evidence"] == "live-probe" and d["status"] == FAIL for d in details)):
        return CheckResult("proof", FAIL, "; ".join(failed), details)
    if passed:
        return CheckResult("proof", PASS, "; ".join(passed), details)
    if unverified:
        return CheckResult("proof", UNVERIFIED, "; ".join(unverified), details)
    return CheckResult("proof", FAIL, "only non-proof evidence was given (scanner alerts, 200/500 codes, "
                                      "explanations, confidence scores and reflections do not count)", details)
