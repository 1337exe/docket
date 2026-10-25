"""Self-test lab: scripted AI-style claims about labapp.py, with known ground truth.

`docket lab` runs the court against the live toy app and reports whether its verdicts match
what is actually true. Real vulnerabilities should survive; fake claims should die for the right reason.
"""
from __future__ import annotations

import json
import tempfile
import uuid
import threading
from pathlib import Path

from .canary import Canary
from .court import run_court
from .models import Finding
from .scope import Scope

SRC = Path(__file__).with_name("labapp.py")
NONCE = "c" + uuid.uuid4().hex[:8]


def _loc(marker):
    for i, line in enumerate(SRC.read_text().splitlines(), 1):
        if marker in line:
            return {"file": "labapp.py", "line": i, "quote": marker}
    raise KeyError(marker)


def scenarios(base):
    P = lambda path, **kw: {"kind": "http_probe", "url": base + path, **kw}
    USER = [{"kind": "attacker_state", "state": "unauthenticated"}]
    S = lambda n: [f"step {i}" for i in range(1, n + 1)]
    ex = lambda i, t, cls, impact, truth, **kw: {"finding": {
        "id": i, "title": t, "vuln_class": cls, "impact": impact, "found_by": "agent-swarm", "assumptions": USER,
        "root_cause": kw.pop("rc", None), "repro_steps": S(3), "target": "labapp.py", **kw}, "expect": truth}
    return [
        ex("L01", "SSRF in /fetch reaches internal services", "ssrf", "data-exfiltration", "survived",
           rc=_loc("# VULN: server-side request forgery"),
           probes=[{"kind": "ssrf_probe", "url": base + "/fetch?url={canary}"}]),
        ex("L02", "Template expressions evaluated in /render", "ssti", "rce", "survived", rc=_loc("# VULN: template expressions"),
           probes=[P("/render?t=%7B%7B7*7%7D%7D", expect_status=200, expect_body_regex="^49$")]),
        ex("L03", "Boolean SQL injection in /search", "sqli", "data-exfiltration", "survived", rc=_loc("# VULN: boolean-based"),
           probes=[{"kind": "boolean_probe", "url": base + "/search?q={p}", "baseline": "alice",
                    "true": "alice' AND '1'='1", "false": "alice' AND '1'='2"}]),
        ex("L04", "IDOR: user1 reads user2's order", "idor", "data-exfiltration", "survived", rc=_loc("# VULN: no ownership check"),
           probes=[P("/orders/2", headers={"X-User": "user1"}, expect_status=200, expect_body_regex="ORDER-2-SECRET")]),
        ex("L05", "Legacy export has no authentication", "auth-bypass", "data-exfiltration", "survived",
           rc=_loc("# VULN: forgot authentication"),
           probes=[P("/legacy/export", expect_status=200, expect_body_regex="LEGACY-EXPORT-ROWS")]),
        ex("L06", "Reflected XSS in /echo", "xss", "account-takeover", "killed", rc=_loc("# SAFE: output is escaped"),
           evidence=[{"type": "reflection", "note": "payload appears in page"}],
           probes=[P("/echo?q=%3Cscript%3Ealert(1)%3C/script%3E", expect_body_regex="<script>alert")]),
        ex("L07", "SQL injection in /lookup (server error on quote)", "sqli", "data-exfiltration", "killed",
           rc=_loc("# SAFE: errors on bad input"), evidence=[{"type": "status_500"}],
           probes=[{"kind": "boolean_probe", "url": base + "/lookup?id={p}", "baseline": "1", "true": "1' AND '1'='1", "false": "1' AND '1'='2"}]),
        ex("L08", "IDOR on /profile/2", "idor", "data-exfiltration", "killed", rc=_loc("# SAFE: ownership enforced"),
           probes=[P("/profile/2", headers={"X-User": "user1"}, expect_status=200, expect_body_regex="ORDER-2-SECRET")]),
        ex("L09", "Admin panel auth bypass", "auth-bypass", "account-takeover", "killed", rc=_loc("# SAFE: token required"),
           probes=[P("/admin/panel", expect_status=200, expect_body_regex="ADMIN-PANEL")]),
        ex("L10", "Command execution via /echo", "rce", "rce", "killed", rc=_loc("# SAFE: output is escaped"),
           evidence=[{"type": "marker_output", "payload": "; echo uid=0(root)", "expected": "uid=0(root)",
                      "response_body": "<p>; echo uid=0(root)</p>"}]),
        ex("L11", "SSRF via url parameter on /echo", "ssrf", "data-exfiltration", "killed", rc=_loc("# SAFE: output is escaped"),
           probes=[{"kind": "ssrf_probe", "url": base + "/echo?q={canary}"}]),
        ex("L12", "Missing security headers", "", "missing-headers", "killed", rc=_loc("# SAFE: output is escaped")),
        ex("L13", "SSRF in /fetch (cites code that is not there)", "ssrf", "data-exfiltration", "killed",
           rc={"file": "labapp.py", "line": 12, "quote": "subprocess.run(url, shell=True)"},
           probes=[{"kind": "ssrf_probe", "url": base + "/fetch?url={canary}"}]),
        ex("L15", "Path traversal in /file reads /etc/passwd", "path-traversal", "data-exfiltration", "survived", rc=_loc("# VULN: path traversal"),
           probes=[P("/file?name=../../etc/passwd", expect_status=200, expect_body_regex="root:x:0:0")]),
        ex("L16", "Path traversal in /file-safe", "path-traversal", "data-exfiltration", "killed", rc=_loc("# SAFE: only the base name"),
           probes=[P("/file-safe?name=../../etc/passwd", expect_status=200, expect_body_regex="root:x:0:0")]),
        ex("L17", "Open redirect in /go", "open-redirect", "account-takeover", "survived", rc=_loc("# VULN: open redirect"),
           probes=[P("/go?next=https://evil.example/x", expect_status=302, expect_headers={"Location": "^https://evil\\.example/"})]),
        ex("L18", "Open redirect in /go-safe", "open-redirect", "account-takeover", "killed", rc=_loc("# SAFE: only local paths"),
           probes=[P("/go-safe?next=https://evil.example/x", expect_status=302, expect_headers={"Location": "^https://evil\\.example/"})]),
        ex("L19", "CORS reflects any origin with credentials on /api/account", "cors", "data-exfiltration", "survived",
           rc=_loc("# VULN: reflects any Origin"),
           probes=[P("/api/account", headers={"Origin": "https://evil.example"}, expect_status=200,
                     expect_headers={"Access-Control-Allow-Origin": "^https://evil\\.example$", "Access-Control-Allow-Credentials": "^true$"})]),
        ex("L20", "Wildcard CORS on /api/public leaks data", "cors", "data-exfiltration", "killed", rc=_loc("# SAFE: wildcard origin"),
           probes=[P("/api/public", headers={"Origin": "https://evil.example"}, expect_status=200,
                     expect_headers={"Access-Control-Allow-Origin": "^https://evil\\.example$", "Access-Control-Allow-Credentials": "^true$"})]),
        ex("L21", "JWT 'alg: none' accepted on /jwt/me", "jwt", "account-takeover", "survived", rc=_loc("# VULN: accepts unsigned"),
           probes=[P("/jwt/me", headers={"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."}, expect_status=200,
                     expect_body_regex="ADMIN-DATA")]),
        ex("L22", "JWT 'alg: none' on /jwt/me-safe", "jwt", "account-takeover", "killed", rc=_loc("# SAFE branch: signature"),
           probes=[P("/jwt/me-safe", headers={"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."}, expect_status=200,
                     expect_body_regex="ADMIN-DATA")]),
        ex("L23", "Command injection in /ping", "cmdi", "rce", "survived", rc=_loc("# VULN: command injection"),
           probes=[P("/ping?host=127.0.0.1%3Bid", expect_status=200, expect_body_regex="uid=0\\(root\\)")]),
        ex("L24", "Command injection in /ping-safe", "cmdi", "rce", "killed", rc=_loc("# SAFE: argument list"),
           probes=[P("/ping-safe?host=127.0.0.1%3Bid", expect_status=200, expect_body_regex="uid=0\\(root\\)")]),
        ex("L25", "Coupon can be redeemed twice (business logic)", "logic", "data-exfiltration", "survived", rc=_loc("# VULN: a coupon can be redeemed"),
           probes=[{"kind": "sequence_probe", "steps": [{"url": base + "/coupon/redeem", "method": "POST", "expect_status": 200},
                                                       {"url": base + "/coupon/redeem", "method": "POST", "expect_status": 200}]}]),
        ex("L26", "Coupon can be redeemed twice on redeem-once", "logic", "data-exfiltration", "killed", rc=_loc("# SAFE: second use is refused"),
           probes=[{"kind": "sequence_probe", "steps": [{"url": base + "/coupon/redeem-once?c=" + NONCE, "method": "POST", "expect_status": 200},
                                                       {"url": base + "/coupon/redeem-once?c=" + NONCE, "method": "POST", "expect_status": 200}]}]),
        ex("L27", "No brute-force protection on /login", "rate-limit", "account-takeover", "survived", rc=_loc("# VULN: no lockout"),
           probes=[{"kind": "repeat_probe", "url": base + "/login", "n": 25, "expect_status": 401}]),
        ex("L28", "No brute-force protection on /login-safe", "rate-limit", "account-takeover", "killed", rc=_loc("# SAFE: throttles"),
           probes=[{"kind": "repeat_probe", "url": base + "/login-safe", "n": 25, "expect_status": 401}]),
        ex("L14", "Server-side request forgery on the fetch endpoint", "ssrf", "data-exfiltration", "duplicate",
           rc=_loc("# VULN: server-side request forgery"),
           probes=[{"kind": "ssrf_probe", "url": base + "/fetch?url={canary}"}]),
    ]


def lab_scope():
    return Scope.from_dict({"accepted_impacts": ["data-exfiltration", "rce", "account-takeover"],
                            "out_of_scope_impacts": ["missing-headers"], "attacker_states": ["unauthenticated"],
                            "active_hosts": ["127.0.0.1"], "require_judge": False, "max_repro_steps": 8})


def run_lab(verbose=True):
    from .labapp import make_server
    srv = make_server(0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    tmp = Path(tempfile.mkdtemp(prefix="fc-lab-"))
    canary = Canary(tmp / "canary.jsonl").start()
    try:
        sc = scenarios(base)
        findings = [Finding.from_dict(s["finding"]) for s in sc]
        verdicts = run_court(findings, lab_scope(), None, {}, SRC.parent, active=True, canary=canary)
    finally:
        srv.shutdown()
        canary.stop()
    rows, bad = [], 0
    for s, v in zip(sc, verdicts):
        ok = v.outcome == s["expect"]
        bad += not ok
        why = v.killed_by or v.duplicate_of
        rows.append((s["finding"]["id"], s["finding"]["title"], s["expect"], v.outcome + (f" ({why})" if why else ""), ok))
    if verbose:
        print(f"{'ID':4} {'EXPECTED':9} {'GOT':34} MATCH  TITLE")
        for i, t, e, g, ok in rows:
            print(f"{i:4} {e:9} {g:34} {'yes' if ok else 'NO ':5}  {t}")
        print(f"\n{len(rows) - bad}/{len(rows)} verdicts match ground truth")
    return verdicts, bad


def write_lab_files(out_dir, port=8099):
    """Findings + scope that target a lab app running on `port` (used by `lab --serve` and `kit`)."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    base = f"http://127.0.0.1:{port}"
    (out / "findings.json").write_text(json.dumps([s["finding"] for s in scenarios(base)], indent=2))
    (out / "expected.json").write_text(json.dumps({s["finding"]["id"]: s["expect"] for s in scenarios(base)}, indent=2))
    (out / "scope.json").write_text(json.dumps({
        "accepted_impacts": ["data-exfiltration", "rce", "account-takeover"], "out_of_scope_impacts": ["missing-headers"],
        "attacker_states": ["unauthenticated"], "active_hosts": ["127.0.0.1"], "require_judge": False}, indent=2))
    return out
