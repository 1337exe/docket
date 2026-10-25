import io
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from docket import codeverify
from docket.active import run_probe
from docket.canary import Canary, read_hits
from docket.cli import main
from docket.court import Court, run_court, try_finding
from docket.dedupe import fingerprint
from docket.ledger import append, stats
from docket.mcp import handle
from docket.models import Finding
from docket.proof import check_proof, validate
from docket.scope import Scope

SCOPE = Scope.from_dict({"accepted_impacts": ["rce", "data-exfiltration"], "attacker_states": ["unauthenticated"],
                         "active_hosts": ["127.0.0.1"], "require_judge": False})


def mk(**kw):
    base = dict(id="X", title="t", impact="rce", target="app/a.py", found_by="finder",
                assumptions=[{"kind": "attacker_state", "state": "unauthenticated"}],
                root_cause={"file": "a.py", "line": 1, "quote": "danger()"}, repro_steps=["a", "b"])
    base.update(kw)
    return Finding(**base)


# ---- proof rules ---------------------------------------------------------------------------
def test_proof_rules_reject_weak_evidence():
    assert not validate({"type": "timing", "baseline_ms": [10], "payload_ms": [5000], "delay_ms": 5000})[0]  # one sample
    assert validate({"type": "timing", "baseline_ms": [10, 12, 11], "payload_ms": [5010, 5020, 4990], "delay_ms": 5000})[0]
    assert not validate({"type": "boolean_pair", "baseline_body": "a", "true_body": "b", "false_body": "c"})[0]
    assert validate({"type": "boolean_pair", "baseline_body": "a", "true_body": "a", "false_body": "c"})[0]
    assert not validate({"type": "cross_account", "status": 200, "marker": "M", "response_body": "ok"})[0]  # 200 alone
    assert validate({"type": "cross_account", "status": 200, "marker": "M", "response_body": "xx M xx"})[0]
    assert not validate({"type": "expression_eval", "payload": "{{7*7}}", "expected": "49", "response_body": "{{7*7}}"})[0]
    assert validate({"type": "expression_eval", "payload": "{{7*7}}", "expected": "49", "response_body": "49"})[0]
    assert not validate({"type": "marker_output", "payload": "echo uid=0", "expected": "uid=0", "response_body": "uid=0"})[0]  # echo
    assert not validate({"type": "dom_exec", "executed": False})[0]
    assert not validate({"type": "unauth_access", "status": 200, "marker": "M", "response_body": "M", "credentials": "token"})[0]
    assert not validate({"type": "sequence", "steps": ["a"]})[0]
    assert not validate({"type": "nonsense"})[0]


def test_non_proof_only_fails_and_class_mismatch_fails():
    only = mk(vuln_class="sqli", evidence=[{"type": "status_500"}, {"type": "scanner_alert"}, {"type": "confidence", "value": 0.99}])
    assert check_proof(only, SCOPE).status == "fail"
    wrong = mk(vuln_class="xss", evidence=[{"type": "timing", "baseline_ms": [1, 1, 1], "payload_ms": [9, 9, 9], "delay_ms": 8}])
    assert check_proof(wrong, SCOPE).status == "fail"
    assert check_proof(mk(), SCOPE).status == "skipped"
    strict = Scope.from_dict({"require_proof": True})
    assert check_proof(mk(vuln_class="sqli"), strict).status == "unverified"


# ---- canary + live probes --------------------------------------------------------------------
@pytest.fixture
def app():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            import urllib.request
            from urllib.parse import parse_qs, urlparse
            u = urlparse(self.path)
            if u.path == "/fetch":
                try:
                    urllib.request.urlopen(parse_qs(u.query)["url"][0], timeout=2).read()
                except Exception:
                    pass
            if u.path == "/redir":
                self.send_response(302)
                self.send_header("Location", "http://169.254.169.254/")
                self.end_headers()
                return
            body = b"hello 49" if u.path == "/ok" else b"nope"
            self.send_response(200 if u.path in ("/ok", "/fetch") else 404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_probes_respect_scope_and_expectations(app, tmp_path):
    ok = {"kind": "http_probe", "url": app + "/ok", "expect_status": 200, "expect_body_regex": "49"}
    assert run_probe(ok, SCOPE)[0] == "pass"
    assert run_probe({**ok, "expect_body_regex": "zzz"}, SCOPE)[0] == "fail"
    assert run_probe({**ok, "url": app + "/missing"}, SCOPE)[0] == "fail"  # 404 != 200
    assert run_probe({**ok, "url": "http://example.org/"}, SCOPE)[0] == "unverified"  # host not allowed: never contacted
    assert run_probe({**ok, "method": "DELETE"}, SCOPE)[0] == "fail"
    assert run_probe({"kind": "http_probe", "url": app + "/redir", "expect_status": 302}, SCOPE)[0] == "pass"  # not followed
    c = Canary(tmp_path / "c.jsonl").start()
    try:
        assert run_probe({"kind": "ssrf_probe", "url": app + "/fetch?url={canary}", "wait": 2}, SCOPE, c)[0] == "pass"
        assert run_probe({"kind": "ssrf_probe", "url": app + "/ok?url={canary}", "wait": 0.3}, SCOPE, c)[0] == "fail"
        n = c.new_nonce()
        assert read_hits(c.logfile, "short") == [] and read_hits(c.logfile, n) == []
    finally:
        c.stop()


def test_oob_evidence_checked_against_canary_log(tmp_path):
    log = tmp_path / "c.jsonl"
    log.write_text(json.dumps({"path": "/c/abcdef123456"}) + "\n")
    f = mk(vuln_class="ssrf", evidence=[{"type": "oob_callback", "nonce": "abcdef123456"}])
    assert check_proof(f, SCOPE, str(log)).status == "pass"
    f2 = mk(vuln_class="ssrf", evidence=[{"type": "oob_callback", "nonce": "madeupnonce99"}])
    assert check_proof(f2, SCOPE, str(log)).status == "fail"


def test_probe_off_without_active_flag(app):
    f = mk(probes=[{"kind": "http_probe", "url": app + "/ok", "expect_status": 200}])
    v = try_finding(f, SCOPE, None, {}, None)  # no active
    assert [c for c in v.checks if c.name == "proof"][0].status == "unverified"


# ---- code verifiers --------------------------------------------------------------------------
@pytest.fixture
def code(tmp_path):
    (tmp_path / "svc.py").write_text(
        "def helper(x):\n    return db.execute('SELECT ' + x)\n\n"
        "def dead(x):\n    return db.execute('SELECT ' + x)\n\n"
        "@app.get('/a')\ndef a():\n    q = request.args['q']\n    return helper(q)\n\n"
        "@app.get('/b')\ndef b():\n    q = request.args['q']\n    return db.execute('SELECT 1 WHERE n = %s', (q,))\n\n"
        "@app.get('/c')\ndef c():\n    return db.execute('SELECT 1')\n\n"
        "@app.get('/d')\ndef d():\n    t = request.args['t']\n    sql = f'SELECT {t}'\n    return db.execute(sql)\n\n"
        "@app.get('/e')\ndef e():\n    return db.execute(CONFIG_QUERY)\n")
    codeverify.clear_cache()
    return tmp_path


def test_entrypoint_reachability(code):
    assert codeverify.entrypoint_reaches({"function": "helper"}, code)[0] == "pass"      # a() -> helper()
    assert codeverify.entrypoint_reaches({"function": "dead"}, code)[0] == "fail"
    assert codeverify.entrypoint_reaches({"function": "nope"}, code)[0] == "fail"       # hallucinated function
    assert codeverify.entrypoint_reaches({"function": "a"}, None)[0] == "unverified"


def test_taint_flow(code):
    t = lambda fn: codeverify.taint_flow({"function": fn, "sink": "execute"}, code)[0]
    assert t("b") == "fail"          # parameterized
    assert t("c") == "fail"          # constant
    assert t("d") == "pass"          # f-string built from request data
    assert t("e") == "unverified"    # unknown origin: never guessed
    assert codeverify.taint_flow({"function": "a", "sink": "nothing"}, code)[0] == "fail"
    # helper(x) is not an entrypoint: its parameter may or may not carry attacker data, so Docket says "unverified"
    assert codeverify.taint_flow({"function": "helper", "sink": "execute"}, code)[0] == "unverified"


def test_path_traversal_and_symlinks_not_followed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("def leak():\n    pass\n")
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "link.py").symlink_to(outside / "secret.py")
    codeverify.clear_cache()
    assert codeverify.entrypoint_reaches({"function": "leak"}, proj)[0] == "fail"  # symlink target never read


# ---- facts, flags, trust, forbidden states --------------------------------------------------------
def test_fact_flag_trust_and_forbidden(tmp_path):
    facts = {"flags": {"BETA": False}, "instances": {"i-1": {"imds": "v2-required"}},
             "roles": {"r": {"trust": {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
                                                       "Action": "sts:AssumeRole"}]}}}}
    v = lambda a, sc=SCOPE: __import__("docket.verifiers", fromlist=["x"]).verify_assumption(a, sc, facts, None)[0]
    assert v({"kind": "flag_enabled", "name": "BETA"}) == "fail"
    assert v({"kind": "flag_enabled", "name": "NOPE"}) == "unverified"
    assert v({"kind": "fact", "path": "instances.i-1.imds", "value": "v1-allowed"}) == "fail"
    assert v({"kind": "fact", "path": "instances.i-1.imds", "value": "v2-required"}) == "pass"
    assert v({"kind": "fact", "path": "instances.i-1.imds", "op": "exists"}) == "pass"
    assert v({"kind": "aws_trust_allows", "role": "r", "principal": "arn:aws:iam::111122223333:role/x"}) == "pass"
    assert v({"kind": "aws_trust_allows", "role": "r", "principal": "arn:aws:iam::999999999999:role/x"}) == "fail"
    strict = Scope.from_dict({"forbidden_states": ["physical access"], "attacker_states": ["unauthenticated"]})
    assert v({"kind": "attacker_state", "state": "unauthenticated", "text": "attacker has physical access to the rack"}, strict) == "fail"


# ---- dedupe, baseline, panel ------------------------------------------------------------------
def test_duplicates_and_baseline(tmp_path):
    a, b = mk(id="A"), mk(id="B", found_by="other")
    c = mk(id="C", root_cause={"file": "a.py", "line": 1, "quote": "something else"})
    out = run_court([a, b, c], SCOPE, None, {}, None)
    assert [v.outcome for v in out][1] == "duplicate" and out[1].duplicate_of == "A" and out[2].outcome != "duplicate"
    known = {fingerprint(a)}
    out = run_court([a], SCOPE, None, {}, None, known_fingerprints=known)
    assert out[0].outcome == "duplicate"
    kn = Scope.from_dict({"known_issues": ["Verbose error"], "require_judge": False})
    assert run_court([mk(id="K", title="Verbose error page")], kn)[0].outcome == "duplicate"


def test_judge_panel_quorum():
    yes = lambda f, p: {"reproduced": True, "model": "m1"}
    no = lambda f, p: {"reproduced": False, "model": "m2"}
    unsure = lambda f, p: {"reproduced": "unsure", "model": "m3"}
    same = lambda f, p: {"reproduced": True, "model": "FINDER"}
    sc = lambda q: Scope.from_dict({"judge_quorum": q, "accepted_impacts": ["rce"]})
    j = lambda q, *judges: [c for c in try_finding(mk(), sc(q), list(judges), {}, None).checks if c.name == "judge"][0]
    assert j("majority", yes, yes, no).status == "pass"
    assert j("majority", yes, no, no).status == "fail"
    assert j("majority", yes, no).status == "unverified"
    assert j("unanimous", yes, yes, unsure).status == "unverified"
    assert j("unanimous", yes, no).status == "fail"
    assert j("any", no, yes).status == "pass"
    r = j("majority", same, yes)  # the finder-model vote is dropped
    assert r.status == "pass" and "vote ignored" in r.reason


# ---- embedding: Python API, MCP, ledger, CLI ----------------------------------------------------------
def test_python_api_remembers_duplicates():
    court = Court({"accepted_impacts": ["rce"], "require_judge": False}, target_dir=None)
    first = court.try_one({"id": "1", "title": "t", "impact": "rce", "root_cause": {"fact_path": "x"}})
    again = court.try_one({"id": "2", "title": "t", "impact": "rce", "root_cause": {"fact_path": "x"}})
    assert first["outcome"] != "duplicate" and again["outcome"] == "duplicate" and again["duplicate_of"] == "1"


def test_mcp_protocol():
    court = Court({"accepted_impacts": ["rce"], "require_judge": False})
    r = handle(court, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}})
    assert r["result"]["serverInfo"]["name"] == "docket"
    assert handle(court, {"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert handle(court, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"][0]["name"] == "court_try_finding"
    call = handle(court, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                          "params": {"name": "court_try_finding", "arguments": {"finding": {"id": "a", "title": "t", "impact": "bad"}}}})
    assert json.loads(call["result"]["content"][0]["text"])["outcome"] == "killed"
    bad = handle(court, {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                         "params": {"name": "court_try_finding", "arguments": {"finding": {}}}})
    assert bad["result"]["isError"] is True
    assert handle(court, {"jsonrpc": "2.0", "id": 5, "method": "nope"})["error"]["code"] == -32601


def test_mcp_over_stdio_subprocess(tmp_path):
    import subprocess
    (tmp_path / "scope.json").write_text(json.dumps({"accepted_impacts": ["rce"], "require_judge": False}))
    msgs = "\n".join(json.dumps(m) for m in [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "court_try_finding",
         "arguments": {"finding": {"id": "z", "title": "t", "impact": "rce"}}}}]) + "\n"
    out = subprocess.run([sys.executable, "-m", "docket.cli", "mcp", "--scope", str(tmp_path / "scope.json")],
                         input=msgs, capture_output=True, text=True, timeout=30).stdout.strip().splitlines()
    assert len(out) == 2 and json.loads(json.loads(out[1])["result"]["content"][0]["text"])["id"] == "z"


def test_ledger_stats_and_baseline_cli(tmp_path):
    assert main(["demo", "--out-dir", str(tmp_path)]) == 0
    verdicts = json.loads((tmp_path / "report.json").read_text())["verdicts"]
    from docket.models import Verdict
    led = tmp_path / "led.jsonl"
    p = tmp_path
    base = ["try", str(p / "findings.json"), "--scope", str(p / "scope.json"), "--facts", str(p / "facts.json"),
            "--target", str(p / "target"), "--judge-file", str(p / "judge.json"), "--out", str(p / "o.html"),
            "--ledger", str(led)]
    assert main(base) == 0
    rows = {r["found_by"]: r for r in stats(str(led))}
    assert rows["finder-model"]["survived"] == 7 and rows["second-agent"]["duplicate"] == 1
    # baseline: everything killed/survived before is skipped as known on the next run
    assert main(base + ["--baseline", str(p / "report.json"), "--json", str(p / "r2.json")]) == 0
    s2 = json.loads((p / "r2.json").read_text())["summary"]
    assert s2["survived"] == 0 and s2["killed"] == 0 and s2["needs_human"] == 1  # only the unverified one comes back


def test_exports(tmp_path):
    assert main(["demo", "--out-dir", str(tmp_path)]) == 0
    sarif = json.loads((tmp_path / "survivors.sarif").read_text())
    res = sarif["runs"][0]["results"]
    assert sarif["version"] == "2.1.0" and {r["level"] for r in res} == {"error", "warning"} and len(res) == 8
    assert res[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app/orders.py"
    md = (tmp_path / "summary.md").read_text()
    assert md.startswith("## Docket") and "| survived |" in md


def test_stdin_init_and_fail_on(tmp_path, monkeypatch, capsys):
    assert main(["init", str(tmp_path)]) == 0 and (tmp_path / "scope.json").exists()
    assert main(["init", str(tmp_path)]) == 0 and "skip" in capsys.readouterr().out  # never overwrites
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps([{
        "id": "s", "title": "t", "impact": "data-exfiltration", "repro_steps": ["a", "b"],
        "assumptions": [{"kind": "attacker_state", "state": "unauthenticated"}],
        "root_cause": {"fact_path": "policies.web-role"}}])))
    assert main(["try", "-", "--scope", str(tmp_path / "scope.json"), "--facts", str(tmp_path / "facts.json"),
                 "--out", str(tmp_path / "o.html"), "--fail-on", "needs-human"]) == 2  # unverifiable -> needs a human -> gate trips


def test_lab_ground_truth():
    from docket.lab import run_lab
    verdicts, bad = run_lab(verbose=False)
    assert bad == 0 and len(verdicts) == 28


def test_selftest_and_kit(tmp_path, capsys):
    assert main(["selftest", "--out-dir", str(tmp_path / "st")]) == 0
    out = capsys.readouterr().out
    assert out.count("[PASS]") == 7 and "install is healthy" in out
    assert main(["kit", str(tmp_path / "kit")]) == 0
    for rel in ("KIT.md", "case/findings.json", "lab/findings.json", "lab/expected.json", "examples/judge_stub.py",
                "examples/github-action.yml", "examples/mcp.json"):
        assert (tmp_path / "kit" / rel).exists(), rel
