import json
import threading
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from docket import audit, codeverify, depverify, importers, suppress
from docket.active import run_probe
from docket.autoverify import add_auto_assumptions
from docket.court import Env, Court, run_court, try_finding
from docket.models import Finding
from docket.proof import validate
from docket.record import Record
from docket.scope import Scope
from docket.verifiers import run_external, verify_assumption

SC = Scope.from_dict({"accepted_impacts": ["rce", "data-exfiltration"], "attacker_states": ["unauthenticated"], "require_judge": False,
                      "active_hosts": ["127.0.0.1"], "impact_map": {"sqli": "data-exfiltration"}})


def src(tmp_path, text, name="app.py"):
    (tmp_path / name).write_text(text)
    codeverify.clear_cache()
    return tmp_path


def tf(tmp_path, text, fn, cls=None, sink=None):
    src(tmp_path, text)
    a = {"function": fn}
    if cls:
        a["vuln_class"] = cls
    if sink:
        a["sink"] = sink
    return codeverify.taint_flow(a, tmp_path)[0]


# ---- sanitizer-aware taint across sink classes ---------------------------------------------------
def test_command_injection_rules(tmp_path):
    base = "import subprocess, shlex, os\n@app.route('/x')\ndef h():\n    host = request.args['h']\n"
    assert tf(tmp_path, base + "    return os.system('ping ' + host)\n", "h", "cmdi") == "pass"
    assert tf(tmp_path, base + "    return os.system('ping ' + shlex.quote(host))\n", "h", "cmdi") == "fail"      # sanitizer
    assert tf(tmp_path, base + "    return subprocess.run(['ping', host])\n", "h", "cmdi") == "fail"               # argv, no shell
    assert tf(tmp_path, base + "    return subprocess.run('ping ' + host, shell=True)\n", "h", "cmdi") == "pass"   # shell=True


def test_path_traversal_ssrf_redirect_deserialization(tmp_path):
    h = "@app.route('/x')\ndef h():\n    v = request.args['v']\n"
    assert tf(tmp_path, h + "    return open(v).read()\n", "h", "path-traversal") == "pass"
    assert tf(tmp_path, h + "    return open(os.path.basename(v)).read()\n", "h", "path-traversal") == "fail"
    assert tf(tmp_path, h + "    return open('static/' + secure_filename(v)).read()\n", "h", "path-traversal") == "fail"
    assert tf(tmp_path, h + "    return requests.get(v).text\n", "h", "ssrf") == "pass"
    assert tf(tmp_path, h + "    return requests.get('https://api.example.com/items/' + str(int(v)))\n", "h", "ssrf") == "fail"
    assert tf(tmp_path, h + "    return redirect(v)\n", "h", "open-redirect") == "pass"
    assert tf(tmp_path, h + "    return redirect('/home')\n", "h", "open-redirect") == "fail"
    assert tf(tmp_path, h + "    return pickle.loads(v)\n", "h", "deserialization") == "pass"
    assert tf(tmp_path, h + "    return yaml.load(v, Loader=yaml.SafeLoader)\n", "h", "deserialization") == "fail"
    assert tf(tmp_path, h + "    return eval(v)\n", "h", "code-exec") == "pass"
    assert tf(tmp_path, h + "    return eval(ast.literal_eval(v))\n", "h", "code-exec") == "fail"
    assert tf(tmp_path, h + "    x = int(v)\n    return cur.execute('SELECT ' + str(x))\n", "h", "sqli") == "fail"  # int() sanitizes


def test_framework_entrypoints(tmp_path):
    src(tmp_path, "def index(r):\n    return helper(r)\ndef helper(r):\n    return 1\ndef orphan():\n    pass\n"
        "urlpatterns = [path('x/', index)]\n"
        "class OrderView(APIView):\n    def get(self, request):\n        return 1\n"
        "@router.post('/y')\nasync def create():\n    return 1\n")
    ok = lambda fn: codeverify.entrypoint_reaches({"function": fn}, tmp_path)[0]
    assert ok("index") == "pass" and ok("helper") == "pass" and ok("get") == "pass" and ok("create") == "pass"
    assert ok("orphan") == "fail" and ok("missing") == "fail"


def test_enclosing_function_and_autoverify(tmp_path):
    src(tmp_path, "@app.route('/s')\ndef search():\n    q = request.args['q']\n    return cur.execute('SELECT ' + q)\n\ndef dead():\n    return cur.execute('SELECT ' + request.args['q'])\n")
    assert codeverify.enclosing_function(tmp_path, "app.py", 4) == "search"
    live = Finding.from_dict({"id": "a", "title": "t", "vuln_class": "sqli", "root_cause": {"file": "app.py", "line": 4, "quote": "x"}})
    dead = Finding.from_dict({"id": "b", "title": "t", "vuln_class": "sqli", "root_cause": {"file": "app.py", "line": 7, "quote": "x"}})
    assert len(add_auto_assumptions(live, tmp_path)) == 3 and add_auto_assumptions(live, tmp_path) == []  # idempotent
    add_auto_assumptions(dead, tmp_path)
    env = Env(SC, target_dir=tmp_path, auto_verify=True)
    assert try_finding(Finding.from_dict({"id": "a", "title": "t", "impact": "rce", "vuln_class": "sqli",
                                          "root_cause": {"file": "app.py", "line": 4, "quote": "cur.execute"}, "repro_steps": ["a", "b"]}),
                       SC, None, {}, tmp_path).outcome == "needs-human"  # no assumptions without auto-verify
    out = run_court([Finding.from_dict({"id": "d", "title": "t", "impact": "rce", "vuln_class": "sqli",
                                        "root_cause": {"file": "app.py", "line": 7, "quote": "cur.execute"}, "repro_steps": ["a", "b"]})],
                    SC, env=env)
    assert out[0].killed_by == "reachability" and "dead code" in out[0].checks[0].reason


# ---- dependency / secrets / s3 / plugin ------------------------------------------------------------
def test_dependency_vuln(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\nflask==3.0.0\nPyYAML==5.1\n")
    (tmp_path / "svc.py").write_text("import requests\nimport yaml\n")
    d = lambda **a: depverify.dependency_vuln(a, tmp_path)[0]
    assert d(package="requests", fixed="2.20.0") == "pass"            # old and imported
    assert d(package="flask", fixed="2.0.0") == "fail"                # already fixed
    assert d(package="django", fixed="4.0") == "fail"                 # not a dependency at all
    (tmp_path / "svc.py").write_text("import os\n")
    assert d(package="requests", fixed="2.20.0") == "unverified"      # present but never imported directly
    (tmp_path / "package-lock.json").write_text(json.dumps({"packages": {"node_modules/lodash": {"version": "4.17.10"}}}))
    (tmp_path / "w.js").write_text("const _ = require('lodash')\n")
    assert d(package="lodash", fixed="4.17.21") == "pass"
    assert depverify.vkey("1.10.0") > depverify.vkey("1.9.9") and depverify.vkey("2.0.0rc1")[0] == 2


def test_secret_plausible(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "a.py").write_text("KEY = 'AKIAQWERTYUIOPASDFGH'\nK2 = 'AKIAIOSFODNN7EXAMPLE'\nK3 = os.environ['KEY']\n"
                                   "tok = 'x8Kd92LmQp0ZrTnV4aYb7WcEu3HgJf1S'\nplain = 'hello world'\n")
    (tmp_path / "tests" / "t.py").write_text("KEY = 'AKIAQWERTYUIOPASDFGH'\n")
    s = lambda f, ln: depverify.secret_plausible({"file": f, "line": ln}, tmp_path)[0]
    assert s("a.py", 1) == "pass" and s("a.py", 2) == "fail" and s("a.py", 3) == "fail" and s("a.py", 4) == "pass"
    assert s("a.py", 5) == "fail" and s("tests/t.py", 1) == "unverified" and s("a.py", 99) == "fail" and s("../x", 1) == "fail"
    assert "NOT verified" in depverify.secret_plausible({"file": "a.py", "line": 1}, tmp_path)[1]


def test_s3_public_and_external_plugin(tmp_path):
    facts = {"s3_buckets": {"open": {"block_public_access": {}, "acl_public": True},
                            "locked": {"block_public_access": {k: True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}},
                            "private": {"block_public_access": {}, "policy": {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::1:root"}, "Action": "s3:*"}]}}}}
    v = lambda b: depverify.s3_public({"bucket": b}, facts)[0]
    assert v("open") == "pass" and v("locked") == "fail" and v("private") == "fail" and v("nope") == "unverified"
    plug = tmp_path / "p.py"
    plug.write_text("import json,sys\nd=json.load(sys.stdin)\nprint(json.dumps({'status':'pass' if d['assumption'].get('ok') else 'fail','reason':'plugin says'}))\n")
    sc = Scope.from_dict({"external_verifiers": {"mine": f"python3 {plug}"}})
    assert run_external({"verifier": "mine", "ok": True}, sc, tmp_path) == ("pass", "plugin says")
    assert run_external({"verifier": "mine", "ok": False}, sc, tmp_path)[0] == "fail"
    assert run_external({"verifier": "ghost"}, sc, tmp_path)[0] == "unverified"
    bad = tmp_path / "bad.py"
    bad.write_text("print('not json')")
    assert run_external({"verifier": "b"}, Scope.from_dict({"external_verifiers": {"b": f"python3 {bad}"}}), tmp_path)[0] == "unverified"


# ---- new proof classes ----------------------------------------------------------------------------------
def test_new_proof_rules():
    assert validate({"type": "file_read", "status": 200, "marker": "root:x:0:0", "payload": "../../etc/passwd", "response_body": "root:x:0:0:..."})[0]
    assert not validate({"type": "file_read", "status": 200, "marker": "etc/passwd", "payload": "../../etc/passwd", "response_body": "etc/passwd"})[0]
    assert validate({"type": "redirect_observed", "status": 302, "location": "https://evil.test/x", "attacker_host": "evil.test"})[0]
    assert not validate({"type": "redirect_observed", "status": 302, "location": "https://evil.test.good.com/", "attacker_host": "evil.test"})[0]
    cors = lambda h: validate({"type": "cors_misconfig", "request_origin": "https://evil.test", "response_headers": h})[0]
    assert cors({"Access-Control-Allow-Origin": "https://evil.test", "Access-Control-Allow-Credentials": "true"})
    assert not cors({"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})   # spec forbids it: unusable
    assert not cors({"Access-Control-Allow-Origin": "https://evil.test"})                                # no credentials
    assert validate({"type": "token_accepted", "status": 200, "marker": "ADMIN", "response_body": "ADMIN", "control_status": 401, "forged": True})[0]
    assert not validate({"type": "token_accepted", "status": 200, "marker": "ADMIN", "response_body": "ADMIN", "control_status": 200, "forged": True})[0]
    assert validate({"type": "privilege_changed", "sent_field": "role", "before": "user", "after": "admin"})[0]
    assert not validate({"type": "privilege_changed", "before": "user", "after": "admin"})[0]
    assert validate({"type": "no_throttle", "statuses": [401] * 25})[0] and not validate({"type": "no_throttle", "statuses": [401] * 10 + [429] * 15})[0]
    assert validate({"type": "cross_origin_state_change", "no_token": True, "cross_origin": True, "state_changed": True})[0]


# ---- new probe kinds (local server) --------------------------------------------------------------------
@pytest.fixture
def web():
    state = {"n": 0, "redeemed": False}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            state["n"] += 1
            code, body, hdr = 200, b"ok", {}
            if self.path == "/cors":
                hdr = {"Access-Control-Allow-Origin": self.headers.get("Origin", ""), "Access-Control-Allow-Credentials": "true"}
            elif self.path == "/login":
                code = 401
            elif self.path == "/login2":
                code = 429 if state["n"] > 5 else 401
            elif self.path == "/redeem":
                code = 200 if True else 409   # reusable coupon (the logic flaw)
            self.send_response(code)
            for k, v in hdr.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_POST = do_GET

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", state
    srv.shutdown()


def test_header_repeat_and_sequence_probes(web):
    url, state = web
    cors = {"kind": "http_probe", "url": url + "/cors", "headers": {"Origin": "https://evil.test"},
            "expect_headers": {"Access-Control-Allow-Origin": "^https://evil.test$", "Access-Control-Allow-Credentials": "true"}}
    assert run_probe(cors, SC)[0] == "pass"
    assert run_probe({**cors, "expect_absent_headers": ["Access-Control-Allow-Credentials"]}, SC)[0] == "fail"
    assert run_probe({"kind": "repeat_probe", "url": url + "/login", "n": 25, "expect_status": 401}, SC)[0] == "pass"     # no lockout
    state["n"] = 0
    assert run_probe({"kind": "repeat_probe", "url": url + "/login2", "n": 25}, SC)[0] == "fail"                          # throttled
    seq = {"kind": "sequence_probe", "steps": [{"url": url + "/redeem", "method": "POST", "expect_status": 200},
                                              {"url": url + "/redeem", "method": "POST", "expect_status": 200}]}
    assert run_probe(seq, SC)[0] == "pass"
    seq["steps"][1]["expect_status"] = 409
    assert run_probe(seq, SC)[0] == "fail"
    assert run_probe({"kind": "sequence_probe", "steps": [{"url": "http://example.org/"}] * 2}, SC)[0] == "unverified"
    assert run_probe({"kind": "sequence_probe", "steps": [{"url": url}]}, SC)[0] == "fail"


def test_probe_budget_is_enforced(web):
    url, _ = web
    f = Finding.from_dict({"id": "b", "title": "t", "impact": "rce", "vuln_class": "rate-limit",
                           "probes": [{"kind": "repeat_probe", "url": url + "/login", "n": 30}]})
    env = Env(SC, active=True, probe_budget=[10])
    v = run_court([f], SC, env=env)[0]
    assert [c for c in v.checks if c.name == "proof"][0].status == "unverified" and "budget" in v.checks[2].reason


# ---- importers ------------------------------------------------------------------------------------------
def test_importers():
    semgrep = json.dumps({"results": [{"check_id": "python.django.security.injection.sql.sql-injection", "path": "app/views.py",
                                       "start": {"line": 12}, "extra": {"message": "SQLi", "severity": "ERROR", "lines": "  cur.execute(q)  ",
                                                                         "metadata": {"cwe": ["CWE-89: SQL Injection"]}}}]})
    kind, f = importers.load(semgrep)
    assert kind == "semgrep" and f[0].vuln_class == "sqli" and f[0].root_cause == {"file": "app/views.py", "line": 12, "quote": "cur.execute(q)"}
    trivy = json.dumps({"Results": [{"Target": "requirements.txt", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "PkgName": "requests", "InstalledVersion": "2.19.0", "FixedVersion": "2.20.0, 2.21", "Severity": "HIGH", "Title": "x"}]}]})
    kind, f = importers.load(trivy)
    assert kind == "trivy" and f[0].assumptions == [{"kind": "dependency_vuln", "package": "requests", "fixed": "2.20.0"}]
    kind, f = importers.load(json.dumps([{"RuleID": "aws-access-token", "File": "a.py", "StartLine": 3, "Secret": "AKIAQWERTYUIOPASDFGH", "Description": "AWS"}]))
    assert kind == "gitleaks" and "AKIA" not in json.dumps([x.__dict__ for x in f]) and f[0].vuln_class == "secrets"
    kind, f = importers.load('{"template-id":"cors-misconfig","info":{"name":"CORS","severity":"medium","tags":"cors,misconfig"},"matched-at":"http://h/x"}\n'
                             '{"template-id":"x","info":{"name":"X"},"host":"h"}\n')
    assert kind == "nuclei" and f[0].vuln_class == "cors" and f[0].target == "http://h/x"
    sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "T", "rules": [{"id": "R1", "properties": {"tags": ["external/cwe/cwe-78"]}}]}},
                                           "results": [{"ruleId": "R1", "message": {"text": "m"}, "level": "error", "locations": [{"physicalLocation": {
                                               "artifactLocation": {"uri": "file:///a.py"}, "region": {"startLine": 2, "snippet": {"text": "os.system(x)"}}}}]}]}]}
    kind, f = importers.load(json.dumps(sarif))
    assert kind == "sarif" and f[0].vuln_class == "cmdi" and f[0].id == "T-R1-0.0" and f[0].root_cause["file"] == "/a.py"
    for bad in ("", "not json", "42", '{"hello": 1}'):
        with pytest.raises(ValueError):
            importers.load(bad)
    kind, f = importers.load(json.dumps({"findings": [{"id": "x", "title": "t"}]}))
    assert kind == "docket" and f[0].id == "x"


def test_impact_map_applies_only_when_unspecified():
    a = Finding.from_dict({"id": "a", "title": "t", "vuln_class": "sqli"})
    b = Finding.from_dict({"id": "b", "title": "t", "vuln_class": "sqli", "impact": "rce"})
    from docket.court import apply_impact_map
    apply_impact_map([a, b], SC)
    assert (a.impact, b.impact) == ("data-exfiltration", "rce")


# ---- suppressions / audit / record+replay / AI escalation ------------------------------------------------
def test_suppressions(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps([{"title_contains": "legacy", "reason": "accepted risk, ticket 12", "author": "babar", "expires": "2999-01-01"},
                             {"id": "old", "reason": "r", "author": "a", "expires": "2001-01-01"}]))
    rules = suppress.load(p)
    fs = [Finding.from_dict({"id": "x", "title": "Legacy endpoint"}), Finding.from_dict({"id": "old", "title": "t"})]
    out = run_court(fs, SC, suppressions=rules)
    assert out[0].outcome == "suppressed" and "ticket 12" in out[0].note and out[1].outcome != "suppressed"   # expired rule ignored
    assert run_court.stale and run_court.stale[0]["id"] == "old"
    for bad in ([{"reason": "r", "author": "a"}], [{"id": "x", "reason": "r"}], [{"id": "x", "reason": "r", "author": "a", "wat": 1}],
                [{"id": "x", "reason": "r", "author": "a", "expires": "tomorrow"}], {"x": 1}):
        p.write_text(json.dumps(bad))
        with pytest.raises(ValueError):
            suppress.load(p)


def test_audit_chain_detects_tampering(tmp_path):
    f = [Finding.from_dict({"id": str(i), "title": "t"}) for i in range(3)]
    log = tmp_path / "a.jsonl"
    audit.append(log, run_court(f, SC), "abc")
    audit.append(log, run_court(f[:1], SC), "abc")        # chains across runs
    ok, n, err = audit.verify(log)
    assert ok and n == 4
    lines = log.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["outcome"] = "survived"
    lines[1] = json.dumps(rec)
    log.write_text("\n".join(lines) + "\n")
    ok, n, err = audit.verify(log)
    assert not ok and "record 2" in err
    log.write_text("\n".join(lines[:1] + lines[2:]) + "\n")   # deleting a record also breaks the chain
    assert not audit.verify(log)[0]


class FakeAI:
    model = "reviewer-1"

    def __init__(self, reply):
        self.reply, self.calls = reply, 0

    def ask(self, system, user, max_tokens=500):
        self.calls += 1
        return json.dumps(self.reply)


def needs_human_finding():
    return Finding.from_dict({"id": "n", "title": "t", "impact": "rce", "found_by": "finder",
                              "assumptions": [{"kind": "metadata_reachable", "text": "unknown kind"}],
                              "root_cause": {"fact_path": "x"}, "repro_steps": ["a", "b"]})


def test_ai_escalation_can_reject_but_never_approve(monkeypatch):
    facts = {"x": 1}
    sure_no = {"likely_real": False, "confidence": 0.95, "reason": "sanitized", "what_would_settle_it": "read line 9"}
    sure_yes = {"likely_real": True, "confidence": 0.99, "reason": "obviously", "what_would_settle_it": "n/a"}
    # AI says "real" with 99% confidence: finding must STILL need a human
    v = run_court([needs_human_finding()], SC, None, facts, env=Env(SC, facts=facts, ai_client=FakeAI(sure_yes)))[0]
    assert v.outcome == "needs-human" and "never approves" in v.checks[-1].reason
    # AI says "false" but scope does not let it close findings: stays with a human, with the opinion attached
    v = run_court([needs_human_finding()], SC, None, facts, env=Env(SC, facts=facts, ai_client=FakeAI(sure_no)))[0]
    assert v.outcome == "needs-human" and "suspects a false positive" in v.checks[-1].reason
    # opt-in: confident AI rejection closes it, with the reason recorded
    sc = Scope.from_dict({**SC.__dict__, "ai_can_reject": True})
    v = run_court([needs_human_finding()], sc, None, facts, env=Env(sc, facts=facts, ai_client=FakeAI(sure_no)))[0]
    assert v.outcome == "killed" and v.killed_by == "ai-review"
    # low confidence never closes anything
    weak = dict(sure_no, confidence=0.5)
    v = run_court([needs_human_finding()], sc, None, facts, env=Env(sc, facts=facts, ai_client=FakeAI(weak)))[0]
    assert v.outcome == "needs-human"
    # AI is only consulted for findings deterministic checks could not settle
    ai = FakeAI(sure_no)
    run_court([Finding.from_dict({"id": "k", "title": "t", "impact": "bad"})], SC, env=Env(SC, ai_client=ai))
    assert ai.calls == 0
    # reviewer identical to the finder is ignored
    same = FakeAI(sure_no)
    same.model = "finder"
    v = run_court([needs_human_finding()], sc, None, facts, env=Env(sc, facts=facts, ai_client=same))[0]
    assert v.outcome == "needs-human" and "same model" in v.checks[-1].reason


def test_record_and_replay_are_deterministic(tmp_path):
    f = needs_human_finding()
    f.probes = []
    judge = lambda fi, p: {"reproduced": True, "model": "j1", "reason": "r"}
    env = Env(SC, judges=[judge], facts={"x": 1}, ai_client=FakeAI({"likely_real": "unsure", "confidence": 0.1, "reason": "?", "what_would_settle_it": "x"}))
    first = run_court([f], SC, env=env)[0].to_dict()
    rec = Record(json.loads(json.dumps(env.record.data)))
    boom = lambda *a: (_ for _ in ()).throw(AssertionError("replay must not call judges or AI"))
    renv = Env(SC, judges=[boom], facts={"x": 1}, ai_client=None, replay=rec)
    second = run_court([needs_human_finding()], SC, env=renv)[0].to_dict()
    assert first["outcome"] == second["outcome"] and [c["status"] for c in first["checks"]] == [c["status"] for c in second["checks"]]


def test_hints_tell_users_what_to_do():
    v = run_court([Finding.from_dict({"id": "h", "title": "t", "impact": "rce", "repro_steps": ["a", "b"], "root_cause": {"file": "a.py", "line": 1, "quote": "x"}, "assumptions": [{"kind": "mystery"}]})],
                  Scope.from_dict({"accepted_impacts": ["rce"]}))[0]
    text = " ".join(v.next_steps)
    assert v.outcome == "needs-human" and "--judge" in text and "supported kind" in text


def test_court_api_exposes_scope_for_impact_first_planning():
    c = Court({"accepted_impacts": ["rce"], "attacker_states": ["unauthenticated"]})
    s = c.scope_summary()
    assert s["accepted_impacts"] == ["rce"] and s["attacker_states"] == ["unauthenticated"]


def test_secret_literals_and_env_assignment(tmp_path):
    (tmp_path / "a.py").write_text('os.environ["JWT_SECRET"] = "jwt_signing_key_very_secret"\nADMIN_PASSWORD = "Sup3r-Admin-9"\n'
                                   'password = os.environ["PW"]\napp.secret_key = "your-secret-key-here"\nuser = create(password="pw")\n')
    (tmp_path / "tests.py").write_text('x = create(password="hunter2hunter2")\n')
    s = lambda f, ln: depverify.secret_plausible({"file": f, "line": ln}, tmp_path)[0]
    assert s("a.py", 1) == "pass" and s("a.py", 2) == "pass"      # assigning INTO the environment is still a hardcoded value
    assert s("a.py", 3) == "fail" and s("a.py", 4) == "fail" and s("a.py", 5) == "fail"
    assert s("tests.py", 1) == "unverified"


def test_bind_all_interfaces_is_not_a_secret():
    assert importers.guess_class("hardcoded_bind_all_interfaces", "Possible binding to all interfaces.") == ""
    assert importers.guess_class("hardcoded_password_string", "Possible hardcoded password") == "secrets"


def test_findings_in_test_code_are_not_product_vulns(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_a.py").write_text("def test_x():\n    assert os.system('ls ' + input())\n")
    f = Finding.from_dict({"id": "t", "title": "t", "impact": "rce", "vuln_class": "cmdi", "repro_steps": ["a", "b"],
                           "root_cause": {"file": "tests/test_a.py", "line": 2, "quote": "os.system"}})
    out = run_court([f], SC, env=Env(SC, target_dir=tmp_path, auto_verify=True))[0]
    assert out.outcome == "killed" and "test or fixture code" in out.checks[0].reason


def test_secret_assigned_to_config_keys(tmp_path):
    (tmp_path / "a.py").write_text("app.config['SECRET_KEY_HMAC_2'] = 'am0r3C0mpl3xK3y'\napp.secret_key = 'F12Zr47j\\\\3yX R~X@H!jmM]Lwf/,?KT'\n"
                                   "auth_token = \"\"\nvuln_app.app.config['SECRET_KEY'] = 'random'\n")
    s = lambda ln: depverify.secret_plausible({"file": "a.py", "line": ln}, tmp_path)[0]
    assert (s(1), s(2), s(3), s(4)) == ("pass", "pass", "fail", "pass")


def test_wrong_scanner_class_does_not_kill_a_real_bug(tmp_path):
    src(tmp_path, "@app.route('/c')\ndef calc():\n    expr = request.args['e']\n    out = eval(expr)\n    return out\n")
    f = Finding.from_dict({"id": "e", "title": "t", "impact": "rce", "vuln_class": "cmdi", "repro_steps": ["a", "b"],
                           "root_cause": {"file": "app.py", "line": 4, "quote": "out = eval(expr)"}})
    out = run_court([f], SC, env=Env(SC, target_dir=tmp_path, auto_verify=True))[0]
    assert out.outcome == "survived" and "eval" in out.checks[0].reason          # judged by the sink actually on the line


def test_dead_code_claims_are_only_made_for_plain_functions(tmp_path):
    src(tmp_path, "class Base:\n    def dispatch_request(self):\n        return 1\n    def __init__(self):\n        pass\n\n"
        "def helper():\n    return 1\n\ndef orphan():\n    return 1\n\ndef main():\n    return helper()\n\nif __name__ == '__main__':\n    main()\n")
    r = lambda fn: codeverify.entrypoint_reaches({"function": fn}, tmp_path)
    assert r("dispatch_request")[0] == "unverified" and r("__init__")[0] == "unverified"   # frameworks call these dynamically
    assert r("helper")[0] == "pass" and r("main")[0] == "pass"                               # reached from script code
    assert r("orphan")[0] == "fail"


def test_class_body_references_count_as_use(tmp_path):
    src(tmp_path, "def _lazy(s):\n    return s\n\nclass Iface:\n    digest = staticmethod(_lazy)\n\ndef really_dead():\n    return 1\n")
    assert codeverify.entrypoint_reaches({"function": "_lazy"}, tmp_path)[0] == "pass"
    assert codeverify.entrypoint_reaches({"function": "really_dead"}, tmp_path)[0] == "fail"
