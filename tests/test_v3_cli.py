"""End-to-end CLI tests for v0.3: config, scanner input, AI via a vendor-shaped mock, proof packs, audit log."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from docket.cli import main

SCOPE = {"accepted_impacts": ["rce", "data-exfiltration"], "attacker_states": ["unauthenticated"], "require_judge": False,
         "impact_map": {"cmdi": "rce", "sqli": "data-exfiltration"}}
APP = ("from flask import request\nimport os, shlex\n\n@app.route('/a')\ndef a():\n    h = request.args['h']\n    return os.system('ping ' + h)\n\n"
       "@app.route('/b')\ndef b():\n    h = request.args['h']\n    return os.system('ping ' + shlex.quote(h))\n\n"
       "def dead():\n    return os.system('ping ' + request.args['h'])\n")


def semgrep(lines):
    return json.dumps({"results": [{"check_id": "x.command-injection", "path": "app.py", "start": {"line": ln},
                                    "extra": {"message": "cmd injection", "severity": "ERROR", "lines": q,
                                              "metadata": {"cwe": ["CWE-78: OS Command Injection"]}}} for ln, q in lines]})


@pytest.fixture
def proj(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(APP)
    (tmp_path / "scope.json").write_text(json.dumps(SCOPE))
    (tmp_path / "scan.json").write_text(semgrep([(7, "os.system('ping ' + h)"), (12, "os.system('ping ' + shlex.quote(h))"),
                                                 (15, "os.system('ping ' + request.args['h'])")]))
    return tmp_path


def run(proj, *extra):
    return main(["try", str(proj / "scan.json"), "--scope", str(proj / "scope.json"), "--target", str(proj / "src"),
                 "--json", str(proj / "r.json"), "--out", str(proj / "r.html"), *extra])


def verdicts(proj):
    return {v["id"]: v for v in json.loads((proj / "r.json").read_text())["verdicts"]}


def test_scanner_output_is_triaged_with_autoverify(proj):
    assert run(proj) == 0
    out = list(verdicts(proj).values())
    assert [v["outcome"] for v in out] == ["survived", "killed", "killed"]            # real, sanitized, dead code
    assert out[1]["killed_by"] == "reachability" and "sanitizer" in str(out[1]["checks"][0]["reason"])
    assert "dead code" in out[2]["checks"][0]["reason"]


def test_no_auto_verify_leaves_scanner_noise_for_humans(proj):
    assert run(proj, "--no-auto-verify", "--fail-on", "needs-human") == 2
    assert {v["outcome"] for v in verdicts(proj).values()} == {"needs-human"}


def test_config_file_supplies_defaults_and_flags_win(proj):
    (proj / "docket.json").write_text(json.dumps({"scope": "scope.json", "target": "src", "fail_on": "survived", "json": "x"}))
    with pytest.raises(SystemExit):                                  # unknown/mistyped key is an error, not silently ignored
        main(["try", str(proj / "scan.json"), "--config", str(proj / "docket.json")])
    (proj / "docket.json").write_text(json.dumps({"scope": "scope.json", "target": "src", "fail_on": "survived", "json_out": "r.json", "out": "r.html"}))
    assert main(["try", str(proj / "scan.json"), "--config", str(proj / "docket.json")]) == 2     # one survivor -> exit 2
    assert main(["try", str(proj / "scan.json"), "--config", str(proj / "docket.json"), "--fail-on", "never"]) == 0


def test_suppression_and_audit_log_and_annotated_sarif(proj, capsys):
    sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "T"}}, "results": [
        {"ruleId": "R", "message": {"text": "cmd injection"}, "level": "error", "properties": {"tags": ["cwe-78"]},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 12, "snippet": {"text": "os.system('ping ' + shlex.quote(h))"}}}}]}]}]}
    (proj / "s.sarif").write_text(json.dumps(sarif))
    (proj / "sup.json").write_text(json.dumps([{"title_contains": "never-matches", "reason": "r", "author": "a"}]))
    log = proj / "audit.jsonl"
    args = ["try", str(proj / "s.sarif"), "--scope", str(proj / "scope.json"), "--target", str(proj / "src"), "--default-impact", "rce",
            "--out", str(proj / "o.html"), "--suppressions", str(proj / "sup.json"), "--audit-log", str(log),
            "--annotate-sarif", str(proj / "annotated.sarif")]
    assert main(args) == 0
    ann = json.loads((proj / "annotated.sarif").read_text())
    assert ann["runs"][0]["results"][0]["suppressions"][0]["justification"].startswith("docket: killed")
    assert main(["audit", str(log)]) == 0 and "chain intact" in capsys.readouterr().out
    log.write_text(log.read_text().replace('"killed"', '"survived"'))
    assert main(["audit", str(log)]) == 1


def test_proof_pack_replays_offline_and_detects_tampering(proj, tmp_path):
    pack = tmp_path / "p.zip"
    assert run(proj, "--pack", str(pack)) == 0
    assert main(["replay", str(pack)]) == 0
    import zipfile
    bad = tmp_path / "bad.zip"
    with zipfile.ZipFile(pack) as zi, zipfile.ZipFile(bad, "w") as zo:
        for i in zi.infolist():
            data = zi.read(i.filename)
            if i.filename == "scope.json":
                data = data.replace(b"rce", b"xxx")
            zo.writestr(i, data)
    assert main(["replay", str(bad)]) == 3


def test_replay_rejects_zip_slip(tmp_path):
    import zipfile
    z = tmp_path / "evil.zip"
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("../../escape.txt", "x")
    with pytest.raises(SystemExit):
        main(["replay", str(z)])
    assert not (tmp_path.parent / "escape.txt").exists()


def test_doctor_and_init_profiles(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["init", str(tmp_path), "--profile", "ci"]) == 0
    cfg = json.loads((tmp_path / "docket.json").read_text())
    assert cfg["fail_on"] == "survived" and cfg["scope"] == "scope.json"
    assert main(["doctor"]) == 0
    assert "never printed" in capsys.readouterr().out


# ---- AI through the CLI against a vendor-shaped mock ------------------------------------------------------
@pytest.fixture
def anthropic_mock():
    state = {"reqs": 0, "reply": {}}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state["reqs"] += 1
            assert self.path == "/v1/messages" and self.headers["x-api-key"] == "test-key"
            assert "AKIAQWERTYUIOPASDFGH" not in json.dumps(body)       # secrets are masked before leaving the machine
            data = json.dumps({"content": [{"type": "text", "text": json.dumps(state["reply"])}]}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    state["url"] = f"http://127.0.0.1:{srv.server_address[1]}"
    yield state
    srv.shutdown()


def test_ai_judge_and_escalation_from_cli(proj, anthropic_mock, monkeypatch, capsys):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", anthropic_mock["url"])
    anthropic_mock["reply"] = {"reproduced": False, "reason": "no"}
    (proj / "scope.json").write_text(json.dumps({**SCOPE, "require_judge": True}))
    assert run(proj, "--judge", "anthropic:claude-test", "--ai-cache", str(proj / "cache"), "--ai-budget", "10") == 0
    v = verdicts(proj)
    assert [x["outcome"] for x in v.values()][0] == "killed" and v[list(v)[0]]["killed_by"] == "judge"
    n = anthropic_mock["reqs"]
    assert n >= 1
    run(proj, "--judge", "anthropic:claude-test", "--ai-cache", str(proj / "cache"), "--ai-budget", "10")
    assert anthropic_mock["reqs"] == n                                  # second run is served from the cache
    assert main(["providers", f"anthropic:claude-test"]) == 0 and "OK" in capsys.readouterr().out


def test_extract_free_text_to_findings(proj, anthropic_mock, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", anthropic_mock["url"])
    anthropic_mock["reply"] = {"findings": [{"title": "SQLi in /search", "vuln_class": "sqli", "target": "app.py",
                                             "root_cause": {"file": "app.py", "line": 3, "quote": "execute"}, "repro_steps": ["a", "b"]}, {"nope": 1}]}
    (proj / "report.txt").write_text("Pentest report. key AKIAQWERTYUIOPASDFGH was found. SQLi in /search.")
    out = proj / "f.json"
    assert main(["extract", str(proj / "report.txt"), "--model", "anthropic:claude-test", "--out", str(out)]) == 0
    items = json.loads(out.read_text())
    assert len(items) == 1 and items[0]["found_by"].startswith("extracted:") and items[0]["impact"] == "unspecified"


def test_judge_anthropic_example_against_mock(anthropic_mock, monkeypatch):
    """The stdlib example judge, run as a real subprocess against the vendor-shaped mock."""
    import subprocess
    import sys
    from pathlib import Path
    anthropic_mock["reply"] = {"reproduced": True, "reason": "looks real"}
    script = Path(__file__).parent.parent / "src" / "docket" / "examples" / "judge_anthropic.py"
    env = {"PATH": "/usr/bin:/bin", "ANTHROPIC_API_KEY": "test-key", "ANTHROPIC_BASE_URL": anthropic_mock["url"], "JUDGE_MODEL": "claude-test"}
    out = subprocess.run([sys.executable, str(script)], input=json.dumps({"claim": "x"}), capture_output=True, text=True, env=env, timeout=30)
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout) == {"reproduced": True, "reason": "looks real", "model": "claude-test"}


def test_scanner_paths_are_normalised_to_target(proj):
    import os
    cwd = os.getcwd()
    os.chdir(proj)
    try:
        for cited in ("src/app.py", "./src/app.py", str(proj / "src" / "app.py"), "app.py"):
            (proj / "scan.json").write_text(semgrep([(7, "os.system('ping ' + h)")]).replace('"app.py"', json.dumps(cited)))
            assert main(["try", "scan.json", "--scope", "scope.json", "--target", "src", "--json", "r.json", "--out", "r.html"]) == 0
            assert json.loads((proj / "r.json").read_text())["verdicts"][0]["outcome"] == "survived", cited
    finally:
        os.chdir(cwd)


def test_replay_refuses_oversized_pack(tmp_path):
    import zipfile
    z = tmp_path / "big.zip"
    with zipfile.ZipFile(z, "w") as f:
        for i in range(6001):
            f.writestr(f"f{i}.txt", "x")
    with pytest.raises(SystemExit):
        main(["replay", str(z)])
