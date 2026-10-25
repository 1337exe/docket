"""Self-test and testing kit, so a fresh install can be checked before anyone trusts it."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import __version__
from .canary import Canary
from .court import run_court, summarize
from .demo import write_demo
from .judge import CommandJudge, FileJudge
from .lab import run_lab, write_lab_files
from .models import Finding
from .report import render_html
from .scope import Scope

EXAMPLES = Path(__file__).with_name("examples")
EXPECTED_DEMO = {"total": 30, "survived": 7, "needs_human": 1, "killed": 20, "duplicates": 2, "suppressed": 0,
                 "killed_by": {"reachability": 13, "impact": 3, "proof": 0, "judge": 2, "reconstruct": 2, "ai-review": 0}}


def _lab(work):
    verdicts, bad = run_lab(verbose=False)
    (work / "lab-report.html").write_text(render_html(verdicts, "Docket: lab run"), encoding="utf-8")
    return bad == 0, f"{len(verdicts) - bad}/{len(verdicts)} lab verdicts match ground truth"


def _demo(work):
    p = write_demo(work / "demo")
    findings = [Finding.from_dict(d) for d in json.loads(p["findings"].read_text())]
    verdicts = run_court(findings, Scope.load(p["scope"]), [FileJudge(p["judge"])], json.loads(p["facts"].read_text()), p["target"])
    (work / "demo-report.html").write_text(render_html(verdicts), encoding="utf-8")
    got = summarize(verdicts)
    return got == EXPECTED_DEMO, f"30-finding demo -> {got['survived']} survived, {got['needs_human']} need a human, " \
                                 f"{got['killed']} killed, {got['duplicates']} duplicates"


def _canary(work):
    c = Canary(work / "canary.jsonl").start()
    try:
        n = c.new_nonce()
        urllib.request.urlopen(c.url_for(n), timeout=3).read()
        ok = bool(c.hits(n)) and not c.hits("0123456789abcdef")
    finally:
        c.stop()
    return ok, "canary records a real callback and ignores unknown nonces"


def _mcp(work):
    (work / "mcp-scope.json").write_text(json.dumps({"accepted_impacts": ["rce"], "require_judge": False}))
    msg = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "court_try_finding", "arguments": {"finding": {"id": "z", "title": "t", "impact": "rce"}}}}) + "\n"
    out = subprocess.run([sys.executable, "-m", "docket.cli", "mcp", "--scope", str(work / "mcp-scope.json")],
                         input=msg, capture_output=True, text=True, timeout=30).stdout.strip()
    return bool(out) and json.loads(json.loads(out)["result"]["content"][0]["text"])["id"] == "z", "MCP server answers over stdio"


def _judge_cmd(work):
    j = CommandJudge(f"{sys.executable} {EXAMPLES / 'judge_stub.py'}")
    f = Finding.from_dict({"id": "j", "title": "t", "root_cause": {"fact_path": "x"}})
    return j(f, {"root_cause": f.root_cause})["model"] == "stub-judge", "external judge command contract works"


def _scope_guard(work):
    hits = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            hits.append(self.path)
            self.send_response(200)
            self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        from .active import run_probe
        status, _ = run_probe({"kind": "http_probe", "url": f"http://127.0.0.1:{srv.server_address[1]}/x"}, Scope.from_dict({}))
    finally:
        srv.shutdown()
    return status == "unverified" and not hits, "a host outside scope.active_hosts is never contacted"


def _scanner_and_pack(work):
    """Scanner output -> triage -> proof pack -> offline replay: the path real users take."""
    from .cli import main
    src = work / "scan-src"
    src.mkdir(exist_ok=True)
    (src / "app.py").write_text("import os\n@app.route('/a')\ndef a():\n    h = request.args['h']\n    return os.system('ping ' + h)\n\n"
                               "def never_called():\n    return os.system('ping ' + request.args['h'])\n")
    res = [{"check_id": "x.cmdi", "path": "app.py", "start": {"line": ln}, "extra": {"message": "command injection", "severity": "ERROR",
           "lines": q, "metadata": {"cwe": ["CWE-78"]}}} for ln, q in ((5, "return os.system('ping ' + h)"), (8, "return os.system('ping ' + request.args['h'])"))]
    (work / "scan.json").write_text(json.dumps({"results": res}))
    (work / "scan-scope.json").write_text(json.dumps({"accepted_impacts": ["rce"], "require_judge": False, "impact_map": {"cmdi": "rce"}}))
    import contextlib
    import io
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        main(["try", str(work / "scan.json"), "--scope", str(work / "scan-scope.json"), "--target", str(src),
              "--json", str(work / "scan-report.json"), "--out", str(work / "scan-report.html"), "--pack", str(work / "scan-pack.zip")])
        replay = main(["replay", str(work / "scan-pack.zip")])
    out = [v["outcome"] for v in json.loads((work / "scan-report.json").read_text())["verdicts"]]
    return out == ["survived", "killed"] and replay == 0, "scanner output triaged (1 real, 1 dead code); proof pack replays offline"


STEPS = [("lab ground truth", _lab), ("demo case", _demo), ("canary listener", _canary), ("MCP server", _mcp),
         ("judge command", _judge_cmd), ("scope guard", _scope_guard), ("scanner + proof pack", _scanner_and_pack)]


def selftest(out_dir="") -> int:
    work = Path(out_dir or tempfile.mkdtemp(prefix="docket-selftest-"))
    work.mkdir(parents=True, exist_ok=True)
    print(f"docket {__version__} self-test (python {sys.version.split()[0]}); everything stays on localhost\n")
    bad = 0
    for name, fn in STEPS:
        try:
            ok, detail = fn(work)
        except Exception as e:  # noqa: BLE001
            ok, detail = False, f"crashed: {type(e).__name__}: {e}"
        bad += not ok
        print(f"  [{'PASS' if ok else 'FAIL'}] {name:18} {detail}")
    print(f"\nreports: {work}/lab-report.html  {work}/demo-report.html")
    print("RESULT: install is healthy" if not bad else f"RESULT: {bad} check(s) failed; please open an issue with this output")
    return 1 if bad else 0


KIT_MD = """# Docket testing kit

Everything here runs on your machine; nothing is sent anywhere unless YOU add an AI provider. Do not point it at
systems you do not own or have permission to test.

## 1. Check the install (1 minute)
    docket doctor
    docket selftest --out-dir ./out
Open `out/lab-report.html` and `out/demo-report.html` in a browser.

## 2. Try the sample case (30 candidates: app code, dependencies, secrets, cloud config)
    docket try case/findings.json --scope case/scope.json --facts case/facts.json \\
        --target case/target --judge-file case/judge.json --out out/case.html --json out/case.json
30 findings in, 7 survivors out. Open a killed one and read why it died. Open the one marked "needs a human"
and read the "What to do next" box.

## 3. Attack the court with a live target (the lab: 28 claims, 14 vulnerability classes, ground truth known)
Terminal A:   docket lab --serve --port 8099 --out-dir lab
Terminal B:   docket try lab/findings.json --scope lab/scope.json --target <path printed by terminal A> --active --out out/lab.html
`lab/expected.json` holds the ground truth: compare it with `out/lab.json` (add `--json out/lab.json`).

## 4. Use it on YOUR scanner output (this is the real use)
    docket init . --profile ci                      # writes scope.json + docket.json
    bandit -r src -f json -o scan.json              # or: semgrep --sarif, nuclei -jsonl, trivy -f json, gitleaks -f json
    docket try scan.json --target src --out report.html --pack proof-pack.zip
    docket replay proof-pack.zip                    # anyone can re-check your verdicts offline

## 5. Add an AI (optional)
    export ANTHROPIC_API_KEY=...      # or OPENAI_API_KEY / GEMINI_API_KEY; ollama needs no key
    docket providers anthropic:<model>              # connection test
    docket try scan.json --target src --judge anthropic:<model> --escalate openai:<model> --ai-cache .docket-cache --ai-budget 50
The AI can argue AGAINST a finding or ask for more evidence. It can never approve one.

## 6. Try to break it (bug-hunting ideas)
- Edit `case/scope.json`: change `judge_quorum`, add a `forbidden_states` keyword, remove an accepted impact.
- Edit `case/findings.json`: give a finding a wrong line number, 20 repro steps, a made-up nonce, or evidence of type `status_200`.
- Add a finding whose evidence is real but whose class is wrong (xss with `timing` evidence).
- Feed hostile strings (huge text, unicode, `../../etc/passwd` paths); the court should answer `unverified`, never crash or pass.
- Edit a proof pack's `scope.json` and run `docket replay`: it must report TAMPERED.
Found something confusing or wrong? Open an issue with the command, the input and the output.

## 7. Plug in your own tool or agent
- Judges: `examples/judge_stub.py` shows the contract; `--judge provider:model` does it for you.
- Python agents: `examples/swarm_hook.py`. MCP clients: `examples/mcp.json`. CI: `examples/github-action.yml`.
"""


def write_kit(dest="docket-kit") -> int:
    d = Path(dest)
    d.mkdir(parents=True, exist_ok=True)
    write_demo(d / "case")
    write_lab_files(d / "lab")
    shutil.copytree(EXAMPLES, d / "examples", dirs_exist_ok=True)
    (d / "KIT.md").write_text(KIT_MD, encoding="utf-8")
    print(f"testing kit written to {d}/\n  start here: {d}/KIT.md\n  quick check: docket selftest --out-dir {d}/out")
    return 0
