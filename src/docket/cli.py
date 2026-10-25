from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time
import zipfile
from dataclasses import asdict
from pathlib import Path

from . import __version__
from . import audit as audit_mod
from . import ledger as ledger_mod
from . import suppress as suppress_mod
from .canary import Canary
from .court import Court, Env, run_court, summarize
from .judge import CommandJudge, FileJudge
from .record import Record
from .scope import Scope

CONFIG_NAMES = ("docket.json", ".docket.json")
LISTS = ("judge", "judge_cmd", "judge_file")
PATHS = ("scope", "facts", "target", "suppressions", "audit_log", "ai_cache", "baseline", "ledger", "out", "json_out",
         "sarif_out", "markdown_out", "judge_file", "record", "pack")


# ---------------------------------------------------------------- options + config
def _common(p):
    p.add_argument("--config", help="docket.json with defaults for any option below (command-line flags win)")
    p.add_argument("--scope", help="scope contract (what counts as a real finding here)")
    p.add_argument("--facts", help="JSON with policies / roles / security_groups / flags used by verifiers")
    p.add_argument("--target", help="source directory that cited code is checked against")
    p.add_argument("--judge", action="append", default=[], metavar="PROVIDER:MODEL",
                   help="blind judge backed by an AI provider, e.g. anthropic:MODEL, openai:MODEL, gemini:MODEL, "
                        "ollama:MODEL, openai-compat:MODEL@http://host/v1 (repeat for a panel)")
    p.add_argument("--judge-cmd", action="append", default=[], help="your own command: blind payload on stdin, JSON verdict on stdout")
    p.add_argument("--judge-file", action="append", default=[], help="recorded judge verdicts (JSON: id -> verdict)")
    p.add_argument("--escalate", metavar="PROVIDER:MODEL", help="ask this AI about findings the checks could not settle. "
                   "It can argue against a finding; it can never approve one")
    p.add_argument("--ai-can-reject", action="store_true", help="let a confident (>=80%%) AI 'false positive' opinion close a finding")
    p.add_argument("--ai-cache", help="directory for cached AI answers (saves money, makes re-runs repeatable)")
    p.add_argument("--ai-budget", type=int, help="maximum number of AI calls in this run")
    p.add_argument("--no-redact", action="store_true", help="do not mask secrets before sending to an AI or writing reports")
    p.add_argument("--suppressions", help="audited suppressions file (each needs a reason and an author)")
    p.add_argument("--audit-log", help="append a hash-chained, tamper-evident record of every verdict here")
    p.add_argument("--auto-verify", dest="auto_verify", action="store_true", default=None,
                   help="add reachability + taint checks from the cited code automatically (default for scanner imports)")
    p.add_argument("--no-auto-verify", dest="auto_verify", action="store_false")
    p.add_argument("--active", action="store_true", help="allow live probes against scope.active_hosts (your own infra only)")
    p.add_argument("--max-probe-requests", type=int, help="hard cap on live HTTP requests per run (default 300)")
    p.add_argument("--probe-delay", type=float, help="seconds to wait between live probes")
    p.add_argument("--canary-log", help="canary listener log used to verify oob_callback evidence")
    p.add_argument("--canary-bind", help="host:port for the built-in canary used by ssrf_probe")
    p.add_argument("--canary-public-url", help="URL the target should call to reach the canary")


def _load_config(a):
    path = getattr(a, "config", None)
    if not path:
        for n in CONFIG_NAMES:
            if Path(n).is_file():
                path = n
                break
    if not path:
        return {}
    try:
        cfg = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ValueError(f"cannot read config {path}: {e}")
    if not isinstance(cfg, dict):
        raise ValueError("config must be a JSON object")
    known = {k for k in vars(a)}
    bad = [k for k in cfg if k.replace("-", "_") not in known and not k.startswith("_")]
    if bad:
        raise ValueError(f"config {path} has unknown keys: {', '.join(bad)}")
    base = Path(path).resolve().parent
    out = {}
    for k, v in cfg.items():
        k = k.replace("-", "_")
        if k in PATHS and isinstance(v, str) and not os.path.isabs(v):
            v = str(base / v)
        elif k in PATHS and isinstance(v, list):
            v = [str(base / x) if not os.path.isabs(x) else x for x in v]
        out[k] = v
    return out


def apply_config(a):
    for k, v in _load_config(a).items():
        cur = getattr(a, k, None)
        if cur in (None, [], False, "") and v is not None:
            setattr(a, k, v if k not in LISTS or isinstance(v, list) else [v])
    return a


def _make_client(spec, a, redact=True):
    from .providers import Client
    return Client(spec, a.ai_cache, a.ai_budget, redact=redact)


def _build(a):
    a = apply_config(a)
    if not a.scope:
        raise ValueError("--scope is required (or set it in docket.json). Run 'docket init' to create one")
    scope = Scope.load(a.scope)
    if a.ai_can_reject:
        scope.ai_can_reject = True
    facts = json.loads(Path(a.facts).read_text()) if a.facts else {}
    redact = not a.no_redact
    judges = [FileJudge(x) for x in a.judge_file] + [CommandJudge(x) for x in a.judge_cmd]
    if a.judge:
        from .providers import ProviderJudge
        judges += [ProviderJudge(_make_client(s, a, redact)) for s in a.judge]
    ai = _make_client(a.escalate, a, redact) if a.escalate else None
    canary = None
    if a.active:
        host, _, port = (a.canary_bind or "127.0.0.1:0").rpartition(":")
        log = a.canary_log or str(Path(tempfile.mkdtemp(prefix="docket-canary-")) / "canary.jsonl")
        canary = Canary(log, host or "127.0.0.1", int(port or 0), a.canary_public_url).start()
        a.canary_log = log
    return scope, facts, judges, ai, canary


def _baseline(path):
    if not path:
        return set()
    data = json.loads(Path(path).read_text())
    return {v["fingerprint"] for v in data.get("verdicts", []) if v.get("outcome") in ("killed", "survived")}


# ---------------------------------------------------------------- try
def _read_findings(a):
    from . import importers
    text = sys.stdin.read() if a.findings == "-" else Path(a.findings).read_text(encoding="utf-8")
    return importers.load(text, a.default_impact or "unspecified", a.format), text


def _annotate_sarif(src_text, verdicts):
    doc = json.loads(src_text)
    done = 0
    for v in verdicts:
        if v.outcome not in ("killed", "duplicate", "suppressed"):
            continue
        m = re.search(r"(\d+)\.(\d+)$", v.finding.id)
        if not m:
            continue
        try:
            res = doc["runs"][int(m[1])]["results"][int(m[2])]
        except (KeyError, IndexError, TypeError):
            continue
        why = v.note or (next((c.reason for c in v.checks if c.name == v.killed_by), "") if v.killed_by else f"duplicate of {v.duplicate_of}")
        res["suppressions"] = [{"kind": "external", "status": "accepted", "justification": f"docket: {v.outcome}: {why}"[:500]}]
        done += 1
    return json.dumps(doc, indent=2), done


def cmd_try(a) -> int:
    from . import report
    a = apply_config(a)
    (kind, findings), src_text = _read_findings(a)
    if a.target:
        from .importers import normalize_paths
        normalize_paths(findings, a.target)
    scope, facts, judges, ai, canary = _build(a)
    auto = a.auto_verify if a.auto_verify is not None else (kind != "docket" and bool(a.target))
    rules = suppress_mod.load(a.suppressions) if a.suppressions else []
    replay = Record(json.loads(Path(a.replay).read_text())) if getattr(a, "replay", None) else None
    env = Env(scope, judges, facts, a.target, a.canary_log, a.active, canary, ai, replay=replay,
              probe_budget=[a.max_probe_requests if a.max_probe_requests is not None else 300],
              probe_delay=a.probe_delay or 0.0, auto_verify=auto)
    t0 = time.time()
    try:
        verdicts = run_court(findings, scope, known_fingerprints=_baseline(a.baseline), suppressions=rules, env=env)
    finally:
        if canary:
            canary.stop()
    meta = {"docket": __version__, "input_format": kind, "auto_verify": auto, "ai_escalation": bool(ai),
            "judges": len(judges), "active": bool(a.active), "seconds": round(time.time() - t0, 1),
            "scope_sha": hashlib.sha256(Path(a.scope).read_bytes()).hexdigest()[:16]}
    report.REDACT = not a.no_redact
    out = a.out or "docket-report.html"
    Path(out).write_text(report.render_html(verdicts, a.title or "Docket report", meta=meta), encoding="utf-8")
    for path, fn in ((a.json_out, report.render_json), (a.sarif_out, report.render_sarif), (a.markdown_out, report.render_markdown)):
        if path:
            Path(path).write_text(fn(verdicts), encoding="utf-8")
    if a.annotate_sarif:
        if kind != "sarif":
            print("note: --annotate-sarif only applies to SARIF input; skipped", file=sys.stderr)
        else:
            text, n = _annotate_sarif(src_text, verdicts)
            Path(a.annotate_sarif).write_text(text, encoding="utf-8")
            print(f"annotated SARIF: {n} results marked as suppressed -> {a.annotate_sarif}")
    if a.ledger:
        ledger_mod.append(a.ledger, verdicts)
    if a.audit_log:
        audit_mod.append(a.audit_log, verdicts, meta["scope_sha"])
    if a.pack:
        n = write_pack(a.pack, findings, a, scope, facts, env, verdicts, meta)
        print(f"proof pack: {a.pack} ({n} files). Anyone can re-check it with: docket replay {a.pack}")
    for r in getattr(run_court, "stale", []):
        print(f"warning: suppression expired {r.get('expires')} and was ignored: {r.get('id') or r.get('title_contains') or r.get('fingerprint')}",
              file=sys.stderr)
    s = summarize(verdicts)
    print(f"{s['total']} candidates -> {s['survived']} survived, {s['needs_human']} need a human, {s['killed']} killed "
          f"{s['killed_by']}, {s['duplicates']} duplicates, {s['suppressed']} suppressed\nreport: {out}")
    if a.fail_on == "survived" and s["survived"]:
        return 2
    if a.fail_on == "needs-human" and (s["survived"] or s["needs_human"]):
        return 2
    return 0


# ---------------------------------------------------------------- proof packs + replay
PACK_GLOBS = ("*.py", "requirements*.txt", "package-lock.json", "poetry.lock", "Pipfile.lock", "package.json")
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", ".tox", "dist", "build"}


def _collect_sources(target):
    base, out, total = Path(target).resolve(), [], 0
    for pat in PACK_GLOBS:
        for p in sorted(base.rglob(pat)):
            rel = p.relative_to(base)
            if any(x in SKIP_DIRS for x in rel.parts) or not p.is_file() or p.is_symlink():
                continue
            size = p.stat().st_size
            if size > 1_000_000 or total + size > 10_000_000 or len(out) >= 3000:
                continue
            total += size
            out.append((rel, p))
    return out


def write_pack(path, findings, a, scope, facts, env, verdicts, meta):
    from . import report
    files = {
        "findings.json": json.dumps([asdict(f) for f in findings], indent=2),
        "scope.json": Path(a.scope).read_text(),
        "facts.json": json.dumps(facts, indent=2),
        "record.json": json.dumps(env.record.data, indent=2),
        "report.json": report.render_json(verdicts),
        "report.html": report.render_html(verdicts, a.title or "Docket report", meta=meta),
    }
    sources = _collect_sources(a.target) if a.target else []
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        manifest = {"docket": __version__, "created": int(time.time()), "meta": meta, "files": {}}
        for name, text in files.items():
            data = text.encode("utf-8")
            z.writestr(name, data)
            manifest["files"][name] = hashlib.sha256(data).hexdigest()
        for rel, p in sources:
            data = p.read_bytes()
            z.writestr("source/" + rel.as_posix(), data)
            manifest["files"]["source/" + rel.as_posix()] = hashlib.sha256(data).hexdigest()
        z.writestr("manifest.json", json.dumps(manifest, indent=2))
    return len(files) + len(sources) + 1


def cmd_replay(a) -> int:
    """Re-run a proof pack offline. No network, no AI, no live probes: judge votes, probe results and AI reviews come from the pack."""
    from .models import Finding
    d = Path(tempfile.mkdtemp(prefix="docket-replay-"))
    base = d.resolve()
    with zipfile.ZipFile(a.pack) as z:
        infos = z.infolist()
        if len(infos) > 6000 or sum(i.file_size for i in infos) > 300_000_000:
            raise ValueError("pack is too large to be a Docket proof pack (limit 6000 files / 300 MB uncompressed)")
        for info in z.infolist():
            dest = (base / info.filename).resolve()
            if base not in dest.parents and dest != base:
                raise ValueError(f"unsafe path in pack: {info.filename}")
        z.extractall(d)
    man = json.loads((d / "manifest.json").read_text())
    for name, digest in man["files"].items():
        if hashlib.sha256((d / name).read_bytes()).hexdigest() != digest:
            print(f"TAMPERED: {name} does not match its recorded hash", file=sys.stderr)
            return 3
    scope = Scope.load(d / "scope.json")
    findings = [Finding.from_dict(x) for x in json.loads((d / "findings.json").read_text())]
    facts = json.loads((d / "facts.json").read_text())
    rec = Record(json.loads((d / "record.json").read_text()))
    tgt = d / "source" if (d / "source").is_dir() else None
    env = Env(scope, [], facts, tgt, replay=rec, auto_verify=False)
    again = run_court(findings, scope, env=env)
    old = {v["id"]: v["outcome"] for v in json.loads((d / "report.json").read_text())["verdicts"]}
    diff = [(v.finding.id, old.get(v.finding.id), v.outcome) for v in again if old.get(v.finding.id) != v.outcome]
    shutil.rmtree(d, ignore_errors=True)
    if diff:
        for i, was, now in diff:
            print(f"DIFFERENT {i}: pack says {was}, replay says {now}")
        return 1
    print(f"replayed {len(again)} findings: every verdict matches the pack (hashes verified)")
    return 0


# ---------------------------------------------------------------- other commands
def cmd_demo(a) -> int:
    from .demo import write_demo
    p = write_demo(a.out_dir)
    d = Path(a.out_dir)
    ns = argparse.Namespace(findings=str(p["findings"]), scope=str(p["scope"]), facts=str(p["facts"]), target=str(p["target"]),
                            judge=[], judge_cmd=[], judge_file=[str(p["judge"])], escalate=None, ai_can_reject=False, ai_cache=None,
                            ai_budget=None, no_redact=False, suppressions=None, audit_log=None, auto_verify=False, active=False,
                            max_probe_requests=None, probe_delay=None, canary_log=None, canary_bind=None, canary_public_url=None,
                            config=None, default_impact="unspecified", format=None, baseline=None, ledger=None, pack=None,
                            annotate_sarif=None, replay=None, title=None, out=str(d / "report.html"), json_out=str(d / "report.json"),
                            sarif_out=str(d / "survivors.sarif"), markdown_out=str(d / "summary.md"), fail_on="never")
    return cmd_try(ns)


def cmd_lab(a) -> int:
    from . import lab, report
    if a.serve:
        from .labapp import make_server
        srv = make_server(a.port)
        out = Path(a.out_dir or "docket-lab")
        lab.write_lab_files(out, a.port)
        print(f"lab app on http://127.0.0.1:{a.port} (localhost only). In another terminal run:\n"
              f"  docket try {out}/findings.json --scope {out}/scope.json --target {lab.SRC.parent} --active "
              f"--out {out}/report.html\nCtrl-C to stop.")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass
        return 0
    verdicts, bad = lab.run_lab()
    if a.out_dir:
        d = Path(a.out_dir)
        d.mkdir(parents=True, exist_ok=True)
        (d / "lab-report.html").write_text(report.render_html(verdicts, "Docket: lab run"), encoding="utf-8")
        print(f"report: {d / 'lab-report.html'}")
    return 1 if bad else 0


def cmd_canary(a) -> int:
    import threading
    host, _, port = a.bind.rpartition(":")
    if host not in ("127.0.0.1", "localhost", ""):
        print("warning: canary is listening on a non-loopback address; anyone who can reach it can write to the log", file=sys.stderr)
    c = Canary(a.log, host or "127.0.0.1", int(port or 8088), a.public_url).start()
    print(f"canary listening on {c.base}; log: {a.log}\nuse URLs like {c.url_for('<nonce>')}; Ctrl-C to stop")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    return 0


def cmd_stats(a) -> int:
    rows = ledger_mod.stats(a.ledger)
    print(f"{'FOUND BY':24} {'TOTAL':>5} {'SURV':>5} {'HUMAN':>5} {'KILLED':>6} {'DUP':>4} {'SURVIVAL':>9}  TOP KILL REASON")
    for r in rows:
        print(f"{r['found_by'][:24]:24} {r['total']:>5} {r['survived']:>5} {r['needs_human']:>5} {r['killed']:>6} "
              f"{r['duplicate']:>4} {r['survival_rate']:>9.1%}  {r['top_kill_reason']}")
    return 0


def cmd_mcp(a) -> int:
    from .mcp import serve
    a = apply_config(a)
    scope, facts, judges, ai, canary = _build(a)
    c = Court(scope, judges, facts, a.target, a.active, canary, a.canary_log, ai)
    c.env.auto_verify = bool(a.auto_verify)
    serve(c)
    return 0


def cmd_audit(a) -> int:
    ok, n, err = audit_mod.verify(a.log)
    if ok:
        print(f"audit log OK: {n} records, chain intact (tamper-evident, not tamper-proof: keep a copy of the last hash elsewhere)")
        return 0
    print(f"audit log BROKEN after {n} good records: {err}", file=sys.stderr)
    return 1


def cmd_extract(a) -> int:
    """Turn a free-text report (pentest PDF text, bug report, AI chat) into findings JSON. The AI only structures; Docket still judges."""
    from .providers import ProviderError, extract
    a = apply_config(a)
    text = sys.stdin.read() if a.report == "-" else Path(a.report).read_text(encoding="utf-8", errors="replace")
    spec = a.model or a.escalate or (a.judge[0] if a.judge else None)
    if not spec:
        raise ValueError("pass --model PROVIDER:MODEL (an AI is needed to read free text)")
    items = extract(_make_client(spec, a, not a.no_redact), text)
    out = []
    for i, x in enumerate(items, 1):
        rc = x.get("root_cause") if isinstance(x.get("root_cause"), dict) else {}
        out.append({"id": f"extract-{i}", "title": str(x.get("title"))[:300], "vuln_class": str(x.get("vuln_class") or ""),
                    "impact": a.default_impact or "unspecified", "target": str(x.get("target") or ""),
                    "found_by": "extracted:" + spec, "root_cause": rc, "repro_steps": [str(s) for s in x.get("repro_steps") or []]})
    Path(a.out).write_text(json.dumps(out, indent=2))
    print(f"{len(out)} findings written to {a.out}. They have no evidence yet: add assumptions/evidence or use --auto-verify with --target.")
    return 0


def cmd_providers(a) -> int:
    from .providers import ProviderError
    ok = True
    for spec in a.specs:
        t0 = time.time()
        try:
            c = _make_client(spec, argparse.Namespace(ai_cache=None, ai_budget=3))
            r = c.ask('Reply with JSON only: {"ok": true}', "ping", 30)
            print(f"OK    {spec}  ({time.time() - t0:.1f}s)  reply: {r.strip()[:60]}")
        except ProviderError as e:
            ok = False
            print(f"FAIL  {spec}  {e}")
    return 0 if ok else 1


def cmd_doctor(a) -> int:
    problems = 0

    def line(ok, msg, hint=""):
        nonlocal problems
        problems += 0 if ok else 1
        print(("ok    " if ok else "FIX   ") + msg + (f"\n        -> {hint}" if hint and not ok else ""))
    line(sys.version_info >= (3, 10), f"python {sys.version.split()[0]}", "Docket needs Python 3.10 or newer")
    line(True, f"docket {__version__}")
    try:
        t = Path(tempfile.mkdtemp())
        (t / "x").write_text("x")
        line(True, "can write temp files")
    except OSError as e:
        line(False, f"cannot write temp files ({e})")
    try:
        import socket
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.close()
        line(True, "can open a localhost port (needed for the lab, canary and selftest)")
    except OSError as e:
        line(False, f"cannot bind localhost ({e})", "a sandbox may block local sockets; --active features need them")
    cfg = next((n for n in CONFIG_NAMES if Path(n).is_file()), None)
    line(True, f"config: {cfg}" if cfg else "config: none (optional; 'docket init' writes docket.json)")
    sc = a.scope or (json.loads(Path(cfg).read_text()).get("scope") if cfg else None)
    if sc:
        try:
            s = Scope.load(sc)
            line(bool(s.accepted_impacts), f"scope {sc}: {len(s.accepted_impacts)} accepted impacts",
                 "with no accepted impacts every finding is unverified; list the impacts you would pay for / fix")
        except Exception as e:  # noqa: BLE001
            line(False, f"scope {sc}: {e}")
    keys = {"ANTHROPIC_API_KEY": "anthropic", "OPENAI_API_KEY": "openai", "GEMINI_API_KEY": "gemini", "GOOGLE_API_KEY": "gemini",
            "DOCKET_API_KEY": "openai-compat"}
    have = sorted({v for k, v in keys.items() if os.environ.get(k)})
    print(f"info  AI keys found in environment for: {', '.join(have) if have else 'none'} (values are never printed). Local models via ollama need no key.")
    print("info  AI is optional: without it Docket still runs every deterministic check; 'unverified' findings go to a human.")
    print("\nall good" if not problems else f"\n{problems} thing(s) to fix")
    return 1 if problems else 0


# what a scanner finding of each class would mean if real; edit to match what YOU would fix or pay for
IMPACT_MAP = {"sqli": "data-exfiltration", "cmdi": "rce", "code-exec": "rce", "deserialization": "rce", "ssti": "rce",
              "path-traversal": "data-exfiltration", "ssrf": "data-exfiltration", "xss": "account-takeover",
              "open-redirect": "account-takeover", "secrets": "account-takeover", "xxe": "data-exfiltration",
              "idor": "data-exfiltration", "auth-bypass": "account-takeover", "jwt": "account-takeover", "cors": "data-exfiltration"}
PROFILES = {
    "ci": {"accepted_impacts": ["rce", "data-exfiltration", "auth-bypass", "account-takeover", "privilege-escalation"],
           "attacker_states": ["unauthenticated", "authenticated-user"], "cfg": {"fail_on": "survived", "auto_verify": True}},
    "bugbounty": {"accepted_impacts": ["rce", "data-exfiltration", "account-takeover", "ssrf-internal-access", "auth-bypass"],
                  "attacker_states": ["unauthenticated", "authenticated-user"], "cfg": {"fail_on": "never"}},
    "cloud": {"accepted_impacts": ["data-exfiltration", "privilege-escalation", "public-exposure", "credential-exposure"],
              "attacker_states": ["unauthenticated", "authenticated-user"], "cfg": {"fail_on": "needs-human"}},
}


def cmd_init(a) -> int:
    from .demo import FACTS
    d = Path(a.dir)
    d.mkdir(parents=True, exist_ok=True)
    scope = {"accepted_impacts": ["rce", "data-exfiltration", "account-takeover"], "out_of_scope_impacts": ["self-xss", "missing-headers"],
             "ineligible_patterns": [], "known_issues": [], "attacker_states": ["unauthenticated", "authenticated-user"],
             "in_scope_targets": [], "active_hosts": [], "require_judge": False, "ai_can_reject": False, "impact_map": IMPACT_MAP}
    cfg = {"scope": "scope.json", "out": "docket-report.html", "json_out": "docket-report.json", "markdown_out": "docket-summary.md",
           "audit_log": "docket-audit.jsonl", "suppressions": "docket-suppressions.json"}
    if a.profile:
        pr = PROFILES[a.profile]
        scope.update({"accepted_impacts": pr["accepted_impacts"], "attacker_states": pr["attacker_states"]})
        cfg.update(pr["cfg"])
    example = {"id": "F1", "title": "short claim", "vuln_class": "idor", "impact": "data-exfiltration",
               "found_by": "your-agent-or-tool", "target": "app/orders.py",
               "assumptions": [{"kind": "attacker_state", "state": "authenticated-user"}],
               "evidence": [{"type": "cross_account", "status": 200, "marker": "ORDER-2-SECRET", "response_body": "..."}],
               "probes": [], "root_cause": {"file": "app/orders.py", "line": 7, "quote": "exact code on that line"},
               "repro_steps": ["log in as user1", "request /orders/2", "see user2's order"]}
    for name, data in (("scope.json", scope), ("docket.json", cfg), ("docket-suppressions.json", []),
                       ("facts.json", FACTS), ("findings.example.json", [example])):
        p = d / name
        if p.exists():
            print(f"skip {p} (exists)")
        else:
            p.write_text(json.dumps(data, indent=2))
            print(f"wrote {p}")
    print("\nnext: edit scope.json, then  docket try <findings-or-scanner-output> --target <your-source-dir>")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="docket", description="Put security findings (from AI agents or scanners) on trial.")
    ap.add_argument("--version", action="version", version=f"docket {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("try", help="run findings (Docket JSON, SARIF, Semgrep, Bandit, Nuclei, Trivy, Gitleaks) through the checks")
    t.add_argument("findings", help="findings file, or '-' for stdin")
    _common(t)
    t.add_argument("--format", choices=["docket", "sarif", "semgrep", "bandit", "nuclei", "trivy", "gitleaks"], help="force the input format")
    t.add_argument("--default-impact", help="impact for scanner results that have none (or use scope.impact_map)")
    t.add_argument("--baseline", help="earlier report.json: findings already killed/reported there are skipped as known")
    t.add_argument("--ledger", help="append verdicts to this JSONL ledger (see 'stats')")
    t.add_argument("--out", help="HTML report path (default docket-report.html)")
    t.add_argument("--title", help="title shown at the top of the HTML report")
    t.add_argument("--json", dest="json_out")
    t.add_argument("--sarif-out", help="write survivors and needs-human findings as SARIF")
    t.add_argument("--annotate-sarif", metavar="FILE", help="SARIF input only: write a copy where killed/duplicate results carry a suppression")
    t.add_argument("--markdown-out", help="short summary (PR comments / $GITHUB_STEP_SUMMARY)")
    t.add_argument("--pack", metavar="FILE.zip", help="write a proof pack anyone can re-check offline with 'docket replay'")
    t.add_argument("--replay", metavar="record.json", help="answer judges/probes/AI from a saved record (offline, deterministic)")
    t.add_argument("--fail-on", choices=["never", "survived", "needs-human"], help="exit 2 if anything survived (or also needs a human)")
    t.set_defaults(fn=cmd_try)
    rp = sub.add_parser("replay", help="re-check a proof pack offline and confirm every verdict is reproduced")
    rp.add_argument("pack")
    rp.set_defaults(fn=cmd_replay)
    d = sub.add_parser("demo", help="write a synthetic case and try it")
    d.add_argument("--out-dir", default="docket-demo")
    d.set_defaults(fn=cmd_demo)
    lb = sub.add_parser("lab", help="self-test against a deliberately vulnerable localhost app")
    lb.add_argument("--serve", action="store_true", help="only run the vulnerable app so you can point tools at it")
    lb.add_argument("--port", type=int, default=8099)
    lb.add_argument("--out-dir", default="")
    lb.set_defaults(fn=cmd_lab)
    c = sub.add_parser("canary", help="run a standalone out-of-band callback listener")
    c.add_argument("--bind", default="127.0.0.1:8088")
    c.add_argument("--log", default="canary.jsonl")
    c.add_argument("--public-url")
    c.set_defaults(fn=cmd_canary)
    st = sub.add_parser("stats", help="survival rate per finder from a ledger")
    st.add_argument("ledger")
    st.set_defaults(fn=cmd_stats)
    m = sub.add_parser("mcp", help="serve the court as MCP tools over stdio (agents check findings before reporting)")
    _common(m)
    m.set_defaults(fn=cmd_mcp)
    au = sub.add_parser("audit", help="verify a hash-chained audit log")
    au.add_argument("log")
    au.set_defaults(fn=cmd_audit)
    ex = sub.add_parser("extract", help="use an AI to turn a free-text report into findings JSON (it only structures, Docket still judges)")
    ex.add_argument("report", help="text file or '-'")
    ex.add_argument("--model", metavar="PROVIDER:MODEL")
    ex.add_argument("--out", default="findings.extracted.json")
    ex.add_argument("--default-impact")
    ex.add_argument("--config")
    ex.add_argument("--escalate")
    ex.add_argument("--judge", action="append", default=[])
    ex.add_argument("--ai-cache")
    ex.add_argument("--ai-budget", type=int)
    ex.add_argument("--no-redact", action="store_true")
    ex.set_defaults(fn=cmd_extract)
    pv = sub.add_parser("providers", help="test AI provider connections: docket providers anthropic:MODEL openai:MODEL ...")
    pv.add_argument("specs", nargs="+")
    pv.set_defaults(fn=cmd_providers)
    dr = sub.add_parser("doctor", help="check this machine and config; says exactly what to fix")
    dr.add_argument("--scope")
    dr.set_defaults(fn=cmd_doctor)
    sf = sub.add_parser("selftest", help="check this install end to end (no pytest, no network, localhost only)")
    sf.add_argument("--out-dir", default="", help="keep the generated reports here")
    sf.set_defaults(fn=lambda a: __import__("docket.kit", fromlist=["x"]).selftest(a.out_dir))
    k = sub.add_parser("kit", help="write the testing kit: sample case, lab, example judges and CI templates")
    k.add_argument("dir", nargs="?", default="docket-kit")
    k.set_defaults(fn=lambda a: __import__("docket.kit", fromlist=["x"]).write_kit(a.dir))
    i = sub.add_parser("init", help="write starter scope.json, docket.json, suppressions and an example finding")
    i.add_argument("dir", nargs="?", default=".")
    i.add_argument("--profile", choices=sorted(PROFILES), help="starting point: ci, bugbounty or cloud")
    i.set_defaults(fn=cmd_init)
    a = ap.parse_args(argv)
    try:
        return a.fn(a)
    except (OSError, ValueError, KeyError) as e:
        print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    sys.exit(main())
