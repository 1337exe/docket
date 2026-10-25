"""Synthetic demo: 30 candidates (app code, dependencies, secrets, cloud config), built so the court has real work to do."""
from __future__ import annotations

import json
from pathlib import Path

FILES = {
    "app/orders.py": 'from flask import request, jsonify\nfrom db import Order\n\n@app.route("/orders/<int:oid>")\n@login_required\ndef get_order(oid):\n    order = Order.query.get(oid)\n    return jsonify(order.to_dict())\n',
    "app/fetch.py": 'import requests\nfrom flask import request\n\ndef proxy():\n    r = requests.get(request.args["url"])\n    return r.text\n',
    "app/admin.py": 'def run_report(name):\n    return db.execute("SELECT * FROM " + name)\n',
    "app/reports.py": ('from db import conn\n\ndef legacy_report(name):\n    return conn.execute("SELECT * FROM " + name)\n\n'
                       '@app.route("/search")\ndef search():\n    term = request.args["q"]\n'
                       '    return conn.execute("SELECT * FROM users WHERE name = %s", (term,))\n'),
    "app/system.py": ('import os, shlex, subprocess\nfrom flask import request\n\n@app.route("/ping")\ndef ping():\n'
                      '    host = request.args["host"]\n    return os.system("ping -c1 " + host)\n\n'
                      '@app.route("/ping2")\ndef ping2():\n    host = request.args["host"]\n'
                      '    return os.system("ping -c1 " + shlex.quote(host))\n'),
    "app/files.py": ('import os, yaml\nfrom flask import request, send_file\n\n@app.route("/download")\ndef download():\n'
                     '    name = request.args["name"]\n    return open("/srv/files/" + name).read()\n\n'
                     '@app.route("/download2")\ndef download2():\n    name = request.args["name"]\n'
                     '    return open("/srv/files/" + os.path.basename(name)).read()\n\n'
                     '@app.route("/import", methods=["POST"])\ndef import_config():\n    data = request.data\n    return yaml.load(data)\n\n'
                     '@app.route("/import2", methods=["POST"])\ndef import_config2():\n    data = request.data\n'
                     '    return yaml.load(data, Loader=yaml.SafeLoader)\n'),
    "config.py": 'AWS_ACCESS_KEY_ID = "AKIAQWERTYUIOPASDFGH"\nEXAMPLE_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
    "requirements.txt": "requests==2.19.0\nflask==3.0.0\n",
}

SCOPE = {"accepted_impacts": ["data-exfiltration", "account-takeover", "rce"],
         "out_of_scope_impacts": ["self-xss", "missing-headers"],
         "attacker_states": ["unauthenticated", "authenticated-user"],
         "in_scope_targets": ["app/*", "aws:*", "requirements.txt", "config.py"], "max_repro_steps": 8,
         "known_issues": ["verbose error page"], "forbidden_states": ["physical access"]}

FACTS = {"policies": {"web-role": {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::app-data/*"}]}},
    "security_groups": {"sg-web": {"ingress": [{"cidr": "0.0.0.0/0", "from": 443, "to": 443}]}},
    "s3_buckets": {"app-public": {"block_public_access": {}, "acl_public": True},
                   "app-private": {"block_public_access": {k: True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}}}}


def F(i, title, impact, assumptions, rc, steps, target="app/orders.py", by="finder-model"):
    return {"id": i, "title": title, "impact": impact, "target": target, "found_by": by, "severity": "high",
            "reasoning": "Looks exploitable.", "assumptions": assumptions, "root_cause": rc, "repro_steps": steps}


def S(n):
    return [f"step {k}" for k in range(1, n + 1)]


USER = [{"kind": "attacker_state", "state": "authenticated-user"}]
ORD = {"file": "app/orders.py", "line": 7, "quote": "order = Order.query.get(oid)"}
L = lambda n, q: {"file": "app/orders.py", "line": n, "quote": q}
IDOR_PROOF = [{"type": "cross_account", "status": 200, "marker": "ORDER-2-SECRET",
               "response_body": "ORDER-2-SECRET (requested as user1)"}]
FINDINGS = [
    dict(F("F01", "Any logged-in user can read other users' orders (IDOR)", "data-exfiltration",
           USER + [{"kind": "entrypoint_reaches", "function": "get_order"},
                   {"kind": "file_contains", "path": "app/orders.py", "pattern": r"Order\.query\.get\(oid\)"}],
           ORD, S(4)), vuln_class="idor", evidence=IDOR_PROOF),
    F("F02", "SSRF in /proxy reaches cloud metadata", "rce",
      [{"kind": "attacker_state", "state": "unauthenticated"}, {"kind": "metadata_reachable", "text": "IMDS reachable from app host"}],
      {"file": "app/fetch.py", "line": 5, "quote": "requests.get(request.args"}, S(5), target="app/fetch.py"),
    F("F03", "Admin report endpoint allows SQL injection", "data-exfiltration",
      [{"kind": "attacker_state", "state": "authenticated-admin"}], {"file": "app/admin.py", "line": 2, "quote": "SELECT"}, S(3), target="app/admin.py"),
    F("F04", "Local file write leads to takeover", "account-takeover", [{"kind": "attacker_state", "state": "local-root"}],
      L(6, "def get_order(oid):"), S(3)),
    F("F05", "Web role can escalate via iam:PassRole", "account-takeover",
      [{"kind": "aws_policy_allows", "policy": "web-role", "action": "iam:PassRole", "resource": "*"}],
      {"fact_path": "policies.web-role"}, S(4), target="aws:web-role"),
    F("F06", "Database port exposed to the internet", "data-exfiltration",
      [{"kind": "network_exposed", "resource": "sg-web", "port": 3306}], {"fact_path": "security_groups.sg-web"}, S(2), target="aws:sg-web"),
    F("F07", "Vendored library has unsafe deserialization", "rce", USER, ORD, S(3), target="vendor/lib.py"),
    F("F08", "Reflected script runs only in the attacker's own session", "self-xss", USER, L(8, "return jsonify"), S(3)),
    F("F09", "Missing X-Frame-Options header", "missing-headers", USER, L(5, "@login_required"), S(2)),
    F("F10", "Theoretical denial of service via huge JSON", "theoretical-dos", USER, L(2, "from db import Order"), S(3)),
    F("F11", "Order IDs can be guessed to forge refunds", "account-takeover", USER, L(4, "@app.route"), S(5)),
    F("F12", "Race condition lets a user read two orders at once", "data-exfiltration", USER, L(8, "return jsonify"), S(4)),
    F("F13", "eval() on query string gives code execution", "rce", USER,
      {"file": "app/orders.py", "line": 7, "quote": "eval(request.args['q'])"}, S(3)),
    F("F14", "Chain of 20 steps ends in account takeover", "account-takeover", USER, L(5, "@login_required"), S(20)),
    dict(F("F15", "Order endpoint is missing an ownership check", "data-exfiltration", USER, ORD, S(3), by="second-agent"),
         vuln_class="idor"),
    F("F16", "Verbose error page leaks stack trace", "data-exfiltration", USER, L(2, "from db import Order"), S(2)),
    F("F17", "SQL injection in legacy_report()", "data-exfiltration",
      USER + [{"kind": "entrypoint_reaches", "function": "legacy_report"}],
      {"file": "app/reports.py", "line": 4, "quote": 'conn.execute("SELECT * FROM " + name)'}, S(3), target="app/reports.py"),
    F("F18", "SQL injection in /search", "data-exfiltration",
      USER + [{"kind": "taint_flow", "function": "search", "sink": "execute"}],
      {"file": "app/reports.py", "line": 9, "quote": "conn.execute"}, S(3), target="app/reports.py"),
]
def at(rel, quote):
    for n, line in enumerate(FILES[rel].splitlines(), 1):
        if quote in line:
            return {"file": rel, "line": n, "quote": quote}
    raise KeyError(quote)


TAINT = lambda fn, cls, sink: USER + [{"kind": "entrypoint_reaches", "function": fn},
                                      {"kind": "taint_flow", "function": fn, "sink": sink, "vuln_class": cls}]
FINDINGS += [
    F("F19", "requests 2.19.0 has a known vulnerability and the app uses it", "data-exfiltration",
      [{"kind": "dependency_vuln", "package": "requests", "fixed": "2.20.0"}], {"file": "requirements.txt", "line": 1, "quote": "requests==2.19.0"},
      S(2), target="requirements.txt"),
    F("F20", "AWS access key committed in config.py", "account-takeover",
      [{"kind": "secret_plausible", "file": "config.py", "line": 1}], at("config.py", "AKIAQWERTYUIOPASDFGH"), S(2), target="config.py"),
    F("F21", "AWS key committed in config.py (documentation example key)", "account-takeover",
      [{"kind": "secret_plausible", "file": "config.py", "line": 2}], at("config.py", "AKIAIOSFODNN7EXAMPLE"), S(2), target="config.py"),
    F("F22", "S3 bucket app-public is world readable", "data-exfiltration", [{"kind": "aws_s3_public", "bucket": "app-public"}],
      {"fact_path": "s3_buckets.app-public"}, S(2), target="aws:app-public"),
    F("F23", "S3 bucket app-private is world readable", "data-exfiltration", [{"kind": "aws_s3_public", "bucket": "app-private"}],
      {"fact_path": "s3_buckets.app-private"}, S(2), target="aws:app-private"),
    F("F24", "Command injection in /ping", "rce", TAINT("ping", "cmdi", "os.system"), at("app/system.py", 'os.system("ping -c1 " + host)'), S(3),
      target="app/system.py"),
    F("F25", "Command injection in /ping2", "rce", TAINT("ping2", "cmdi", "os.system"), at("app/system.py", "shlex.quote(host)"), S(3),
      target="app/system.py"),
    F("F26", "Path traversal in /download", "data-exfiltration", TAINT("download", "path-traversal", "open"),
      at("app/files.py", 'open("/srv/files/" + name)'), S(3), target="app/files.py"),
    F("F27", "Path traversal in /download2", "data-exfiltration", TAINT("download2", "path-traversal", "open"),
      at("app/files.py", "os.path.basename(name)"), S(3), target="app/files.py"),
    F("F28", "Unsafe YAML load in /import gives code execution", "rce", TAINT("import_config", "deserialization", "yaml.load"),
      at("app/files.py", "return yaml.load(data)"), S(3), target="app/files.py"),
    F("F29", "Unsafe YAML load in /import2 gives code execution", "rce", TAINT("import_config2", "deserialization", "yaml.load"),
      at("app/files.py", "Loader=yaml.SafeLoader"), S(3), target="app/files.py"),
    F("F30", "flask 3.0.0 is affected by an old CVE", "data-exfiltration", [{"kind": "dependency_vuln", "package": "flask", "fixed": "2.0.0"}],
      {"file": "requirements.txt", "line": 2, "quote": "flask==3.0.0"}, S(2), target="requirements.txt"),
]
J = lambda ok, why: {"reproduced": ok, "model": "judge-model", "reason": why}
JUDGE = {f["id"]: J(True, "Followed the steps and reproduced it.") for f in FINDINGS}
JUDGE["F11"] = J(False, "Order IDs are signed; guessing fails.")
JUDGE["F12"] = J(False, "The handler is read-only; no race window.")


def write_demo(out_dir) -> dict:
    d = Path(out_dir)
    for rel, text in FILES.items():
        p = d / "target" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    paths = {"target": d / "target", "findings": d / "findings.json", "scope": d / "scope.json",
             "facts": d / "facts.json", "judge": d / "judge.json"}
    for key, data in (("findings", FINDINGS), ("scope", SCOPE), ("facts", FACTS), ("judge", JUDGE)):
        paths[key].write_text(json.dumps(data, indent=2))
    return paths
