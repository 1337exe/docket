"""Import findings from the tools people already run, so Docket works on their own work, not just samples.

Supported: SARIF 2.1 (any tool), Semgrep JSON, Bandit JSON, Nuclei JSONL, Trivy JSON, Gitleaks JSON, Docket JSON, and
free-text reports (via --extract with an AI provider). Scanners rarely state impact: set scope.impact_map
(vuln_class -> impact) or pass --default-impact.
"""
from __future__ import annotations

import hashlib
import json
import re

from .models import Finding

CWE_CLASS = {"89": "sqli", "564": "sqli", "79": "xss", "80": "xss", "22": "path-traversal", "23": "path-traversal", "36": "path-traversal",
             "73": "path-traversal", "918": "ssrf", "78": "cmdi", "77": "cmdi", "94": "code-exec", "95": "code-exec", "502": "deserialization",
             "601": "open-redirect", "798": "secrets", "259": "secrets", "321": "secrets", "200": "info-exposure", "352": "csrf",
             "639": "idor", "284": "auth-bypass", "287": "auth-bypass", "306": "auth-bypass", "611": "xxe", "1336": "ssti", "346": "cors",
             "942": "cors", "307": "rate-limit", "1321": "mass-assignment", "915": "mass-assignment", "1104": "dependency", "937": "dependency"}
KEYWORD_CLASS = [("sql", "sqli"), ("xss", "xss"), ("cross-site-scripting", "xss"), ("traversal", "path-traversal"), ("lfi", "path-traversal"),
                 ("ssrf", "ssrf"), ("command-injection", "cmdi"), ("cmd-injection", "cmdi"), ("os-command", "cmdi"), ("subprocess", "cmdi"), ("os-system", "cmdi"), ("eval", "code-exec"),
                 ("exec", "code-exec"), ("deserial", "deserialization"), ("pickle", "deserialization"), ("yaml-load", "deserialization"),
                 ("redirect", "open-redirect"), ("secret", "secrets"), ("hardcoded-password", "secrets"), ("hardcoded-secret", "secrets"), ("hardcoded-token", "secrets"), ("hardcoded-credential", "secrets"), ("password", "secrets"), ("token", "secrets"),
                 ("csrf", "csrf"), ("idor", "idor"), ("xxe", "xxe"), ("ssti", "ssti"), ("template-injection", "ssti"), ("cors", "cors"),
                 ("jwt", "jwt"), ("takeover", "auth-bypass")]
SEVERITY = {"error": "high", "warning": "medium", "note": "low", "none": "info"}


def guess_class(*texts, cwes=()):
    for c in cwes:
        m = re.search(r"(\d+)", str(c))
        if m and m.group(1) in CWE_CLASS:
            return CWE_CLASS[m.group(1)]
    blob = re.sub(r"[\s_]+", "-", " ".join(str(t).lower() for t in texts if t))
    for kw, cls in KEYWORD_CLASS:
        if kw in blob:
            return cls
    return ""


def _short(s):
    return hashlib.sha256(str(s).encode()).hexdigest()[:8]


def _quote(txt):
    lines = [x.strip() for x in str(txt or "").strip().splitlines() if x.strip()]
    return lines[0] if lines else ""


def from_sarif(doc, default_impact="unspecified"):
    out = []
    for ri, run in enumerate(doc.get("runs", [])):
        tool = ((run.get("tool") or {}).get("driver") or {}).get("name", "sarif")
        rules = {r.get("id"): r for r in ((run.get("tool") or {}).get("driver") or {}).get("rules", []) if isinstance(r, dict)}
        for i, r in enumerate(run.get("results", [])):
            loc = ((r.get("locations") or [{}])[0].get("physicalLocation") or {})
            uri = (loc.get("artifactLocation") or {}).get("uri", "")
            uri = re.sub(r"^file://", "", uri)
            region = loc.get("region") or {}
            rc = {"file": uri, "line": region["startLine"], "quote": _quote((region.get("snippet") or {}).get("text"))} \
                if uri and region.get("startLine") else None
            props = r.get("properties") or {}
            rule = rules.get(r.get("ruleId")) or {}
            tags = " ".join(map(str, list((rule.get("properties") or {}).get("tags", [])) + list(props.get("tags", [])) + [r.get("ruleId", "")]))
            cwes = [t for t in re.findall(r"CWE-?\d+", tags + " " + json.dumps(rule)[:600], re.I)]
            out.append(Finding(id=f"{tool}-{r.get('ruleId', 'rule')}-{ri}.{i}", title=(r.get("message") or {}).get("text", r.get("ruleId", "finding"))[:300],
                               impact=props.get("impact", default_impact), severity=SEVERITY.get(r.get("level", ""), r.get("level", "")),
                               vuln_class=props.get("vuln_class") or guess_class(r.get("ruleId"), tags, (r.get("message") or {}).get("text"), cwes=cwes), target=uri, root_cause=rc,
                               repro_steps=list(props.get("repro_steps", [])), assumptions=list(props.get("assumptions", [])), found_by=tool))
    return out


def from_semgrep(doc, default_impact="unspecified"):
    out = []
    for i, r in enumerate(doc.get("results", [])):
        ex, meta = r.get("extra") or {}, (r.get("extra") or {}).get("metadata") or {}
        cwes = meta.get("cwe") if isinstance(meta.get("cwe"), list) else [meta.get("cwe")] if meta.get("cwe") else []
        out.append(Finding(id=f"semgrep-{_short(r.get('check_id'))}-{i}", title=(ex.get("message") or r.get("check_id", "semgrep finding"))[:300],
                           impact=default_impact, severity={"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(ex.get("severity", ""), ""),
                           vuln_class=guess_class(r.get("check_id"), cwes=cwes), target=r.get("path", ""),
                           root_cause={"file": r.get("path", ""), "line": (r.get("start") or {}).get("line"), "quote": _quote(ex.get("lines"))},
                           found_by="semgrep"))
    return out


def from_bandit(doc, default_impact="unspecified"):
    out = []
    for i, r in enumerate(doc.get("results", [])):
        if not isinstance(r, dict) or not r.get("filename"):
            continue
        fn, ln = re.sub(r"^\./", "", str(r["filename"])), r.get("line_number")
        quote = ""
        for row in str(r.get("code", "")).splitlines():
            m = re.match(r"\s*(\d+)\s(.*)$", row)
            if m and int(m.group(1)) == ln:
                quote = m.group(2).strip()
        cwe = (r.get("issue_cwe") or {}).get("id")
        out.append(Finding(id=f"bandit-{r.get('test_id', 'B')}-{i}", title=f"{r.get('issue_text', 'bandit finding')} ({fn}:{ln})"[:300],
                           impact=default_impact, severity={"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(r.get("issue_severity"), ""),
                           vuln_class=guess_class(r.get("test_name"), r.get("issue_text"), cwes=[cwe] if cwe else []), target=fn,
                           root_cause={"file": fn, "line": ln, "quote": quote}, found_by="bandit"))
    return out


def from_nuclei(lines, default_impact="unspecified"):
    out = []
    for i, ln in enumerate(lines):
        try:
            r = json.loads(ln)
        except ValueError:
            continue
        if not isinstance(r, dict) or "template-id" not in r:
            continue
        info = r.get("info") or {}
        tags = info.get("tags") if isinstance(info.get("tags"), list) else str(info.get("tags", "")).split(",")
        out.append(Finding(id=f"nuclei-{r['template-id']}-{i}", title=(info.get("name") or r["template-id"])[:300], impact=default_impact,
                           severity=str(info.get("severity", "")), vuln_class=guess_class(r["template-id"], " ".join(tags)),
                           target=r.get("matched-at") or r.get("host", ""), found_by="nuclei",
                           repro_steps=[f"run template {r['template-id']} against {r.get('matched-at') or r.get('host', '')}"]))
    return out


def from_trivy(doc, default_impact="unspecified"):
    out = []
    for res in doc.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            fixed = str(v.get("FixedVersion", "")).split(",")[0].strip()
            out.append(Finding(
                id=f"trivy-{v.get('VulnerabilityID')}-{v.get('PkgName')}", title=f"{v.get('PkgName')} {v.get('InstalledVersion')}: {v.get('Title') or v.get('VulnerabilityID')}"[:300],
                impact=default_impact, severity=str(v.get("Severity", "")).lower(), vuln_class="dependency", target=res.get("Target", ""),
                assumptions=[{"kind": "dependency_vuln", "package": v.get("PkgName"), "fixed": fixed}] if fixed else [], found_by="trivy"))
    return out


def from_gitleaks(arr, default_impact="unspecified"):
    out = []
    for i, r in enumerate(arr):
        if not isinstance(r, dict) or "RuleID" not in r:
            continue
        out.append(Finding(id=f"gitleaks-{r['RuleID']}-{i}", title=f"{r.get('Description', r['RuleID'])} in {r.get('File')}"[:300], impact=default_impact,
                           vuln_class="secrets", target=r.get("File", ""),
                           root_cause={"file": r.get("File", ""), "line": r.get("StartLine"), "quote": f"[secret:{_short(r.get('Secret'))}]"},
                           assumptions=[{"kind": "secret_plausible", "file": r.get("File", ""), "line": r.get("StartLine")}], found_by="gitleaks"))
    return out


def sniff(text: str):
    """Return (format, parsed) for an input document, or raise ValueError."""
    t = text.lstrip()
    if not t:
        raise ValueError("input is empty")
    lines = [ln for ln in t.splitlines() if ln.strip()]
    if len(lines) > 1 and all(ln.lstrip().startswith("{") for ln in lines[:3]):
        try:
            if "template-id" in json.loads(lines[0]):
                return "nuclei", lines
        except ValueError:
            pass
    try:
        doc = json.loads(t)
    except ValueError:
        raise ValueError("input is not JSON, JSONL or SARIF")
    if isinstance(doc, dict):
        if isinstance(doc.get("runs"), list):
            return "sarif", doc
        if "results" in doc and isinstance(doc["results"], list) and doc["results"] and "test_id" in doc["results"][0]:
            return "bandit", doc
        if "results" in doc and isinstance(doc["results"], list) and (not doc["results"] or "check_id" in doc["results"][0]):
            return "semgrep", doc
        if "Results" in doc:
            return "trivy", doc
        if "findings" in doc:
            return "docket", doc["findings"]
    if isinstance(doc, list):
        if doc and isinstance(doc[0], dict) and "RuleID" in doc[0]:
            return "gitleaks", doc
        return "docket", doc
    raise ValueError("unrecognised input format")


def load(text: str, default_impact="unspecified", fmt=None):
    kind, data = sniff(text)
    kind = fmt or kind
    if kind == "docket":
        return "docket", [Finding.from_dict(d) for d in data]
    fn = {"sarif": from_sarif, "semgrep": from_semgrep, "nuclei": from_nuclei, "bandit": from_bandit, "trivy": from_trivy, "gitleaks": from_gitleaks}[kind]
    out = fn(data, default_impact)
    for f in out:  # scanners give a location, not a story: write the steps a human would follow from that location
        if not f.repro_steps:
            rc = f.root_cause or {}
            where = f"{rc['file']}:{rc['line']}" if rc.get("file") and rc.get("line") else (f.target or "the reported location")
            f.repro_steps = [f"Open {where} (reported by {f.found_by or kind})", f"Confirm the reported condition: {f.title[:120]}"]
    return kind, out


def normalize_paths(findings, target):
    """Scanners report paths relative to wherever they ran (src/app/x.py, ./x.py, /abs/x.py). Make them relative to --target
    when that is unambiguous: only rewrites a path that does not exist under target but does after stripping a prefix."""
    import os
    from pathlib import Path
    if not target:
        return 0
    base = Path(target).resolve()
    tparts = [x for x in os.path.normpath(str(target)).split(os.sep) if x not in ("", ".")]

    def fix(p):
        if not isinstance(p, str) or not p:
            return p
        q = p.replace("\\", "/")
        cands = []
        if os.path.isabs(q):
            try:
                cands.append(str(Path(q).resolve().relative_to(base)))
            except ValueError:
                pass
        q2 = re.sub(r"^(\./)+", "", q)
        cands.append(q2)
        for i in range(len(tparts), 0, -1):  # strip the --target path (or a suffix of it) from the front
            pre = "/".join(tparts[-i:]) + "/"
            if q2.startswith(pre):
                cands.append(q2[len(pre):])
        for c in cands:
            if c and (base / c).exists() and ".." not in Path(c).parts:
                return c
        return p

    n = 0
    for f in findings:
        before = (f.target, (f.root_cause or {}).get("file"))
        f.target = fix(f.target)
        if f.root_cause and "file" in f.root_cause:
            f.root_cause["file"] = fix(f.root_cause["file"])
        for a in f.assumptions:
            for k in ("file", "path"):
                if k in a:
                    a[k] = fix(a[k])
        n += before != (f.target, (f.root_cause or {}).get("file"))
    return n
