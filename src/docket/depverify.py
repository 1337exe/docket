"""Dependency and secret verifiers (offline, no network)."""
from __future__ import annotations

import json
import math
import re
from pathlib import Path

from .models import FAIL, PASS, UNVERIFIED
from .util import safe_join


def vkey(v):
    """Loose version -> comparable tuple (handles 1.2.3, 1.2.3rc1, v2.0, 1.2.3-beta)."""
    nums = re.findall(r"\d+", str(v).split("+")[0].split("-")[0])
    return tuple(int(x) for x in nums[:6]) or (0,)


def _lock_versions(target):
    """Return {package(lowercase): version} from requirements*.txt, package-lock.json, poetry.lock, Pipfile.lock."""
    found, base = {}, Path(target)
    for p in list(base.rglob("requirements*.txt")) + list(base.rglob("constraints*.txt")):
        if "node_modules" in p.parts:
            continue
        for line in p.read_text(errors="replace").splitlines():
            m = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-+]+)", line)
            if m:
                found[m.group(1).lower().replace("_", "-")] = m.group(2)
    for p in base.rglob("package-lock.json"):
        if "node_modules" in p.parts:
            continue
        try:
            d = json.loads(p.read_text(errors="replace"))
        except ValueError:
            continue
        for k, v in (d.get("packages") or {}).items():
            if k.startswith("node_modules/") and isinstance(v, dict) and v.get("version"):
                found[k.split("node_modules/")[-1].lower()] = v["version"]
        for k, v in (d.get("dependencies") or {}).items():
            if isinstance(v, dict) and v.get("version"):
                found.setdefault(k.lower(), v["version"])
    for p in base.rglob("poetry.lock"):
        txt = p.read_text(errors="replace")
        for m in re.finditer(r'\[\[package\]\]\s*name = "([^"]+)"\s*version = "([^"]+)"', txt):
            found[m.group(1).lower().replace("_", "-")] = m.group(2)
    for p in base.rglob("Pipfile.lock"):
        try:
            d = json.loads(p.read_text(errors="replace"))
        except ValueError:
            continue
        for sec in ("default", "develop"):
            for k, v in (d.get(sec) or {}).items():
                ver = str(v.get("version", "")).lstrip("=")
                if ver:
                    found[k.lower().replace("_", "-")] = ver
    return found


def _imports(target, pkg):
    pat_py = re.compile(rf"^\s*(?:import|from)\s+{re.escape(pkg.replace('-', '_'))}(?:[.\s]|$)", re.M)
    pat_js = re.compile(rf"""(?:require\(\s*|from\s+|import\s+)['"]{re.escape(pkg)}(?:/[^'"]*)?['"]""")
    base = Path(target)
    n = 0
    for p in base.rglob("*"):
        if not p.is_file() or p.suffix not in (".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs") or "node_modules" in p.parts:
            continue
        n += 1
        if n > 5000:
            break
        try:
            txt = p.read_text(errors="replace")
        except OSError:
            continue
        if (p.suffix == ".py" and pat_py.search(txt)) or (p.suffix != ".py" and pat_js.search(txt)):
            return str(p.relative_to(base))
    return None


def dependency_vuln(a, target):
    if not target:
        return UNVERIFIED, "no --target directory"
    pkg, fixed = str(a.get("package", "")).lower().replace("_", "-"), a.get("fixed") or a.get("affected_below")
    if not pkg or not fixed:
        return UNVERIFIED, "dependency_vuln needs 'package' and 'fixed' (first fixed version)"
    versions = _lock_versions(target)
    if pkg not in versions:
        return FAIL, f"'{pkg}' is not pinned in any lockfile or requirements file in the target"
    got = versions[pkg]
    if vkey(got) >= vkey(fixed):
        return FAIL, f"{pkg} {got} is at or above the fixed version {fixed}"
    where = _imports(target, pkg)
    if where:
        return PASS, f"{pkg} {got} is below the fixed version {fixed} and is imported directly (e.g. {where})"
    return UNVERIFIED, f"{pkg} {got} is below the fixed version {fixed}, but no direct import was found (may be transitive; reachability not shown)"


PLACEHOLDER = re.compile(r"(?i)(example|sample|dummy|changeme|change_me|your[_-]|xxxx|<[^>]+>|\$\{[^}]+\}|placeholder|redacted|fake|test[_-]?key|1234567890)")
FORMATS = [("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")), ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
           ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")), ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
           ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")), ("stripe-key", re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{20,}\b"))]
ASSIGNED = re.compile(r"""(?i)(pass(?:word|wd)?|pwd|secret|token|api[_-]?key|credential)[\w\"'\]\[]*\s*[:=]\s*[\"']([^\"']{6,})[\"']""")
ENV_READ = re.compile(r"(os\.environ|os\.getenv|process\.env|getenv\(|ENV\[|System\.getenv)")
TESTISH = re.compile(r"(^|/)(tests?|fixtures?|testdata|docs?|examples?|samples?|mocks?)(/|$)|\.md$|_test\.|test_|(^|/)tests?\.py$|conftest")


TESTPATH = re.compile(r"(^|/)(tests?|testing|fixtures?|testdata|mocks?)(/|$)|(^|/)(test_[^/]*|[^/]*_test|tests?|conftest)\.py$")


def production_code(a, target):
    f = str(a.get("file", ""))
    if TESTPATH.search(f.replace("\\", "/")):
        return FAIL, f"{f} is test or fixture code, not code that ships; scanner findings there are not product vulnerabilities"
    return PASS, f"{f} is not a test path"


def entropy(s):
    if not s:
        return 0.0
    return -sum(c / len(s) * math.log2(c / len(s)) for c in (s.count(x) for x in set(s)))


def secret_plausible(a, target):
    if not target:
        return UNVERIFIED, "no --target directory"
    p = safe_join(target, a.get("file", ""))
    if p is None or not p.is_file():
        return FAIL, f"file '{a.get('file')}' does not exist in target"
    lines = p.read_text(errors="replace").splitlines()
    ln = a.get("line")
    if not isinstance(ln, int) or not 1 <= ln <= len(lines):
        return FAIL, f"line {ln} is not in {a.get('file')}"
    text = lines[ln - 1]
    rhs = re.split(r"(?<![=!<>])=(?!=)", text, maxsplit=1)[-1]  # reading from the environment only counts on the right of an assignment
    if ENV_READ.search(rhs):
        return FAIL, "the value is read from the environment, not hardcoded"
    kind = cand = None
    for k, rx in FORMATS:
        m = rx.search(text)
        if m:
            kind, cand = k, m.group(0)
            break
    if cand is None:
        m = re.search(r"""['"]([A-Za-z0-9+/_\-=]{20,})['"]""", text)
        if m and entropy(m.group(1)) >= 3.5 and not PLACEHOLDER.search(m.group(1)):
            kind, cand = "high-entropy-string", m.group(1)
    if cand is None:
        m = ASSIGNED.search(text)
        if m:
            kind, cand = "hardcoded-credential-literal", m.group(2)
    if cand is None:
        return FAIL, "no secret-shaped value on the cited line"
    if PLACEHOLDER.search(cand) or PLACEHOLDER.search(text) and kind in ("high-entropy-string", "hardcoded-credential-literal"):
        return FAIL, "the value looks like a placeholder or documentation example"
    if TESTISH.search(a.get("file", "")):
        return UNVERIFIED, f"{kind} found, but in a test/docs/fixture path; confirm it is not a real credential"
    return PASS, f"a {kind}-shaped value that is not a placeholder is hardcoded (format match only: liveness is NOT verified; rotate if real)"


def s3_public(a, facts):
    b = ((facts.get("s3_buckets") or {}).get(a.get("bucket", "")))
    if b is None:
        return UNVERIFIED, f"bucket '{a.get('bucket')}' not in facts file (facts.s3_buckets)"
    block = b.get("block_public_access") or {}
    all_blocked = all(block.get(k) is True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))
    if all_blocked:
        return FAIL, "all four Block Public Access settings are enabled"
    pol = b.get("policy") or {}
    stmts = pol.get("Statement", [])
    stmts = stmts if isinstance(stmts, list) else [stmts]
    pub_policy = any(s.get("Effect") == "Allow" and (s.get("Principal") == "*" or (isinstance(s.get("Principal"), dict) and "*" in
                     (s["Principal"].get("AWS") if isinstance(s["Principal"].get("AWS"), list) else [s["Principal"].get("AWS")])))
                     and not s.get("Condition") for s in stmts if isinstance(s, dict))
    if b.get("acl_public") is True or pub_policy:
        return PASS, "block-public-access is not fully on and an ACL or policy grants access to everyone"
    return FAIL, "block-public-access is not fully on, but no ACL or policy grants public access"
