"""Live probes: the court re-tests a claim itself instead of trusting the finder's story.

Only hosts listed in scope.active_hosts are ever contacted, redirects are not followed, bodies are
capped. Intended for your own infrastructure / authorised targets only.
"""
from __future__ import annotations

import re
import urllib.error
import urllib.parse
import urllib.request

from .models import FAIL, PASS, UNVERIFIED

MAX_BODY = 65536


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def _request(method, url, headers, body, timeout, with_headers=False):
    req = urllib.request.Request(url, data=body.encode() if isinstance(body, str) else None, method=method,
                                 headers={str(k): str(v) for k, v in (headers or {}).items()})
    try:
        with _opener.open(req, timeout=timeout) as r:
            out = (r.status, r.read(MAX_BODY).decode("utf-8", "replace"), dict(r.headers.items()))
    except urllib.error.HTTPError as e:
        out = (e.code, e.read(MAX_BODY).decode("utf-8", "replace"), dict(e.headers.items()))
    return out if with_headers else out[:2]


def probe_cost(p):
    k = p.get("kind")
    return min(int(p.get("n", 20)), 50) if k == "repeat_probe" else len(p.get("steps") or []) if k == "sequence_probe" else 3 if k == "boolean_probe" else 1


def _gate(p, scope):
    url = p.get("url", "")
    u = urllib.parse.urlparse(url.replace("{canary}", "x").replace("{p}", "x"))
    if u.scheme not in ("http", "https") or not u.hostname:
        return "probe url must be http(s)"
    if not scope.host_allowed(u.hostname):
        return f"host '{u.hostname}' is not in scope.active_hosts"
    if str(p.get("method", "GET")).upper() not in ("GET", "HEAD", "POST"):
        return "only GET, HEAD and POST probes are allowed"
    return None


def run_probe(p, scope, canary=None, timeout=5.0):
    kind = p.get("kind", "")
    why = None if kind == "sequence_probe" else _gate(p, scope)
    if why:
        return UNVERIFIED if "scope.active_hosts" in why or "not in" in why else FAIL, why
    method = str(p.get("method", "GET")).upper()
    try:
        if kind == "http_probe":
            status, body, hdrs = _request(method, p["url"], p.get("headers"), p.get("body"), timeout, True)
            want = p.get("expect_status")
            if want is not None and status not in (want if isinstance(want, list) else [want]):
                return FAIL, f"expected status {want}, got {status}"
            rx, bad = p.get("expect_body_regex"), p.get("expect_absent_regex")
            if rx and not re.search(rx, body):
                return FAIL, f"status {status}, but the expected content was not in the response"
            if bad and re.search(bad, body):
                return FAIL, "response contained content that should be absent"
            low = {k.lower(): v for k, v in hdrs.items()}
            for name, rx in (p.get("expect_headers") or {}).items():
                if not re.search(str(rx), low.get(str(name).lower(), "")):
                    return FAIL, f"header {name} did not match the expected value"
            for name in p.get("expect_absent_headers") or []:
                if str(name).lower() in low:
                    return FAIL, f"header {name} is present but should be absent"
            return PASS, f"live probe matched expectations (status {status})"
        if kind == "repeat_probe":
            n = min(int(p.get("n", 20)), 50)
            statuses = [_request(method, p["url"], p.get("headers"), p.get("body"), timeout)[0] for _ in range(n)]
            bad = [x for x in (p.get("expect_no_status") or [429, 423]) if x in statuses]
            want = p.get("expect_status")
            if bad:
                return FAIL, f"the server throttled or locked out ({bad[0]}) within {n} attempts"
            if want is not None and any(x != want for x in statuses):
                return FAIL, f"responses were not uniformly {want} (saw {sorted(set(statuses))})"
            return PASS, f"{n} rapid attempts were never throttled (statuses {sorted(set(statuses))})"
        if kind == "sequence_probe":
            steps = p.get("steps") or []
            if not 2 <= len(steps) <= 10:
                return FAIL, "sequence_probe needs 2 to 10 steps"
            for i, st in enumerate(steps, 1):
                stt = {**st, "kind": "http_probe"}
                host_why = _gate(stt, scope)
                if host_why:
                    return UNVERIFIED, f"step {i}: {host_why}"
                status, why = run_probe(stt, scope, canary, timeout)
                if status != PASS:
                    return status, f"step {i} of {len(steps)} did not match: {why}"
            return PASS, f"all {len(steps)} steps in order matched (the forbidden sequence is possible)"
        if kind == "boolean_probe":
            url = p["url"]
            bodies = {}
            for k in ("baseline", "true", "false"):
                bodies[k] = _request(method, url.replace("{p}", urllib.parse.quote(str(p.get(k, "")), safe="")),
                                     p.get("headers"), p.get("body"), timeout)[1]
            if bodies["true"] == bodies["baseline"] and bodies["false"] != bodies["baseline"]:
                return PASS, "true condition matches baseline, false condition differs"
            return FAIL, "responses do not differ between true and false conditions"
        if kind == "ssrf_probe":
            if canary is None:
                return UNVERIFIED, "no canary listener available"
            nonce = canary.new_nonce()
            url = p["url"].replace("{canary}", urllib.parse.quote(canary.url_for(nonce), safe=""))
            _request(method, url, p.get("headers"), p.get("body"), timeout)
            hits = canary.wait_for(nonce, float(p.get("wait", 3)))
            if hits:
                return PASS, f"target called the canary (nonce {nonce}) from {hits[0].get('ip')}"
            return FAIL, "target never called the canary"
    except (OSError, KeyError, ValueError) as e:
        return UNVERIFIED, f"probe could not run: {type(e).__name__}"
    return UNVERIFIED, f"unknown probe kind '{kind}'"
