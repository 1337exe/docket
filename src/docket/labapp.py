"""A deliberately vulnerable toy web app for testing docket. Binds to 127.0.0.1 only.

NEVER expose this to a network. Some endpoints are really vulnerable (marked VULN); others look
suspicious but are safe (marked SAFE), so a good validator must tell them apart.
"""
import base64
import html
import json
import os
import re
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

ORDERS = {"1": ("user1", "ORDER-1-SECRET"), "2": ("user2", "ORDER-2-SECRET")}
REDEEMED, LOGIN_TRIES = set(), {}
USERS = [{"name": "alice", "secret": "S-ALICE"}, {"name": "bob", "secret": "S-BOB"}]


class Lab(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, ctype="text/plain", headers=None):
        data = body.encode()
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        user = self.headers.get("X-User", "")
        path = u.path
        if path == "/fetch":  # VULN: server-side request forgery
            url = q.get("url", "")
            if not url.startswith(("http://", "https://")):
                return self.send(400, "bad url")
            try:
                with urllib.request.urlopen(url, timeout=3) as r:
                    return self.send(200, r.read(200).decode("utf-8", "replace"))
            except Exception:
                return self.send(502, "fetch failed")
        if path == "/render":  # VULN: template expressions are evaluated
            t = q.get("t", "")
            return self.send(200, re.sub(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}", lambda m: str(int(m[1]) * int(m[2])), t))
        if path == "/search":  # VULN: boolean-based injection
            term = q.get("q", "")
            m = re.match(r"^(.*)' AND '1'='(\d)$", term)
            name, cond = (m[1], m[2] == "1") if m else (term, True)
            rows = [r for r in USERS if r["name"] == name] if cond else []
            return self.send(200, ",".join(r["secret"] for r in rows) or "no results")
        if path.startswith("/orders/"):  # VULN: no ownership check (IDOR)
            oid = path.rsplit("/", 1)[-1]
            return self.send(200, ORDERS[oid][1]) if oid in ORDERS else self.send(404, "none")
        if path.startswith("/profile/"):  # SAFE: ownership enforced
            pid = path.rsplit("/", 1)[-1]
            if pid in ORDERS and ORDERS[pid][0] == user:
                return self.send(200, ORDERS[pid][1])
            return self.send(403, "forbidden")
        if path == "/legacy/export":  # VULN: forgot authentication
            return self.send(200, "LEGACY-EXPORT-ROWS")
        if path == "/admin/panel":  # SAFE: token required
            if self.headers.get("X-Token") == "s3cr3t":
                return self.send(200, "ADMIN-PANEL")
            return self.send(401, "login required")
        if path == "/echo":  # SAFE: output is escaped
            return self.send(200, "<p>" + html.escape(q.get("q", "")) + "</p>", "text/html")
        if path == "/lookup":  # SAFE: errors on bad input but is not injectable
            try:
                return self.send(200, f"row-{int(q.get('id', ''))}")
            except ValueError:
                return self.send(500, "ValueError: invalid literal for int()")
        if path == "/file":  # VULN: path traversal (the toy 'filesystem' has /etc/passwd)
            name = q.get("name", "")
            return self.send(200, "root:x:0:0:root:/root:/bin/sh" if ".." in name else f"public file {name}")
        if path == "/file-safe":  # SAFE: only the base name is used
            name = os.path.basename(q.get("name", ""))
            return self.send(200, f"public file {name}")
        if path == "/go":  # VULN: open redirect
            return self.send(302, "", headers={"Location": q.get("next", "/")})
        if path == "/go-safe":  # SAFE: only local paths are allowed
            nxt = q.get("next", "/")
            ok = nxt.startswith("/") and not nxt.startswith("//") and "\\" not in nxt
            return self.send(302, "", headers={"Location": nxt if ok else "/home"})
        if path == "/api/account":  # VULN: reflects any Origin and allows credentials
            o = self.headers.get("Origin", "")
            return self.send(200, "ACCOUNT-DATA", headers={"Access-Control-Allow-Origin": o, "Access-Control-Allow-Credentials": "true"})
        if path == "/api/public":  # SAFE: wildcard origin, no credentials, public data
            return self.send(200, "PUBLIC-DATA", headers={"Access-Control-Allow-Origin": "*"})
        if path in ("/jwt/me", "/jwt/me-safe"):
            tok = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
            try:
                head = json.loads(base64.urlsafe_b64decode(tok.split(".")[0] + "=="))
            except Exception:
                return self.send(401, "bad token")
            if path == "/jwt/me" and head.get("alg") == "none":  # VULN: accepts unsigned tokens
                return self.send(200, "ADMIN-DATA")
            return self.send(401, "signature required")  # SAFE branch: signature is always required
        if path == "/ping":  # VULN: command injection (simulated, nothing is executed)
            h = q.get("host", "")
            return self.send(200, "PING ok" + ("\nuid=0(root) gid=0(root)" if re.search(r"[;|&`$]", h) else ""))
        if path == "/ping-safe":  # SAFE: argument list, no shell (simulated)
            return self.send(200, "PING ok")
        if path == "/coupon/redeem":  # VULN: a coupon can be redeemed again and again
            return self.send(200, "REDEEMED")
        if path == "/coupon/redeem-once":  # SAFE: second use is refused
            c = q.get("c", "")
            if c in REDEEMED:
                return self.send(409, "ALREADY-USED")
            REDEEMED.add(c)
            return self.send(200, "REDEEMED")
        if path == "/login":  # VULN: no lockout, no throttling
            return self.send(401, "invalid credentials")
        if path == "/login-safe":  # SAFE: throttles after 5 tries
            n = LOGIN_TRIES[self.client_address[0]] = LOGIN_TRIES.get(self.client_address[0], 0) + 1
            return self.send(429 if n > 5 else 401, "slow down" if n > 5 else "invalid credentials")
        if path == "/health":
            return self.send(200, "")
        self.send(404, "not found")


Lab.do_POST = Lab.do_GET


def make_server(port=0):
    return ThreadingHTTPServer(("127.0.0.1", port), Lab)


if __name__ == "__main__":
    srv = make_server(8099)
    print("lab listening on http://127.0.0.1:8099 (localhost only)")
    srv.serve_forever()
