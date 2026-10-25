"""Out-of-band canary: a tiny HTTP listener that records who calls it.

SSRF, blind injection and command-execution claims are only real if the target calls *us* with a
nonce nobody else knew. The court mints the nonce, so a model cannot fake it.
"""
from __future__ import annotations

import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def read_hits(logfile, nonce):
    if not nonce or len(str(nonce)) < 6:  # short nonces are guessable: refuse to match them
        return []
    hits = []
    try:
        with open(logfile, encoding="utf-8") as fh:
            for line in fh:
                try:
                    h = json.loads(line)
                except ValueError:
                    continue
                if str(nonce) in str(h.get("path", "")):
                    hits.append(h)
    except OSError:
        pass
    return hits


class Canary:
    def __init__(self, logfile, host="127.0.0.1", port=0, public_url=None):
        self.logfile, self.host, self.port, self.public_url = logfile, host, port, public_url
        self._lock, self._srv = threading.Lock(), None

    def start(self):
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                rec = {"t": time.time(), "path": self.path[:300], "ip": self.client_address[0],
                       "ua": (self.headers.get("User-Agent") or "")[:120]}
                with outer._lock, open(outer.logfile, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(rec) + "\n")
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            do_POST = do_HEAD = do_PUT = do_GET

        self._srv = ThreadingHTTPServer((self.host, self.port), H)
        self.port = self._srv.server_address[1]
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    @property
    def base(self):
        return (self.public_url or f"http://{self.host}:{self.port}").rstrip("/")

    def new_nonce(self):
        return secrets.token_hex(8)

    def url_for(self, nonce):
        return f"{self.base}/c/{nonce}"

    def hits(self, nonce):
        return read_hits(self.logfile, nonce)

    def wait_for(self, nonce, seconds=3.0):
        end = time.time() + seconds
        while time.time() < end:
            h = self.hits(nonce)
            if h:
                return h
            time.sleep(0.1)
        return []

    def stop(self):
        if self._srv:
            self._srv.shutdown()
