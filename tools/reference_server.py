#!/usr/bin/env python3
"""Reference NoEscape panel server (stdlib only) for integration tests and as a protocol spec.

Usage: reference_server.py PORT SECRET [BANNED_HWID ...]
Optional TLS: set NOESCAPE_REF_TLS_CERT and NOESCAPE_REF_TLS_KEY (PEM files) to serve https.

Endpoints (all under /api/ac):
  GET  /check?hwid=H&nonce=N  -> {"banned":bool,"signature":HMAC(secret, "H:0|1:N")}
  POST /heartbeat             -> 200 only if the request is authentic and fresh
  POST /alert                 -> 200 only if the request is authentic and fresh

Request authentication: header "X-NoEscape-Signature" = hex HMAC-SHA256(secret, raw body bytes).
Freshness: body "timestamp" within MAX_SKEW seconds and body "nonce" never seen before.
"""
import hashlib, hmac, json, os, ssl, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PORT = int(sys.argv[1]); SECRET = sys.argv[2].encode(); BANNED = set(sys.argv[3:])
MAX_SKEW = 300
MAX_BODY = 64 * 1024
_seen = {}                # nonce -> expiry (replay cache)
_seen_lock = threading.Lock()


def sign(msg: bytes) -> str:
    return hmac.new(SECRET, msg, hashlib.sha256).hexdigest()


def fresh_nonce(nonce: str) -> bool:
    if not isinstance(nonce, str) or not (16 <= len(nonce) <= 128):
        return False
    now = time.time()
    with _seen_lock:
        for k in [k for k, exp in _seen.items() if exp < now]:
            del _seen[k]
        if nonce in _seen:
            return False
        _seen[nonce] = now + 2 * MAX_SKEW
        return True


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, body):
        data = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True

    def do_GET(self):
        u = urlparse(self.path); q = parse_qs(u.query)
        if not u.path.endswith("/check"):
            return self._send(404, {"error": "not found"})
        hwid = q.get("hwid", [""])[0]; nonce = q.get("nonce", [""])[0]
        if not hwid or not nonce or len(nonce) > 128:
            return self._send(400, {"error": "bad request"})
        flag = "1" if hwid in BANNED else "0"
        self._send(200, {"banned": flag == "1", "signature": sign(f"{hwid}:{flag}:{nonce}".encode())})

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self._send(400, {"error": "bad length"})
        if n <= 0 or n > MAX_BODY:
            return self._send(413, {"error": "body too large"})
        raw = self.rfile.read(n)
        if not hmac.compare_digest(sign(raw), self.headers.get("X-NoEscape-Signature", "")):
            return self._send(403, {"error": "invalid signature"})
        try:
            d = json.loads(raw)
            fresh = abs(time.time() - int(d["timestamp"])) <= MAX_SKEW and fresh_nonce(d.get("nonce"))
        except (ValueError, KeyError, TypeError):
            return self._send(400, {"error": "bad request"})
        if not (self.path.endswith("/heartbeat") or self.path.endswith("/alert")):
            return self._send(404, {"error": "not found"})
        if not fresh:
            return self._send(403, {"error": "stale or replayed request"})
        self._send(200, {"ok": True})


srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)
cert, key = os.environ.get("NOESCAPE_REF_TLS_CERT"), os.environ.get("NOESCAPE_REF_TLS_KEY")
if cert and key:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
