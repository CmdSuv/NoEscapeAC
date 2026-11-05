#!/usr/bin/env python3
"""Reference NoEscape panel server (stdlib only) for integration tests and as a protocol spec.

Usage: reference_server.py PORT SECRET [BANNED_HWID ...]
Endpoints (all under /api/ac):
  GET  /check?hwid=H&nonce=N  -> {"banned":bool,"signature":HMAC(secret, "H:0|1:N")}
  POST /heartbeat             -> 200 only if HMAC(secret,"hwid:timestamp:threat_score:status") is valid
  POST /alert                 -> 200 only if HMAC(secret,"hwid:timestamp:type:details") is valid
NOTE: plain HTTP. Deploy behind TLS; the C++ client has no TLS support yet.
"""
import hashlib, hmac, json, sys, time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

PORT = int(sys.argv[1]); SECRET = sys.argv[2].encode(); BANNED = set(sys.argv[3:])
MAX_SKEW = 300

def sign(msg: str) -> str:
    return hmac.new(SECRET, msg.encode(), hashlib.sha256).hexdigest()

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, body):
        data = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data))); self.send_header("Connection", "close")
        self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        u = urlparse(self.path); q = parse_qs(u.query)
        if not u.path.endswith("/check"): return self._send(404, {"error": "not found"})
        hwid = q.get("hwid", [""])[0]; nonce = q.get("nonce", [""])[0]
        if not hwid or not nonce: return self._send(400, {"error": "bad request"})
        flag = "1" if hwid in BANNED else "0"
        self._send(200, {"banned": flag == "1", "signature": sign(f"{hwid}:{flag}:{nonce}")})
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        try: d = json.loads(self.rfile.read(n))
        except Exception: return self._send(400, {"error": "bad json"})
        try:
            if self.path.endswith("/heartbeat"):
                msg = f'{d["hwid"]}:{d["timestamp"]}:{d["threat_score"]}:{d["status"]}'
            elif self.path.endswith("/alert"):
                msg = f'{d["hwid"]}:{d["timestamp"]}:{d["type"]}:{d["details"]}'
            else: return self._send(404, {"error": "not found"})
            ok = hmac.compare_digest(sign(msg), d.get("signature", ""))
            fresh = abs(time.time() - int(d["timestamp"])) <= MAX_SKEW
        except KeyError: return self._send(400, {"error": "missing field"})
        if ok and fresh: return self._send(200, {"ok": True})
        self._send(403, {"error": "invalid signature or stale timestamp"})

HTTPServer(("127.0.0.1", PORT), H).serve_forever()
