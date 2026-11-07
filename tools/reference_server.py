#!/usr/bin/env python3
"""Reference NoEscape panel server (stdlib only) for integration tests and as a protocol spec.

Usage: reference_server.py PORT SECRET [BANNED_HWID ...]
Optional TLS: set NOESCAPE_REF_TLS_CERT and NOESCAPE_REF_TLS_KEY (PEM files) to serve https.

Endpoints (all under /api/ac):
  GET  /check?hwid=H&nonce=N  -> {"banned":bool,"signature":HMAC(secret, "H:0|1:N")}
  POST /heartbeat             -> 200 only if the request is authentic and fresh
  POST /alert                 -> 200 only if the request is authentic and fresh

Session verdict (for the GAME server, not the client):
  GET  /session?hwid=H        -> {"valid":bool,"reason":str}
       valid only while (a) heartbeats keep arriving (TTL), (b) the last code-attestation answer
       was correct, and (c) when an attestation challenge is outstanding it is answered in time.
       The game server should drop players whose session is not valid.

Code attestation (enabled when NOESCAPE_REF_IMAGE points at the reference build of the client's
executable code, an ELF file): every heartbeat reply carries a signed challenge
{"id","nonce","offset","length","sig"}; the client answers via POST /attest with
HMAC(secret, id:nonce:<those bytes of its first executable PT_LOAD segment>). The server recomputes
the value from the reference image. Reference image notes: ELF only here; for PE builds supply the
expected bytes from your build pipeline.

Request authentication: header "X-NoEscape-Signature" = hex HMAC-SHA256(secret, raw body bytes).
Freshness: body "timestamp" within MAX_SKEW seconds and body "nonce" never seen before.
"""
import hashlib, hmac, json, os, ssl, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PORT = int(sys.argv[1]); SECRET = sys.argv[2].encode(); BANNED = set(sys.argv[3:])
MAX_SKEW = 300
MAX_BODY = 64 * 1024
SESSION_TTL = int(os.environ.get("NOESCAPE_REF_SESSION_TTL", "45"))
ATTEST_DEADLINE = int(os.environ.get("NOESCAPE_REF_ATTEST_DEADLINE", "20"))
CHALLENGE_BYTES = 4096
_seen = {}                # nonce -> expiry (replay cache)
_sessions = {}            # hwid -> dict(last_hb, pending={id,nonce,offset,length,issued}, failed, last_ok)
_challenge_lock = threading.Lock()


def load_reference_code(path):
    """Bytes of the first executable PT_LOAD segment of an ELF64 image (what the client hashes)."""
    import struct
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"\x7fELF" or data[4] != 2:
        raise ValueError("reference image must be an ELF64 file")
    phoff, = struct.unpack_from("<Q", data, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(phnum):
        ptype, flags, off, vaddr, paddr, filesz, memsz, align = struct.unpack_from("<IIQQQQQQ", data, phoff + i * phentsize)
        if ptype == 1 and flags & 1:   # PT_LOAD, PF_X
            seg = data[off:off + filesz]
            return seg + b"\x00" * (memsz - filesz)
    raise ValueError("no executable segment")


REFERENCE_CODE = None
if os.environ.get("NOESCAPE_REF_IMAGE"):
    REFERENCE_CODE = load_reference_code(os.environ["NOESCAPE_REF_IMAGE"])
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
        hwid = q.get("hwid", [""])[0]; nonce = q.get("nonce", [""])[0]
        if u.path.endswith("/session"):
            return self._session(hwid)
        if not u.path.endswith("/check"):
            return self._send(404, {"error": "not found"})
        if not hwid or not nonce or len(nonce) > 128:
            return self._send(400, {"error": "bad request"})
        flag = "1" if hwid in BANNED else "0"
        self._send(200, {"banned": flag == "1", "signature": sign(f"{hwid}:{flag}:{nonce}".encode())})

    def _session(self, hwid):
        now = time.time()
        with _challenge_lock:
            st = _sessions.get(hwid)
            if not st:
                return self._send(200, {"valid": False, "reason": "no heartbeat"})
            if now - st["last_hb"] > SESSION_TTL:
                return self._send(200, {"valid": False, "reason": "heartbeat expired"})
            if st["failed"]:
                return self._send(200, {"valid": False, "reason": "attestation failed"})
            pend = st["pending"]
            if pend and now - pend["issued"] > ATTEST_DEADLINE + 10:
                return self._send(200, {"valid": False, "reason": "attestation unanswered"})
        self._send(200, {"valid": True, "reason": "ok"})

    def _issue_challenge(self, hwid, hb_nonce):
        if REFERENCE_CODE is None:
            return None
        import secrets
        cid = secrets.token_hex(8)
        nonce = secrets.token_hex(16)
        length = min(CHALLENGE_BYTES, len(REFERENCE_CODE))
        offset = secrets.randbelow(len(REFERENCE_CODE) - length + 1)
        sig = sign(f"challenge:{hwid}:{hb_nonce}:{cid}:{nonce}:{offset}:{length}".encode())
        with _challenge_lock:
            st = _sessions[hwid]
            st["pending"] = {"id": cid, "nonce": nonce, "offset": offset, "length": length, "issued": time.time()}
        return {"id": cid, "nonce": nonce, "offset": offset, "length": length, "sig": sig}

    def _attest(self, hwid, d):
        cid = d.get("challenge_id"); answer = d.get("answer", "")
        with _challenge_lock:
            st = _sessions.get(hwid)
            pend = st and st["pending"]
            if not pend or pend["id"] != cid:
                return False
            st["pending"] = None                      # single use
            if time.time() - pend["issued"] > ATTEST_DEADLINE:
                st["failed"] = True
                return False
            code = REFERENCE_CODE[pend["offset"]:pend["offset"] + pend["length"]]
            expected = hmac.new(SECRET, f'{pend["id"]}:{pend["nonce"]}:'.encode() + code, hashlib.sha256).hexdigest()
            ok = hmac.compare_digest(expected, answer)
            if ok:
                st["last_ok"] = time.time()
            else:
                st["failed"] = True
            return ok

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
        if not (self.path.endswith("/heartbeat") or self.path.endswith("/alert") or self.path.endswith("/attest")):
            return self._send(404, {"error": "not found"})
        if not fresh:
            return self._send(403, {"error": "stale or replayed request"})
        hwid = str(d.get("hwid", ""))[:128]
        if self.path.endswith("/heartbeat"):
            with _challenge_lock:
                st = _sessions.setdefault(hwid, {"last_hb": 0, "pending": None, "failed": False, "last_ok": 0})
                st["last_hb"] = time.time()
            ch = self._issue_challenge(hwid, str(d.get("nonce", "")))
            return self._send(200, {"ok": True, "challenge": ch} if ch else {"ok": True})
        if self.path.endswith("/attest"):
            ok = self._attest(hwid, d)
            return self._send(200 if ok else 403, {"ok": ok})
        self._send(200, {"ok": True})


srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)
cert, key = os.environ.get("NOESCAPE_REF_TLS_CERT"), os.environ.get("NOESCAPE_REF_TLS_KEY")
if cert and key:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
