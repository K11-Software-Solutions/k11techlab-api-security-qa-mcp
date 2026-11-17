"""K11 Bank: a small API with deliberate OWASP API Top 10 flaws, for k11 API Security QA's demo and tests.

  BOLA          GET /accounts/{id} returns any user's account (PATCH and DELETE check the owner)
  Broken auth   GET /reports is documented as secured but skips the token check
  Mass assign.  POST /users accepts "role" from the client
  Exposure      GET /users/me returns the password hash
  BFLA          DELETE /admin/users/{id} lets any logged-in user delete users (GET /admin/stats is protected)
  CORS          reflects any Origin with Access-Control-Allow-Credentials: true
  Errors        malformed JSON returns a Python traceback with HTTP 500

Run with secure=True (or --secure) and every flaw is fixed, so the tests can prove both directions.

  python demo/bank/server.py --port 8090            tokens: alice-token, bob-token, admin-token
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import threading
import time
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKENS = {"alice-token": "u-alice", "bob-token": "u-bob", "admin-token": "u-admin"}


class Bank:
    def __init__(self, port: int = 0, secure: bool = False):
        self.secure = secure
        self.lock = threading.Lock()
        self.users = {
            "u-alice": {"id": "u-alice", "email": "alice@example.test", "name": "Alice", "role": "customer",
                        "passwordHash": hashlib.sha256(b"alice").hexdigest()},
            "u-bob": {"id": "u-bob", "email": "bob@example.test", "name": "Bob", "role": "customer",
                      "passwordHash": hashlib.sha256(b"bob").hexdigest()},
            "u-admin": {"id": "u-admin", "email": "admin@example.test", "name": "Admin", "role": "admin",
                        "passwordHash": hashlib.sha256(b"admin").hexdigest()},
        }
        self.accounts: dict[str, dict] = {}
        self.hits: dict[str, list[float]] = {}
        bank = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body=None, extra=None):
                data = b"" if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
                self.send_response(code)
                self.send_header("Content-Type", "application/json" if not isinstance(body, bytes) else "text/plain")
                self.send_header("Content-Length", str(len(data)))
                origin = self.headers.get("Origin")
                if origin:
                    if bank.secure:
                        if origin == "https://app.k11bank.test":
                            self.send_header("Access-Control-Allow-Origin", origin)
                    else:  # FLAW: reflects any origin with credentials
                        self.send_header("Access-Control-Allow-Origin", origin)
                        self.send_header("Access-Control-Allow-Credentials", "true")
                if bank.secure:
                    self.send_header("X-Content-Type-Options", "nosniff")
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            def _user(self):
                auth = self.headers.get("Authorization", "")
                return bank.users.get(TOKENS.get(auth[7:], "")) if auth.startswith("Bearer ") else None

            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b"{}"
                return json.loads(raw)

            def _limited(self) -> bool:
                """Secure mode: account reads are limited to 10 per second per token (or client)."""
                if not bank.secure or not (self.command == "GET" and self.path.startswith("/accounts/")):
                    return False
                key = self.headers.get("Authorization") or self.client_address[0]
                now = time.monotonic()
                with bank.lock:
                    recent = [t for t in bank.hits.get(key, []) if now - t < 1.0]
                    recent.append(now)
                    bank.hits[key] = recent
                return len(recent) > 10

            def _route(self, method):
                path = self.path.split("?")[0]
                if self._limited():
                    return self._send(429, {"error": "too many requests"}, {"Retry-After": "1"})
                try:
                    if method == "GET" and path == "/health":
                        return self._send(200, {"status": "ok"})
                    if method == "POST" and path == "/users":
                        body = self._body()
                        uid = "u-" + uuid.uuid4().hex[:8]
                        user = {"id": uid, "email": body.get("email"), "name": body.get("name"), "role": "customer",
                                "passwordHash": hashlib.sha256(str(body.get("password", "")).encode()).hexdigest()}
                        if not bank.secure and "role" in body:      # FLAW: mass assignment
                            user["role"] = body["role"]
                        with bank.lock:
                            bank.users[uid] = user
                        return self._send(201, {k: user[k] for k in ("id", "email", "name", "role")})
                    if method == "DELETE" and (m := re.fullmatch(r"/users/([^/]+)", path)):
                        me = self._user()
                        if not me:
                            return self._send(401, {"error": "unauthorized"})
                        if me["id"] != m.group(1) and me["role"] != "admin":
                            return self._send(403, {"error": "forbidden"})
                        bank.users.pop(m.group(1), None)
                        return self._send(204)
                    if method == "GET" and path == "/reports":
                        me = self._user()
                        if bank.secure and not me:                   # FLAW (insecure mode): no auth check
                            return self._send(401, {"error": "unauthorized"})
                        return self._send(200, {"accounts": len(bank.accounts), "users": len(bank.users)})
                    me = self._user()
                    if not me:
                        return self._send(401, {"error": "unauthorized"})
                    if method == "GET" and path == "/users/me":
                        out = dict(me)
                        if bank.secure:                               # FLAW (insecure mode): password hash returned
                            out.pop("passwordHash")
                        return self._send(200, out)
                    if method == "POST" and path == "/accounts":
                        body = self._body()
                        aid = "acc-" + uuid.uuid4().hex[:8]
                        acc = {"id": aid, "name": str(body.get("name", "Account")), "owner": me["id"], "balance": 0}
                        with bank.lock:
                            bank.accounts[aid] = acc
                        return self._send(201, acc)
                    if (m := re.fullmatch(r"/accounts/([^/]+)", path)):
                        acc = bank.accounts.get(m.group(1))
                        mine = acc is not None and acc["owner"] == me["id"]
                        if method == "GET":
                            if acc is None or (bank.secure and not mine):  # FLAW (insecure mode): BOLA on read
                                return self._send(404, {"error": "not found"})
                            return self._send(200, acc)
                        if acc is None or not mine:
                            return self._send(404, {"error": "not found"})
                        if method == "PATCH":
                            body = self._body()
                            acc["name"] = str(body.get("name", acc["name"]))
                            return self._send(200, acc)
                        if method == "DELETE":
                            bank.accounts.pop(acc["id"], None)
                            return self._send(204)
                    if method == "GET" and path == "/admin/stats":
                        if me["role"] != "admin":
                            return self._send(403, {"error": "forbidden"})
                        return self._send(200, {"users": len(bank.users)})
                    if method == "DELETE" and (m := re.fullmatch(r"/admin/users/([^/]+)", path)):
                        if bank.secure and me["role"] != "admin":     # FLAW (insecure mode): BFLA
                            return self._send(403, {"error": "forbidden"})
                        if m.group(1) not in bank.users:
                            return self._send(404, {"error": "not found"})
                        bank.users.pop(m.group(1), None)
                        return self._send(204)
                    return self._send(404, {"error": "not found"})
                except (ValueError, KeyError):
                    if bank.secure:
                        return self._send(400, {"error": "invalid request"})
                    return self._send(500, traceback.format_exc().encode())   # FLAW: stack trace

            def do_GET(self):  # noqa: N802
                self._route("GET")

            def do_POST(self):  # noqa: N802
                self._route("POST")

            def do_PATCH(self):  # noqa: N802
                self._route("PATCH")

            def do_DELETE(self):  # noqa: N802
                self._route("DELETE")

        if secure:
            H.server_version, H.sys_version = "K11Bank", ""   # no version numbers in the Server header
        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8090)
    ap.add_argument("--secure", action="store_true")
    a = ap.parse_args()
    b = Bank(a.port, a.secure)
    print(f"K11 Bank on {b.url} ({'secure' if a.secure else 'with deliberate flaws'}); tokens: alice-token, bob-token, admin-token")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        b.close()
