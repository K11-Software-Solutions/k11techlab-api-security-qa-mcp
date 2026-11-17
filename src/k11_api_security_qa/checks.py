"""OWASP API Security Top 10 (2023) checks, generated from the spec and run against a test environment.

  auth             API2  every secured operation must reject missing and invalid credentials
  bola             API1  another user must not read, change or delete the owner's object
  bfla             API5  normal users must not call admin-only operations
  mass_assignment  API3  privileged fields sent by a client (role, isAdmin, price...) must be ignored
  data_exposure    API3  responses must not carry secrets, or fields the spec doesn't document
  headers          API8  CORS that trusts any origin with credentials; missing hardening headers
  errors           API8  malformed input must not produce stack traces or server errors
  rate_limit       API4  repeated requests should eventually be throttled (opt-in)

Each test records its request (credentials masked), the response status and a short body excerpt
as evidence. A control request proves a test meant something: if the owner can't read their own
object, the cross-user result is "inconclusive", not "passed".
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urljoin, urlsplit

import httpx
from k11_api_qa import auth as authmod
from k11_api_qa.config import Config as ApiConfig, writes_allowed
from k11_api_qa.generate import example
from k11_api_qa.values import Vars, json_path
from k11_contract_qa.spec import Operation, Spec, json_schema_of, norm_path, resolve, success_response

from .config import INJECT, SENSITIVE, SecurityConfig

SAFE = {"GET", "HEAD", "OPTIONS"}
STACK = re.compile(r"Traceback \(most recent call last\)|\bat [\w$.]+\([\w$]+\.java:\d+\)|Exception in thread|"
                   r"System\.[A-Za-z]+Exception|SQLSTATE|ORA-\d{5}|psycopg|sqlite3\.|ActiveRecord::|"
                   r"node_modules[\\/]|\bat Object\.<anonymous>|stack trace", re.I)
EVIL_ORIGIN = "https://k11-evil.example"


@dataclass
class Finding:
    id: str            # OWASP category, e.g. "API1:2023"
    check: str
    title: str
    severity: str      # critical | high | medium | low | info
    endpoint: str = ""
    identity: str = ""
    evidence: dict = field(default_factory=dict)
    fix: str = ""
    source: str = "api"


@dataclass
class TestResult:
    check: str
    endpoint: str
    name: str
    outcome: str       # passed | failed | inconclusive | not_run
    detail: str = ""


class Client:
    """Requests as an identity, always on the environment's host, secrets masked in evidence."""

    def __init__(self, api_cfg: ApiConfig, env_name: str, env: dict, base_url: str, sec: SecurityConfig):
        self.api_cfg, self.env_name, self.env, self.base = api_cfg, env_name, env, base_url.rstrip("/") + "/"
        self.sec = sec
        self.vars = Vars({"env": {"name": env_name, "base_url": base_url}})
        self.http = httpx.Client(timeout=api_cfg.timeout_s, follow_redirects=False)
        self.writes, self.writes_why = writes_allowed(env_name, env, base_url)
        self._headers: dict[str, dict] = {}

    def close(self):
        self.http.close()

    def headers_for(self, identity: str | None) -> dict[str, str]:
        if identity is None:
            return {}
        if identity not in self._headers:
            prof = (self.sec.identities.get(identity) or {}).get("auth", identity)
            self._headers[identity] = authmod.headers(prof, self.api_cfg.auth, self.vars, self.api_cfg.timeout_s)
        return dict(self._headers[identity])

    def request(self, method: str, path: str, identity: str | None, json_body: Any = None, raw_body: bytes | None = None,
                extra_headers: dict | None = None, query: dict | None = None) -> tuple[httpx.Response | None, dict]:
        url = urljoin(self.base, path.lstrip("/"))
        if urlsplit(url).netloc.lower() != urlsplit(self.base).netloc.lower():
            raise ValueError(f"Request must stay on {urlsplit(self.base).netloc}")
        hdrs = self.headers_for(identity)
        hdrs.update(extra_headers or {})
        kwargs: dict[str, Any] = {"headers": hdrs}
        if query:
            kwargs["params"] = query
        if raw_body is not None:
            kwargs["content"] = raw_body
            hdrs.setdefault("Content-Type", "application/json")
        elif json_body is not None:
            kwargs["json"] = json_body
        ev = {"request": f"{method} {path}", "as": identity or "anonymous",
              **({"body": self.vars.mask(json_body)} if json_body is not None else {})}
        try:
            r = self.http.request(method, url, **kwargs)
        except httpx.HTTPError as e:
            ev["error"] = f"{type(e).__name__}: {str(e)[:150]}"
            return None, ev
        ev["status"] = r.status_code
        ev["response"] = self.vars.mask(r.text[:300])
        return r, ev


def _json(r: httpx.Response | None) -> Any:
    try:
        return r.json() if r is not None else None
    except ValueError:
        return None


def _fill_path(template: str, values: dict[str, str]) -> str:
    out = template
    for name in re.findall(r"\{([^}]+)\}", template):
        out = out.replace("{" + name + "}", quote(str(values.get(name, "k11-probe-id")), safe=""))
    return out


def _body_for(spec: Spec, op: Operation) -> Any:
    rb = resolve(spec.raw, op.request_body) if op.request_body else None
    schema = json_schema_of((rb or {}).get("content")) if rb else None
    return example(resolve(spec.raw, schema)) if schema is not None else None


def _secured(op: Operation) -> bool:
    return bool(op.security) and not any(s == {} for s in (op.security or []))


def _ok(r: httpx.Response | None) -> bool:
    return r is not None and 200 <= r.status_code < 300


def _denied(r: httpx.Response | None) -> bool:
    return r is not None and r.status_code in (401, 403, 404)


class Run:
    def __init__(self, client: Client, spec: Spec, sec: SecurityConfig):
        self.c, self.spec, self.sec = client, spec, sec
        self.findings: list[Finding] = []
        self.tests: list[TestResult] = []
        self.owned: dict[str, dict[str, str]] = {}   # norm path -> {param: id}
        self.cleanup: list[tuple[str, str]] = []
        self.responses: list[tuple[str, Any, Operation]] = []  # (endpoint, json, op) seen as the owner
        self.owner, self.others = sec.owner_and_others()
        self.admin = sec.admin_identity()

    def test(self, check, endpoint, name, outcome, detail=""):
        self.tests.append(TestResult(check, endpoint, name, outcome, detail))

    # ---- resources -----------------------------------------------------------------------------
    def setup_resources(self) -> None:
        for path, spec in self.sec.resources.items():
            names = re.findall(r"\{([^}]+)\}", path)
            if not names:
                continue
            if spec.get("id") is not None:
                self.owned[norm_path(path)] = {names[-1]: str(spec["id"])}
                continue
            create = spec.get("create") or {}
            if not create.get("call"):
                continue
            method, _, cpath = str(create["call"]).partition(" ")
            if method.upper() not in SAFE and not self.c.writes:
                self.test("setup", path, "create a test resource", "not_run", f"writes refused: {self.c.writes_why}")
                continue
            body = self.c.vars.sub(create.get("body")) if create.get("body") is not None else None
            r, ev = self.c.request(method.upper(), cpath.strip(), spec.get("owner") or self.owner, json_body=body)
            found, value = json_path(_json(r), create.get("save", "$.id")) if _ok(r) else (False, None)
            if not found:
                self.test("setup", path, "create a test resource", "inconclusive",
                          f"{create['call']} as {spec.get('owner') or self.owner} gave {ev.get('status', ev.get('error'))}")
                continue
            self.owned[norm_path(path)] = {names[-1]: str(value)}
            if create.get("delete", True):
                self.cleanup.append((spec.get("owner") or self.owner, _fill_path(path, {names[-1]: str(value)})))

    def ids_for(self, op: Operation) -> dict[str, str] | None:
        """Ids of an owned object usable in this operation's path (exact path, or a path ending the same way)."""
        key = norm_path(op.path)
        if key in self.owned:
            return self.owned[key]
        names = re.findall(r"\{([^}]+)\}", op.path)
        for path, ids in self.owned.items():
            if key.startswith(path.rsplit("/{}", 1)[0]) and path.count("{}") == key.count("{}"):
                return {names[-1]: next(iter(ids.values()))} if names else ids
        return None

    def teardown(self) -> None:
        for identity, path in reversed(self.cleanup):
            if self.c.writes:
                self.c.request("DELETE", path, identity)

    # ---- API2: broken authentication ----------------------------------------------------------
    def check_auth(self) -> None:
        for op in self.spec.operations.values():
            ep = op.key
            if not _secured(op):
                if op.method.upper() not in SAFE:
                    self.findings.append(Finding("API2:2023", "auth", "Data-changing operation documented without authentication",
                                                 "info", ep, fix="Confirm this is intended (e.g. sign-up); otherwise add a security requirement to the spec and the API."))
                continue
            if op.method.upper() not in SAFE and not self.c.writes:
                self.test("auth", ep, "rejects missing credentials", "not_run", "writes refused on this environment")
                continue
            path = _fill_path(op.path, self.ids_for(op) or {})
            body = _body_for(self.spec, op) if op.method.upper() not in SAFE else None
            for label, hdrs in (("no credentials", None), ("invalid token", {"Authorization": "Bearer k11-invalid-token"})):
                r, ev = self.c.request(op.method.upper(), path, None, json_body=body, extra_headers=hdrs)
                if r is None:
                    self.test("auth", ep, f"rejects {label}", "inconclusive", ev.get("error", ""))
                elif r.status_code in (401, 403):
                    self.test("auth", ep, f"rejects {label}", "passed", f"HTTP {r.status_code}")
                elif r.status_code == 404 and not self.ids_for(op) and "{" in op.path:
                    self.test("auth", ep, f"rejects {label}", "inconclusive", "404 for a probe id; can't tell if auth ran first")
                elif r.status_code >= 500:
                    self.test("auth", ep, f"rejects {label}", "failed", f"HTTP {r.status_code}")
                    self.findings.append(Finding("API8:2023", "auth", f"Server error when called with {label}", "medium", ep,
                                                 evidence=ev, fix="Authenticate before any other processing; return 401."))
                else:
                    self.test("auth", ep, f"rejects {label}", "failed", f"HTTP {r.status_code}")
                    sev = "critical" if op.method.upper() not in SAFE else "high"
                    self.findings.append(Finding("API2:2023", "auth", f"Accepts a request with {label}", sev, ep, evidence=ev,
                                                 fix="Require valid credentials on this operation (the spec says it is secured)."))

    # ---- API1: broken object level authorization ----------------------------------------------
    def check_bola(self) -> None:
        if not self.owner or not self.others:
            self.test("bola", "*", "cross-user access", "not_run", "needs two normal identities (e.g. alice and bob)")
            return
        ops = [op for op in self.spec.operations.values() if "{" in op.path and not self.sec.is_admin_path(op.path)]
        order = {"GET": 0, "HEAD": 0, "PUT": 1, "PATCH": 1, "POST": 1, "DELETE": 2}
        for op in sorted(ops, key=lambda o: order.get(o.method.upper(), 1)):
            ep, m = op.key, op.method.upper()
            ids = self.ids_for(op)
            if not ids:
                self.test("bola", ep, "another user can't reach the owner's object", "not_run",
                          f"no test resource for {op.path} (add it under resources:)")
                continue
            if m not in SAFE and not self.c.writes:
                self.test("bola", ep, "another user can't change the owner's object", "not_run", "writes refused on this environment")
                continue
            path = _fill_path(op.path, ids)
            if m in SAFE:
                r, ev = self.c.request(m, path, self.owner)
                if not _ok(r):
                    self.test("bola", ep, "another user can't read the owner's object", "inconclusive",
                              f"control failed: the owner ({self.owner}) got {ev.get('status', ev.get('error'))}")
                    continue
                self.responses.append((ep, _json(r), op))
            body = _body_for(self.spec, op) if m not in SAFE and m != "DELETE" else None
            for other in self.others:
                r2, ev2 = self.c.request(m, path, other, json_body=body)
                if r2 is None:
                    self.test("bola", ep, f"{other} can't reach {self.owner}'s object", "inconclusive", ev2.get("error", ""))
                elif _denied(r2):
                    self.test("bola", ep, f"{other} can't reach {self.owner}'s object", "passed", f"HTTP {r2.status_code}")
                elif _ok(r2):
                    self.test("bola", ep, f"{other} can't reach {self.owner}'s object", "failed", f"HTTP {r2.status_code}")
                    verb = {"GET": "read", "HEAD": "read", "DELETE": "delete"}.get(m, "change")
                    self.findings.append(Finding(
                        "API1:2023", "bola", f"{other} can {verb} an object that belongs to {self.owner}",
                        "high" if verb == "read" else "critical", ep, other, ev2,
                        "Check that the caller owns (or may access) the object on every request, not just that they are logged in."))
                    if m == "DELETE":
                        self.setup_resources()  # the object is gone; recreate for later checks
                else:
                    self.test("bola", ep, f"{other} can't reach {self.owner}'s object", "inconclusive", f"HTTP {r2.status_code}")

    # ---- API5: broken function level authorization --------------------------------------------
    def check_bfla(self) -> None:
        admin_ops = [op for op in self.spec.operations.values() if self.sec.is_admin_path(op.path, op.meta.get("tags"))]
        users = [i for i in [self.owner, *self.others] if i]
        if not admin_ops or not users:
            return
        for op in admin_ops:
            ep, m = op.key, op.method.upper()
            if m not in SAFE and not self.c.writes:
                self.test("bfla", ep, "normal users can't call it", "not_run", "writes refused on this environment")
                continue
            path = _fill_path(op.path, self.ids_for(op) or {})
            body = _body_for(self.spec, op) if m not in SAFE and m != "DELETE" else None
            r, ev = self.c.request(m, path, users[0], json_body=body)
            if r is None:
                self.test("bfla", ep, "normal users can't call it", "inconclusive", ev.get("error", ""))
            elif r.status_code in (401, 403):
                self.test("bfla", ep, "normal users can't call it", "passed", f"HTTP {r.status_code}")
            elif _ok(r) or (r.status_code == 404 and m == "DELETE"):
                self.test("bfla", ep, "normal users can't call it", "failed", f"HTTP {r.status_code}")
                self.findings.append(Finding("API5:2023", "bfla", f"Admin-only operation callable by a normal user ({users[0]})",
                                             "critical" if m not in SAFE else "high", ep, users[0], ev,
                                             "Check the caller's role in the operation itself, not only in the UI."))
            else:
                self.test("bfla", ep, "normal users can't call it", "inconclusive", f"HTTP {r.status_code}")

    # ---- API3: mass assignment ----------------------------------------------------------------
    def check_mass_assignment(self) -> None:
        if not self.owner:
            return
        for op in self.spec.operations.values():
            m = op.method.upper()
            if m not in ("POST", "PUT", "PATCH") or self.sec.is_admin_path(op.path):
                continue
            ep = op.key
            body = _body_for(self.spec, op)
            if not isinstance(body, dict):
                continue
            if not self.c.writes:
                self.test("mass_assignment", ep, "privileged fields are ignored", "not_run", "writes refused on this environment")
                continue
            if "{" in op.path and not self.ids_for(op):
                self.test("mass_assignment", ep, "privileged fields are ignored", "not_run", f"no test resource for {op.path}")
                continue
            rb = resolve(self.spec.raw, op.request_body) or {}
            req_props = set(((resolve(self.spec.raw, json_schema_of(rb.get("content")) or {})) or {}).get("properties", {}))
            sr = success_response(op)
            resp_schema = resolve(self.spec.raw, json_schema_of((resolve(self.spec.raw, sr[1]) or {}).get("content"))) if sr else None
            resp_props = (resp_schema or {}).get("properties", {}) if isinstance(resp_schema, dict) else {}
            inject = {k: v for k, v in INJECT.items() if k not in req_props}
            for k, p in resp_props.items():   # documented response fields the client isn't meant to send
                p = resolve(self.spec.raw, p) or {}
                if k not in req_props and k not in inject and k.lower() not in ("id",) and p.get("type") in ("string", "boolean", "number", "integer"):
                    inject[k] = {"string": "k11-injected", "boolean": True, "number": 0.01, "integer": 999999}[p["type"]]
            path = _fill_path(op.path, self.ids_for(op) or {})
            r, ev = self.c.request(m, path, self.owner, json_body={**body, **inject})
            if not _ok(r):
                self.test("mass_assignment", ep, "privileged fields are ignored", "inconclusive",
                          f"request with extra fields gave {ev.get('status', ev.get('error'))}" +
                          ("" if r is None or r.status_code < 500 else " (a 5xx: extra fields crash the API)"))
                continue
            doc = _json(r)
            if isinstance(doc, dict) and m == "POST" and doc.get("id") is not None:
                self.cleanup.append((self.owner, f"{path.rstrip('/')}/{quote(str(doc['id']), safe='')}"))
            got = {k: doc[k] for k in inject if isinstance(doc, dict) and k in doc and doc[k] == inject[k]}
            if got:
                self.test("mass_assignment", ep, "privileged fields are ignored", "failed", f"accepted {sorted(got)}")
                self.findings.append(Finding("API3:2023", "mass_assignment",
                                             f"Client-supplied {', '.join(sorted(got))} accepted and stored", "high", ep, self.owner,
                                             {**ev, "accepted": got},
                                             "Bind requests to an explicit allow-list of fields (a request DTO); never copy the body onto the model."))
            else:
                self.test("mass_assignment", ep, "privileged fields are ignored", "passed")
            if isinstance(doc, dict):
                self.responses.append((ep, doc, op))

    # ---- API3: excessive data exposure --------------------------------------------------------
    def check_data_exposure(self) -> None:
        sensitive = set(SENSITIVE) | set(self.sec.sensitive_fields)
        for op in self.spec.operations.values():   # read the owner's own data too
            if op.method.upper() == "GET" and "{" not in op.path and _secured(op) and self.owner and not self.sec.is_admin_path(op.path):
                r, _ = self.c.request("GET", op.path, self.owner)
                if _ok(r):
                    self.responses.append((op.key, _json(r), op))
        seen: set[tuple[str, str]] = set()
        for ep, doc, op in self.responses:
            sr = success_response(op)
            schema = resolve(self.spec.raw, json_schema_of((resolve(self.spec.raw, sr[1]) or {}).get("content"))) if sr else None
            for path, key, value in _walk(doc):
                k = key.lower().replace("-", "").replace("_", "")
                if (k in {s.replace("_", "") for s in sensitive}) and value not in (None, "", [], {}) and (ep, key) not in seen:
                    seen.add((ep, key))
                    self.findings.append(Finding("API3:2023", "data_exposure", f"Response contains a secret field: {path}", "high", ep,
                                                 self.owner or "", {"field": path},
                                                 "Remove the field from the response model; never serialise credentials or secrets."))
            undocumented = sorted(_undocumented(self.spec, doc, schema))
            if undocumented and (ep, "*") not in seen:
                seen.add((ep, "*"))
                self.findings.append(Finding("API3:2023", "data_exposure", f"Response has fields the spec doesn't document: {', '.join(undocumented[:8])}",
                                             "low", ep, self.owner or "", {"fields": undocumented[:20]},
                                             "Return only documented fields (or document them); extra fields often leak internal data."))
        self.test("data_exposure", "*", "no secrets or undocumented fields in responses",
                  "failed" if any(f.check == "data_exposure" and f.severity != "low" for f in self.findings) else "passed",
                  f"{len(self.responses)} response(s) inspected")

    # ---- API8: misconfiguration ---------------------------------------------------------------
    def check_headers(self) -> None:
        op = next((o for o in self.spec.operations.values() if o.method.upper() == "GET" and (self.ids_for(o) or "{" not in o.path)), None)
        if not op:
            return
        path = _fill_path(op.path, self.ids_for(op) or {})
        r, ev = self.c.request("GET", path, self.owner, extra_headers={"Origin": EVIL_ORIGIN})
        if r is None:
            return
        h = {k.lower(): v for k, v in r.headers.items()}
        acao, creds = h.get("access-control-allow-origin"), h.get("access-control-allow-credentials", "").lower() == "true"
        if acao in (EVIL_ORIGIN, "null") or (acao == "*" and creds):
            self.findings.append(Finding("API8:2023", "headers", f"CORS trusts any origin{' with credentials' if creds else ''} (Access-Control-Allow-Origin: {acao})",
                                         "high" if creds else "medium", op.key, evidence={"origin_sent": EVIL_ORIGIN, "acao": acao, "credentials": creds},
                                         fix="Allow only known origins; never reflect the request's Origin with credentials."))
        if h.get("x-content-type-options", "").lower() != "nosniff":
            self.findings.append(Finding("API8:2023", "headers", "Missing X-Content-Type-Options: nosniff", "low", op.key,
                                         fix="Send X-Content-Type-Options: nosniff on every response."))
        if self.c.base.startswith("https://") and "strict-transport-security" not in h:
            self.findings.append(Finding("API8:2023", "headers", "Missing Strict-Transport-Security on HTTPS", "medium", op.key,
                                         fix="Send Strict-Transport-Security with a long max-age."))
        for name in ("server", "x-powered-by", "x-aspnet-version"):
            if re.search(r"\d+\.\d+", h.get(name, "")):
                self.findings.append(Finding("API8:2023", "headers", f"{name} header discloses a version: {h[name]}", "low", op.key,
                                             fix="Remove version numbers from server headers."))
        self.test("headers", op.key, "CORS and hardening headers",
                  "failed" if any(f.check == "headers" and f.severity in ("high", "medium") for f in self.findings) else "passed")

    def check_errors(self) -> None:
        op = next((o for o in self.spec.operations.values() if o.method.upper() in ("POST", "PUT", "PATCH")
                   and o.request_body and (self.ids_for(o) or "{" not in o.path)), None)
        if not op:
            return
        if not self.c.writes:
            self.test("errors", op.key, "malformed input is rejected cleanly", "not_run", "writes refused on this environment")
            return
        path = _fill_path(op.path, self.ids_for(op) or {})
        r, ev = self.c.request(op.method.upper(), path, self.owner, raw_body=b'{"k11": [unclosed')
        if r is None:
            return
        leak = STACK.search(r.text or "")
        if leak or r.status_code >= 500:
            self.test("errors", op.key, "malformed input is rejected cleanly", "failed", f"HTTP {r.status_code}")
            self.findings.append(Finding("API8:2023", "errors",
                                         "Error response leaks a stack trace" if leak else f"Malformed JSON causes HTTP {r.status_code}",
                                         "medium", op.key, self.owner or "", {**ev, **({"leak": leak.group(0)} if leak else {})},
                                         "Validate input before processing; return a generic 400 and log details server-side."))
        else:
            self.test("errors", op.key, "malformed input is rejected cleanly", "passed", f"HTTP {r.status_code}")

    # ---- API4: rate limiting (opt-in) ---------------------------------------------------------
    def check_rate_limit(self) -> None:
        rl = self.sec.rate_limit or {}
        op = self.spec.find(rl.get("endpoint", "")) if rl.get("endpoint") else None
        if op is None or op.method.upper() not in SAFE:
            self.test("rate_limit", rl.get("endpoint", "-"), "requests are throttled", "not_run",
                      "set rate_limit.endpoint to a GET operation in security.yaml")
            return
        n = max(5, min(int(rl.get("requests", 30)), 200))
        path = _fill_path(op.path, self.ids_for(op) or {})
        limited, headers_seen = False, False
        for _ in range(n):
            r, _ev = self.c.request("GET", path, self.owner)
            if r is None:
                break
            if r.status_code == 429:
                limited = True
                break
            if any(k.lower().startswith(("ratelimit", "x-ratelimit")) for k in r.headers):
                headers_seen = True
            time.sleep(0.005)
        if limited or headers_seen:
            self.test("rate_limit", op.key, "requests are throttled", "passed", "429 returned" if limited else "rate-limit headers present")
        else:
            self.test("rate_limit", op.key, "requests are throttled", "failed", f"{n} requests, no 429 and no rate-limit headers")
            self.findings.append(Finding("API4:2023", "rate_limit", f"No rate limiting observed after {n} requests", "medium", op.key,
                                         fix="Throttle per client and per user (429 with Retry-After)."))


def _walk(doc: Any, prefix: str = "$"):
    if isinstance(doc, dict):
        for k, v in doc.items():
            yield f"{prefix}.{k}", str(k), v
            yield from _walk(v, f"{prefix}.{k}")
    elif isinstance(doc, list):
        for item in doc[:20]:
            yield from _walk(item, f"{prefix}[*]")


def _undocumented(spec: Spec, doc: Any, schema: Any, depth: int = 0) -> set[str]:
    schema = resolve(spec.raw, schema) if schema else None
    if not isinstance(schema, dict) or depth > 4:
        return set()
    if isinstance(doc, list) and schema.get("type") == "array":
        out: set[str] = set()
        for item in doc[:5]:
            out |= _undocumented(spec, item, schema.get("items"), depth + 1)
        return out
    if isinstance(doc, dict) and isinstance(schema.get("properties"), dict) and not schema.get("additionalProperties"):
        props = schema["properties"]
        out = {k for k in doc if k not in props}
        for k, v in doc.items():
            if k in props:
                out |= {f"{k}.{x}" for x in _undocumented(spec, v, props[k], depth + 1)}
        return out
    return set()
