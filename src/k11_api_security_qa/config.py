"""Security test config: ``.qa-mcp/security.yaml`` (environments and auth profiles come from
``.qa-mcp/api-test.yaml``, shared with k11 API Functional QA).

    spec: openapi.yaml                    # default: the spec in api-test.yaml
    environment: local
    identities:                           # who the tests act as (auth profiles from api-test.yaml)
      alice: { auth: alice }              # a normal user; owns the test resources
      bob:   { auth: bob }                # another normal user: must NOT reach alice's data
      admin: { auth: admin }              # optional: proves admin-only operations work for admins
    resources:                            # an object alice owns, for each path with an id in it
      "/accounts/{id}":
        create: { call: POST /accounts, body: { name: QA account }, save: "$.id" }   # or: id: acc-123
    admin_paths: ["/admin/**"]            # admin-only operations (operations tagged "admin" count too)
    checks: [auth, bola, bfla, mass_assignment, data_exposure, headers, errors]   # rate_limit is opt-in
    rate_limit: { endpoint: "GET /accounts/{id}", requests: 30 }
    sarif: ["security-reports/*.sarif"]   # scanner results to include (Semgrep, CodeQL, Trivy, ZAP, ...)
    sensitive_fields: [pin]               # extra field names that must never appear in responses

Safety: tests run only on environments where k11 API Functional QA allows writes (local hosts,
test-named environments, or allow_writes: true); never on production-like names. Every request
stays on the environment's host. Rate-limit probing is opt-in and capped.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

CONFIG = ".qa-mcp/security.yaml"
ALL_CHECKS = ("auth", "bola", "bfla", "mass_assignment", "data_exposure", "headers", "errors", "rate_limit")
DEFAULT_CHECKS = ("auth", "bola", "bfla", "mass_assignment", "data_exposure", "headers", "errors")
SENSITIVE = ("password", "passwd", "passwordhash", "password_hash", "secret", "clientsecret", "client_secret", "token",
             "accesstoken", "access_token", "refreshtoken", "refresh_token", "apikey", "api_key", "privatekey",
             "private_key", "ssn", "creditcard", "credit_card", "cardnumber", "card_number", "cvv", "cvc", "pin",
             "otp", "mfasecret", "salt")
INJECT = {"role": "admin", "roles": ["admin"], "isAdmin": True, "is_admin": True, "admin": True,
          "permissions": ["*"], "verified": True, "isVerified": True, "balance": 999999, "credit": 999999,
          "price": 0.01, "discount": 100, "total": 0.01, "status": "approved", "ownerId": "k11-other-owner",
          "userId": "k11-other-user", "tenantId": "k11-other-tenant", "plan": "enterprise"}


@dataclass
class SecurityConfig:
    root: Path
    spec: str | None = None
    environment: str | None = None
    identities: dict[str, dict] = field(default_factory=dict)
    resources: dict[str, dict] = field(default_factory=dict)
    admin_paths: list[str] = field(default_factory=lambda: ["/admin/**", "/admin"])
    checks: list[str] = field(default_factory=lambda: list(DEFAULT_CHECKS))
    rate_limit: dict = field(default_factory=dict)
    sarif: list[str] = field(default_factory=list)
    sensitive_fields: list[str] = field(default_factory=list)
    exists: bool = False

    def owner_and_others(self) -> tuple[str | None, list[str]]:
        """The identity that owns test resources (first non-admin), and the other normal identities."""
        normal = [n for n, i in self.identities.items() if not i.get("admin") and n != "admin"]
        return (normal[0] if normal else None), normal[1:]

    def admin_identity(self) -> str | None:
        return next((n for n, i in self.identities.items() if i.get("admin") or n == "admin"), None)

    def is_admin_path(self, path: str, tags: list | None = None) -> bool:
        if tags and any(str(t).lower() == "admin" for t in tags):
            return True
        return any(fnmatch.fnmatchcase(path, p) or fnmatch.fnmatchcase(path, p.rstrip("*").rstrip("/")) for p in self.admin_paths)


def load(root: Path) -> SecurityConfig:
    p = Path(root) / CONFIG
    data: dict[str, Any] = yaml.safe_load(p.read_text("utf8")) or {} if p.is_file() else {}
    unknown = set(data) - {"spec", "environment", "identities", "resources", "admin_paths", "checks", "rate_limit",
                           "sarif", "sensitive_fields"}
    if unknown:
        raise ValueError(f"{CONFIG}: unknown key(s) {sorted(unknown)}")
    checks = list(data.get("checks") or DEFAULT_CHECKS)
    bad = set(checks) - set(ALL_CHECKS)
    if bad:
        raise ValueError(f"{CONFIG}: unknown check(s) {sorted(bad)}; known: {list(ALL_CHECKS)}")
    cfg = SecurityConfig(root=Path(root), spec=data.get("spec"), environment=data.get("environment"),
                         identities=data.get("identities") or {}, resources=data.get("resources") or {},
                         checks=checks, rate_limit=data.get("rate_limit") or {}, sarif=list(data.get("sarif") or []),
                         sensitive_fields=[str(s).lower() for s in data.get("sensitive_fields") or []], exists=p.is_file())
    if "admin_paths" in data:
        cfg.admin_paths = list(data["admin_paths"] or [])
    return cfg


INIT = """# k11 API Security QA (https://github.com/K11-Software-Solutions/k11techlab-api-security-qa-mcp)
# Environments and auth profiles come from .qa-mcp/api-test.yaml. Use TEST accounts only.
identities:
  alice: { auth: alice }      # a normal user who owns the test data
  bob:   { auth: bob }        # a second normal user: must not reach alice's data
  # admin: { auth: admin }    # optional, for admin-only operations

resources:                    # an object alice owns, for each path with an id
  # "/orders/{id}":
  #   create: { call: POST /orders, body: { items: [{ sku: BAG-1, qty: 1 }] }, save: "$.id" }
  #   # or an existing id:  id: ord-123

admin_paths: ["/admin/**"]
checks: [auth, bola, bfla, mass_assignment, data_exposure, headers, errors]
# sarif: ["security-reports/*.sarif"]   # Semgrep / CodeQL / Trivy / ZAP results to include
"""
