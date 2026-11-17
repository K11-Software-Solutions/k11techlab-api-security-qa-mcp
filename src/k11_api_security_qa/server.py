"""MCP server: OWASP API Security Top 10 tests from your spec, and scanner results judged for a release."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

from . import __version__, sarif
from .config import ALL_CHECKS, CONFIG, INIT, load


def project_root() -> Path:
    return Path(os.environ.get("QA_MCP_ROOT") or os.getcwd()).resolve()


def _brief(doc: dict, limit: int = 30) -> dict:
    return {"status": doc["status"], "reason": doc["reason"], "environment": doc.get("environment"), "summary": doc["summary"],
            "api_findings": [{k: f[k] for k in ("id", "severity", "title", "endpoint", "identity", "fix")} for f in doc["api"]["findings"][:limit]],
            "failed_or_inconclusive_tests": [t for t in doc["api"]["tests"] if t["outcome"] in ("failed", "inconclusive")][:limit],
            "scanner_findings": [f for f in doc["scanners"]["findings"] if f["status"] in ("new", "acceptance_expired")][:limit],
            "notes": doc.get("notes")}


def create_server() -> FastMCP:
    mcp = FastMCP(
        "k11-api-security-qa",
        instructions=(
            "API security testing for release decisions. run_security_tests generates OWASP API Security Top 10 tests from "
            "the OpenAPI spec and runs them on a TEST environment as the identities in .qa-mcp/security.yaml: broken "
            "authentication, cross-user object access (BOLA), admin-only operations, mass assignment, secrets in responses, "
            "CORS and error leaks. It also reads SARIF from scanners (Semgrep, CodeQL, Trivy, ZAP...) and counts only new "
            "findings and expired risk acceptances. Start with security_config. Never run against production, never use "
            "real user accounts, and never weaken a finding to pass a release."
        ),
    )
    mcp._mcp_server.version = __version__

    @mcp.tool(title="Security config")
    def security_config() -> dict:
        """What will be tested: environment (and whether data-changing tests may run), identities and their auth profiles,
        test resources, admin-only operations, enabled checks, scanner result files, baseline and accepted risks."""
        from k11_api_qa import config as api_config
        from k11_api_qa.config import PROD_NAME, writes_allowed

        root = project_root()
        sec = load(root)
        api_cfg = api_config.load(root)
        envs = {}
        for name, env in api_cfg.environments.items():
            ok, why = writes_allowed(name, env, str(env.get("base_url", "")) if not str(env.get("base_url", "")).startswith("${") else "http://unresolved")
            envs[name] = {"security_tests": "refused (production-like)" if PROD_NAME.search(name) else
                          ("all checks" if ok else f"read-only checks only ({why})")}
        missing = [f"{n} → auth profile '{i.get('auth', n)}'" for n, i in sec.identities.items()
                   if i.get("auth", n) not in api_cfg.auth and i.get("auth", n) != "none"]
        owner, others = sec.owner_and_others()
        acc = []
        try:
            acc = sarif.load_acceptances(root)
        except ValueError as e:
            acc = [{"error": str(e)}]
        return {"config": CONFIG if sec.exists else None, "spec": sec.spec or api_cfg.spec, "environments": envs,
                "default_environment": sec.environment or api_cfg.default_environment,
                "identities": list(sec.identities), "owner": owner, "other_users": others, "admin": sec.admin_identity(),
                "identities_missing_auth_profiles": missing, "resources": list(sec.resources), "admin_paths": sec.admin_paths,
                "checks": sec.checks, "available_checks": list(ALL_CHECKS), "sarif": sec.sarif,
                "scanner_baseline": sarif.BASELINE if sarif.load_baseline(root) is not None else None,
                "accepted_risks": len(acc) if acc and "error" not in acc[0] else acc}

    @mcp.tool(title="Run security tests")
    def run_security_tests(environment: Optional[str] = None, checks: Optional[list[str]] = None,
                           include_scanners: bool = True) -> dict:
        """Run the OWASP API Top 10 checks on a test environment (refused on production-like names) and judge scanner SARIF
        results; writes .qa-mcp/security-report/ (JSON evidence for the Release Gate, Markdown for the PR). Returns the
        verdict, findings with evidence and fixes, and tests that failed or were inconclusive. checks: any of
        auth, bola, bfla, mass_assignment, data_exposure, headers, errors, rate_limit."""
        from .run import run

        bad = set(checks or []) - set(ALL_CHECKS)
        if bad:
            raise ValueError(f"Unknown check(s) {sorted(bad)}; known: {list(ALL_CHECKS)}")
        out = run(project_root(), environment, checks, True, include_scanners)
        return {**_brief(out["report"]), "paths": out["paths"]}

    @mcp.tool(title="Judge scanner results")
    def judge_scanner_results() -> dict:
        """Read SARIF from the paths in security.yaml (Semgrep, CodeQL, Trivy, Gitleaks, ZAP, Checkov...) and say which
        findings are new compared with the baseline, which are accepted (owner, reason, expiry) and which acceptances
        have expired. No requests are sent."""
        from .run import run

        out = run(project_root(), include_api=False, include_sarif=True)
        doc = out["report"]
        return {"summary": doc["summary"], "files": doc["scanners"]["files"],
                "new_or_expired": [f for f in doc["scanners"]["findings"] if f["status"] in ("new", "acceptance_expired")][:50],
                "notes": doc["notes"], "paths": out["paths"]}

    @mcp.tool(title="Save scanner baseline")
    def save_scanner_baseline() -> dict:
        """Record the current scanner findings as the baseline (do this on main), so later runs count only findings a
        change introduces."""
        root = project_root()
        sec = load(root)
        if not sec.sarif:
            raise ValueError("No 'sarif:' paths in .qa-mcp/security.yaml")
        findings, files = sarif.collect(root, sec.sarif)
        p = sarif.save_baseline(root, findings)
        return {"saved": p.relative_to(root).as_posix(), "findings": len(findings), "files": files}

    @mcp.tool(title="Get report")
    def get_report(check: Optional[str] = None) -> dict:
        """The last security report, or one check's tests and findings with full evidence (requests, statuses, excerpts)."""
        p = project_root() / ".qa-mcp/security-report/security-report.json"
        if not p.is_file():
            raise ValueError("No report yet; run run_security_tests first")
        doc = json.loads(p.read_text("utf8"))
        if not check:
            return _brief(doc)
        return {"check": check, "tests": [t for t in doc["api"]["tests"] if t["check"] == check],
                "findings": [f for f in doc["api"]["findings"] if f["check"] == check]}

    @mcp.tool(title="Create security config")
    def init_security_config(overwrite: bool = False) -> dict:
        """Write a starter .qa-mcp/security.yaml (identities, resources, admin paths, checks)."""
        p = project_root() / CONFIG
        if p.exists() and not overwrite:
            raise ValueError(f"{CONFIG} already exists (overwrite=true to replace it)")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(INIT, "utf8")
        return {"written": CONFIG, "content": INIT}

    return mcp


def serve() -> None:
    create_server().run()
