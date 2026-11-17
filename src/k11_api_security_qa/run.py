"""One security run: resolve the environment, run the API checks, judge scanner results, write the report."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from k11_api_qa import config as api_config
from k11_api_qa.config import PROD_NAME
from k11_api_qa.values import Vars
from k11_contract_qa.spec import inside, load_spec

from . import __version__, sarif
from .checks import Client, Run
from .config import SecurityConfig, load

SEVERITIES = ("critical", "high", "medium", "low", "info")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def run(root: Path, environment: str | None = None, checks: list[str] | None = None, include_api: bool = True,
        include_sarif: bool = True, report_dir: str = ".qa-mcp/security-report") -> dict[str, Any]:
    root = Path(root).resolve()
    sec = load(root)
    api_cfg = api_config.load(root)
    doc: dict[str, Any] = {"tool": f"k11-api-security-qa-mcp {__version__}", "generatedAt": _now(), "status": "completed",
                           "reason": "", "environment": None, "spec": None, "api": {"tests": [], "findings": []},
                           "scanners": {"files": [], "findings": []}, "notes": []}
    if include_api:
        _api(root, sec, api_cfg, environment, checks, doc)
    if include_sarif and sec.sarif:
        try:
            findings, files = sarif.collect(root, sec.sarif)
            sarif.judge(findings, sarif.load_baseline(root), sarif.load_acceptances(root))
            doc["scanners"] = {"files": files, "findings": sarif.as_dicts(findings),
                               "baseline": sarif.BASELINE if sarif.load_baseline(root) is not None else None}
            if sarif.load_baseline(root) is None and findings:
                doc["notes"].append("No scanner baseline yet: every scanner finding counts as new. Save one from main "
                                    "(k11-api-security-qa-mcp baseline) to judge only what a change introduces.")
        except ValueError as e:
            doc["notes"].append(f"Scanner results not read: {e}")
    doc["summary"] = summarize(doc)
    out = inside(root, report_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "security-report.json").write_text(json.dumps(doc, indent=2, ensure_ascii=False, default=str) + "\n", "utf8")
    (out / "security-report.md").write_text(to_markdown(doc), "utf8")
    return {"report": doc, "paths": {"json": (out / "security-report.json").relative_to(root).as_posix(),
                                     "markdown": (out / "security-report.md").relative_to(root).as_posix()}}


def _api(root: Path, sec: SecurityConfig, api_cfg, environment: str | None, checks: list[str] | None, doc: dict) -> None:
    try:
        env_name, env = api_cfg.environment(environment or sec.environment or None)
    except ValueError as e:
        doc["status"], doc["reason"] = "blocked", str(e)
        return
    doc["environment"] = env_name
    if PROD_NAME.search(env_name):
        doc["status"] = "blocked"
        doc["reason"] = (f"'{env_name}' looks like production. Security tests send attack traffic and create test data, so they "
                         "only run against test environments. Testing production needs explicit authorization and a "
                         "separate, scoped engagement.")
        return
    base = str(Vars().sub(env.get("base_url", ""))) if "${" in str(env.get("base_url", "")) else str(env.get("base_url", ""))
    if not base.startswith(("http://", "https://")):
        doc["status"], doc["reason"] = "blocked", f"Environment '{env_name}' needs base_url (http:// or https://)"
        return
    spec_src = sec.spec or api_cfg.spec
    if not spec_src:
        doc["status"], doc["reason"] = "blocked", "No spec: set 'spec:' in .qa-mcp/security.yaml or .qa-mcp/api-test.yaml"
        return
    spec = load_spec(root, spec_src)
    if not spec.http:
        doc["status"], doc["reason"] = "blocked", f"{spec_src} is {spec.format}; the API checks need OpenAPI or Swagger"
        return
    for op in spec.operations.values():   # carry tags (for admin-only operations)
        raw = ((spec.raw.get("paths") or {}).get(op.path) or {}).get(op.method) or {}
        op.meta.setdefault("tags", raw.get("tags") or [])
    doc["spec"] = spec_src
    if len([n for n in sec.identities]) < 1:
        doc["notes"].append("No identities in .qa-mcp/security.yaml: only unauthenticated checks ran. Add two test users "
                            "(alice, bob) to test object-level authorization.")
    client = Client(api_cfg, env_name, env, base, sec)
    if not client.writes:
        doc["notes"].append(f"Writes are refused on '{env_name}' ({client.writes_why}); checks that change data were not run.")
    r = Run(client, spec, sec)
    wanted = [c for c in (checks or sec.checks)]
    try:
        r.setup_resources()
        for name in ("auth", "bola", "bfla", "mass_assignment", "data_exposure", "headers", "errors", "rate_limit"):
            if name in wanted:
                getattr(r, f"check_{name}")()
    except Exception as e:  # noqa: BLE001 - report, don't crash
        doc["status"], doc["reason"] = "error", client.vars.mask(f"{type(e).__name__}: {e}")[:300]
    finally:
        r.teardown()
        client.close()
    doc["api"] = {"checks": wanted, "operations": len(spec.operations), "identities": list(sec.identities),
                  "tests": [asdict(t) for t in r.tests],
                  "findings": sorted((asdict(f) for f in r.findings), key=lambda f: (SEVERITIES.index(f["severity"]), f["id"]))}


def summarize(doc: dict) -> dict:
    api_sev = Counter(f["severity"] for f in doc["api"]["findings"])
    scan = doc["scanners"]["findings"]
    counted = [f for f in scan if f["status"] in ("new", "acceptance_expired")]
    scan_sev = Counter(f["severity"] for f in counted)
    tests = Counter(t["outcome"] for t in doc["api"]["tests"])
    total = {s: api_sev.get(s, 0) + scan_sev.get(s, 0) for s in SEVERITIES}
    verdict = "fail" if (total["critical"] or total["high"] or doc["status"] != "completed") else "pass"
    return {**total, "verdict": verdict,
            "api_tests": {k: tests.get(k, 0) for k in ("passed", "failed", "inconclusive", "not_run")},
            "scanner": {k: sum(1 for f in scan if f["status"] == k) for k in ("new", "existing", "accepted", "acceptance_expired")}}


ICON = {"critical": "🟥", "high": "🔴", "medium": "🟠", "low": "🟡", "info": "⚪"}


def to_markdown(doc: dict) -> str:
    s = doc["summary"]
    L = [f"## API security: {'✅ no critical or high findings' if s['verdict'] == 'pass' else '❌ needs attention'}", ""]
    if doc["status"] != "completed":
        L += [f"> ⛔ **{doc['status']}**: {doc['reason']}", ""]
    t = s["api_tests"]
    L.append(f"Environment **{doc.get('environment') or '–'}** · spec `{doc.get('spec') or '–'}` · "
             f"{s['critical']} critical, {s['high']} high, {s['medium']} medium, {s['low']} low. "
             f"API tests: {t['passed']} passed, {t['failed']} failed, {t['inconclusive']} inconclusive, {t['not_run']} not run.")
    L.append("")
    if doc["api"]["findings"]:
        L += ["### API findings (OWASP API Security Top 10)", "", "| | Category | Finding | Endpoint | As |", "|---|---|---|---|---|"]
        for f in doc["api"]["findings"]:
            L.append(f"| {ICON[f['severity']]} {f['severity']} | {f['id']} | {f['title']} | `{f['endpoint']}` | {f.get('identity') or '–'} |")
        L.append("")
        for f in doc["api"]["findings"]:
            if f["severity"] in ("critical", "high"):
                ev = f.get("evidence") or {}
                L += [f"<details><summary>{f['id']} {f['title']}</summary>", "",
                      f"`{ev.get('request', f['endpoint'])}` as **{ev.get('as', f.get('identity') or 'anonymous')}** → HTTP {ev.get('status', '–')}",
                      "", f"Fix: {f['fix']}", "", "</details>", ""]
    sc = doc["scanners"]
    if sc["findings"]:
        c = s["scanner"]
        L += ["### Scanner findings", "", f"From {', '.join(sc['files'])}: **{c['new']} new**, {c['existing']} already on main, "
              f"{c['accepted']} accepted, {c['acceptance_expired']} with an expired acceptance.", ""]
        shown = [f for f in sc["findings"] if f["status"] in ("new", "acceptance_expired")][:25]
        if shown:
            L += ["| | Tool | Rule | Where | Status |", "|---|---|---|---|---|"]
            for f in shown:
                where = f"{f['path']}:{f['line']}" if f.get("line") else f["path"]
                L.append(f"| {ICON[f['severity']]} {f['severity']} | {f['tool']} | `{f['rule']}` | `{where}` | {f['status'].replace('_', ' ')} |")
            L.append("")
    for n in doc.get("notes") or []:
        L.append(f"> {n}")
    L += ["", f"<sub>{doc['tool']} · {doc['generatedAt']}</sub>", ""]
    return "\n".join(L)
