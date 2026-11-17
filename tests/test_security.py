"""Every check against K11 Bank: each deliberate flaw is found, and the fixed bank passes. Plus safety rules,
scanner judgment, the CLI and the MCP tools."""

import json
from datetime import date

import anyio
import pytest

from k11_api_security_qa import sarif
from k11_api_security_qa.cli import main
from k11_api_security_qa.run import run


def found(doc):
    return {(f["id"], f["check"], f["endpoint"], f["severity"]) for f in doc["api"]["findings"]}


def test_every_flaw_is_found(project, bank):
    doc = run(project)["report"]
    assert doc["status"] == "completed"
    f = found(doc)
    assert ("API1:2023", "bola", "GET /accounts/{id}", "high") in f                 # bob reads alice's account
    assert ("API2:2023", "auth", "GET /reports", "high") in f                       # secured in the spec, not in the API
    assert ("API3:2023", "mass_assignment", "POST /users", "high") in f            # role accepted at sign-up
    assert ("API3:2023", "data_exposure", "GET /users/me", "high") in f            # password hash in the response
    assert ("API5:2023", "bfla", "DELETE /admin/users/{id}", "critical") in f      # any user can delete users
    assert ("API8:2023", "headers", "GET /health", "high") in f                     # CORS reflects origin + credentials
    assert ("API8:2023", "errors", "POST /users", "medium") in f                    # stack trace on bad JSON
    assert ("API4:2023", "rate_limit", "GET /accounts/{id}", "medium") in f
    ev = next(x for x in doc["api"]["findings"] if x["check"] == "bola")["evidence"]
    assert ev["as"] == "bob" and ev["status"] == 200 and "alice-token" not in json.dumps(doc)
    # what the bank does right is recorded as passing, not just ignored
    tests = {(t["check"], t["endpoint"], t["outcome"]) for t in doc["api"]["tests"]}
    assert ("bola", "PATCH /accounts/{id}", "passed") in tests and ("bola", "DELETE /accounts/{id}", "passed") in tests
    assert ("bfla", "GET /admin/stats", "passed") in tests
    assert doc["summary"]["verdict"] == "fail"


def test_the_fixed_bank_passes(project, secure_bank):
    doc = run(project, include_sarif=False)["report"]
    assert [f for f in doc["api"]["findings"] if f["severity"] != "info"] == [], doc["api"]["findings"]
    assert doc["summary"]["api_tests"]["failed"] == 0 and doc["summary"]["api_tests"]["passed"] >= 25
    assert doc["summary"]["verdict"] == "pass"


def test_control_requests_make_results_meaningful(project, secure_bank):
    """If the owner can't read their own object, a 404 for bob proves nothing: inconclusive, not passed."""
    cfg = project / ".qa-mcp/security.yaml"
    cfg.write_text(cfg.read_text("utf8").replace('create: { call: POST /accounts, body: { name: QA account }, save: "$.id" }',
                                                  'id: acc-not-owned-by-anyone'), "utf8")
    doc = run(project, checks=["bola"], include_sarif=False)["report"]
    t = next(t for t in doc["api"]["tests"] if t["endpoint"] == "GET /accounts/{id}")
    assert t["outcome"] == "inconclusive" and "control failed" in t["detail"]


def test_production_is_refused_and_read_only_environments_skip_writes(project, bank):
    doc = run(project, "prod")["report"]
    assert doc["status"] == "blocked" and "production" in doc["reason"] and doc["api"]["tests"] == []
    api = project / ".qa-mcp/api-test.yaml"
    api.write_text(api.read_text("utf8").replace("  prod:", "  shared:\n    base_url: \"${ENV:BANK_URL}\"\n    allow_writes: false\n  prod:"), "utf8")
    doc = run(project, "shared", include_sarif=False)["report"]
    assert doc["status"] == "completed"
    outcomes = {(t["check"], t["endpoint"]): t["outcome"] for t in doc["api"]["tests"]}
    assert outcomes[("mass_assignment", "POST /users")] == "not_run"
    assert outcomes[("auth", "GET /reports")] == "failed"     # read-only checks still run
    assert any("Writes are refused" in n for n in doc["notes"])


def test_scanner_findings_new_existing_accepted_expired(project):
    findings, files = sarif.collect(project, ["security-reports/*.sarif"])
    assert files == ["security-reports/semgrep.sarif"] and len(findings) == 4
    sarif.judge(findings, sarif.load_baseline(project), sarif.load_acceptances(project), today=date(2026, 11, 16))
    status = {f.rule.split(".")[-1]: (f.severity, f.status) for f in findings}
    assert status == {"generic-api-key": ("critical", "new"), "sql-injection": ("high", "existing"),
                      "md5-used": ("medium", "accepted"), "debug-enabled": ("high", "acceptance_expired")}
    doc = run(project, include_api=False)["report"]
    assert doc["summary"]["critical"] == 1 and doc["summary"]["high"] == 1     # only new + expired count
    assert doc["summary"]["scanner"] == {"new": 1, "existing": 1, "accepted": 1, "acceptance_expired": 1}


def test_acceptances_need_owner_reason_and_expiry(project):
    (project / ".qa-mcp/security-accepted.yaml").write_text("accepted:\n  - rule: x\n    owner: '@me'\n", "utf8")
    with pytest.raises(ValueError, match="reason"):
        sarif.load_acceptances(project)


def test_sarif_without_fingerprints_and_bad_files(tmp_path):
    (tmp_path / "a.sarif").write_text(json.dumps({"runs": [{"tool": {"driver": {"name": "Trivy"}}, "results": [
        {"ruleId": "CVE-2024-1", "level": "error", "message": {"text": "lib 1.2.3 vulnerable"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "file://requirements.txt"}}}]},
        {"ruleId": "R2", "level": "note", "message": {"text": "x"}, "suppressions": [{"kind": "inSource"}]}]}]}), "utf8")
    (tmp_path / "b.sarif").write_text("not json", "utf8")
    fs = sarif.parse_sarif(tmp_path / "a.sarif", tmp_path)
    assert len(fs) == 1 and fs[0].severity == "high" and fs[0].path == "requirements.txt" and fs[0].fingerprint.startswith("Trivy:")
    with pytest.raises(ValueError):
        sarif.parse_sarif(tmp_path / "b.sarif", tmp_path)
    with pytest.raises(ValueError, match="inside the project"):
        sarif.collect(tmp_path, ["../*.sarif"])


def test_cli_fail_on_and_baseline(project, bank, capsys):
    assert main(["run"]) == 1
    out = capsys.readouterr().out
    assert "critical" in out and "API1:2023" in out
    assert main(["run", "--fail-on", "never"]) == 0
    assert main(["run", "--checks", "headers", "--no-scanners", "--fail-on", "critical"]) == 0   # high only
    assert main(["baseline"]) == 0
    assert json.loads((project / ".qa-mcp/security-baseline.json").read_text())["count"] == 4


def test_mcp_tools(project, bank):
    from mcp.shared.memory import create_connected_server_and_client_session

    from k11_api_security_qa.server import create_server

    async def go():
        async with create_connected_server_and_client_session(create_server()._mcp_server) as c:
            tools = {t.name for t in (await c.list_tools()).tools}
            assert tools == {"security_config", "run_security_tests", "judge_scanner_results", "save_scanner_baseline",
                             "get_report", "init_security_config"}
            cfg = json.loads((await c.call_tool("security_config", {})).content[0].text)
            assert cfg["owner"] == "alice" and cfg["other_users"] == ["bob"] and cfg["admin"] == "admin"
            assert cfg["environments"]["prod"]["security_tests"].startswith("refused")
            r = json.loads((await c.call_tool("run_security_tests", {"checks": ["bola", "auth"]})).content[0].text)
            assert r["summary"]["verdict"] == "fail" and r["paths"]["json"] == ".qa-mcp/security-report/security-report.json"
            one = json.loads((await c.call_tool("get_report", {"check": "bola"})).content[0].text)
            assert one["findings"][0]["evidence"]["as"] == "bob"
            j = json.loads((await c.call_tool("judge_scanner_results", {})).content[0].text)
            assert len(j["new_or_expired"]) == 2
            bad = await c.call_tool("run_security_tests", {"checks": ["sqlmap"]})
            assert bad.isError

    anyio.run(go)
