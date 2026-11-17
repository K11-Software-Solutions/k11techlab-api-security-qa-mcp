# k11 API Security QA: MCP server and CI tool

<!-- mcp-name: io.github.K11-Software-Solutions/api-security-qa -->

[![PyPI](https://img.shields.io/pypi/v/k11-api-security-qa-mcp?label=PyPI)](https://pypi.org/project/k11-api-security-qa-mcp/)
[![CI](https://github.com/K11-Software-Solutions/k11techlab-api-security-qa-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/K11-Software-Solutions/k11techlab-api-security-qa-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**Can another user read my customer's account? Scanners usually can't tell you. This can.**

The most common serious API flaw, *broken object-level authorization* (OWASP API1), looks like a perfectly normal request to a scanner: it's a logged-in user asking for an id. Finding it needs two real users and knowledge of which object belongs to whom. k11 API Security QA generates those tests from your OpenAPI spec, runs them as your test users against a test environment, and judges your existing scanner results for the release decision.

**OWASP API Security Top 10 tests, from your spec**

| Check | Category | What it proves |
|---|---|---|
| `bola` | API1 | **bob can't read, change or delete alice's object**; a control request proves alice can |
| `auth` | API2 | every operation the spec marks as secured rejects missing and invalid credentials |
| `mass_assignment` | API3 | client-sent `role`, `isAdmin`, `balance`, `price`… are ignored, not stored |
| `data_exposure` | API3 | no password hashes, tokens or keys in responses; flags fields the spec doesn't document |
| `bfla` | API5 | normal users can't call admin-only operations |
| `headers` | API8 | CORS doesn't trust any origin with credentials; hardening headers; no version leaks |
| `errors` | API8 | malformed input gets a clean 400, not a stack trace or a 500 |
| `rate_limit` | API4 | repeated requests are throttled (opt-in) |

**Scanner results, judged for a release:** SARIF from Semgrep, CodeQL, Trivy, Gitleaks, Checkov, ZAP and others. Only findings **this change introduced** count (compared with a baseline from main), and accepted risks need an **owner, a reason and an expiry date**. When the date passes, the finding counts again.

## See it work

Against the included demo bank, which has deliberate flaws:

```text
❌ 2 critical, 7 high, 2 medium, 4 low · API tests: 21 passed, 9 failed

critical  API5  Admin-only operation callable by a normal user (alice)   DELETE /admin/users/{id}
high      API1  bob can read an object that belongs to alice              GET /accounts/{id}
high      API2  Accepts a request with no credentials                     GET /reports
high      API3  Client-supplied role accepted and stored                  POST /users
high      API3  Response contains a secret field: $.passwordHash          GET /users/me
high      API8  CORS trusts any origin with credentials                   GET /health
medium    API8  Error response leaks a stack trace                        POST /users
scanner   1 new critical (hard-coded API key), 1 expired acceptance (Flask debug, owner @platform-team)
```

Started with `--secure`, the same bank passes all 30 API tests. Each finding carries the exact request, the user it was sent as, the status that proved it, and the fix.

## Configure

Environments and auth profiles come from `.qa-mcp/api-test.yaml` (shared with [k11 API Functional QA](https://github.com/K11-Software-Solutions/k11techlab-api-functional-qa-mcp)). Security settings live in `.qa-mcp/security.yaml`:

```yaml
identities:
  alice: { auth: alice }        # TEST users only
  bob:   { auth: bob }
  admin: { auth: admin }        # optional
resources:                      # an object alice owns, for each path with an id
  "/accounts/{id}":
    create: { call: POST /accounts, body: { name: QA account }, save: "$.id" }
admin_paths: ["/admin/**"]      # operations tagged "admin" count too
checks: [auth, bola, bfla, mass_assignment, data_exposure, headers, errors]
sarif: ["security-reports/*.sarif"]
```

Accepted risks, in `.qa-mcp/security-accepted.yaml`:

```yaml
accepted:
  - rule: python.lang.security.audit.md5-used
    path: app/legacy/checksum.py
    owner: "@security-lead"
    reason: legacy file checksum, not used for passwords
    expires: 2026-12-31
```

## Safety

- **Never production.** Environments named like production are refused, with no override: testing production needs explicit authorization and a scoped engagement.
- **Writes only where allowed.** Checks that create or change data (mass assignment, cross-user writes, malformed bodies) run only on environments where API Functional QA allows writes: local hosts, test-named environments, or `allow_writes: true`. Elsewhere they're reported as *not run*.
- **Test resources are created and deleted by the tool;** destructive admin checks target ids you choose (e.g. one that doesn't exist).
- **Credentials** come from `${ENV:NAME}`, never appear in reports, and requests never leave the environment's host.
- **Honest results:** a control request (alice reading her own object) must succeed, or the cross-user result is *inconclusive*, not *passed*.

## Tools (MCP)

| Tool | What it does |
|---|---|
| `security_config` | What will be tested: environments (and whether data-changing checks can run), identities, resources, admin operations, scanners, baseline, accepted risks |
| `run_security_tests` | Runs the checks and judges scanner results; writes `.qa-mcp/security-report/` |
| `judge_scanner_results` | Scanner findings only: new, existing, accepted, acceptance expired (no requests sent) |
| `save_scanner_baseline` | Records current scanner findings as the baseline (on main) |
| `get_report` | The last report, or one check's tests and findings with full evidence |
| `init_security_config` | Writes a starter `.qa-mcp/security.yaml` |

Command: **`/security-check`**.

## Install and CI

```bash
pip install k11-api-security-qa-mcp
k11-api-security-qa-mcp init                 # .qa-mcp/security.yaml
k11-api-security-qa-mcp baseline             # on main, after your scanners ran
k11-api-security-qa-mcp run --env staging    # fails on new critical/high findings (--fail-on)
```

Claude Code:

```text
/plugin marketplace add K11-Software-Solutions/k11techlab-api-security-qa-mcp
/plugin install api-security-qa@k11-api-security-qa
```

[`docs/security-tests.yml`](docs/security-tests.yml) runs your scanners and the API checks on every pull request. `security-report.json` is read by the [k11 Release Gate](https://github.com/K11-Software-Solutions/k11techlab-release-gate-mcp) as security evidence.

## Part of the K11 QA suite

[Playwright QA](https://github.com/K11-Software-Solutions/k11techlab-playwright-qa-mcp) · [Selenium QA](https://github.com/K11-Software-Solutions/k11techlab-selenium-qa-mcp) · [Appium QA](https://github.com/K11-Software-Solutions/k11techlab-appium-qa-mcp) · [API Contract QA](https://github.com/K11-Software-Solutions/k11techlab-api-contract-qa-mcp) · [API Functional QA](https://github.com/K11-Software-Solutions/k11techlab-api-functional-qa-mcp) · **API Security QA** · [Performance QA](https://github.com/K11-Software-Solutions/k11techlab-performance-qa-mcp) · [LLM Assure](https://github.com/K11-Software-Solutions/k11techlab-llm-assurance-toolkit) · [Release Gate](https://github.com/K11-Software-Solutions/k11techlab-release-gate-mcp) · [Release Readiness Agent](https://github.com/K11-Software-Solutions/k11techlab-release-readiness-agent)

## Roadmap

- SSRF (API7) probes for URL parameters, against a local canary only
- Unsafe consumption of third-party APIs (API10) with a mock upstream
- GraphQL: introspection, depth and batching limits
- Cross-tenant checks for multi-tenant APIs

---

Built by [K11 Software Solutions](https://k11softwaresolutions.com). MIT licensed.
