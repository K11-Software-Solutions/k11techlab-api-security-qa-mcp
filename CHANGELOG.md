# Changelog

## 0.1.0 (16 November 2026)

- First release: OWASP API Security Top 10 (2023) tests generated from your OpenAPI spec and run as your test identities:
  broken authentication (API2), cross-user object access (API1), admin-only operations (API5), mass assignment and
  secrets or undocumented fields in responses (API3), CORS, hardening headers and error leaks (API8), rate limiting (API4, opt-in).
- Control requests make results meaningful: if the owner can't reach their own object, the cross-user test is inconclusive.
- Scanner SARIF from any tool, judged against a baseline (only new findings count) and risk acceptances that need an owner,
  a reason and an expiry date.
- Refuses production-like environments; data-changing checks only where writes are allowed; credentials masked in evidence.
- MCP tools, CLI for CI, `/security-check` command; `security-report.json` is read by k11 Release Gate.
