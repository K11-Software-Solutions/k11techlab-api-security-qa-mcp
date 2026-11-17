---
description: Run OWASP API Security Top 10 tests from the spec and judge scanner results for this change
argument-hint: "[environment] [checks, e.g. bola,auth]"
---

Check this API's security with the api-security-qa MCP tools, and explain the result.

Input: $ARGUMENTS

1. Call `security_config`. Use a test environment (production-like ones are refused; never try to get around that). If there are fewer than two normal identities, explain that cross-user access (BOLA) can't be tested and offer to set them up with `init_security_config`; the accounts must be TEST accounts the user controls.
2. If an operation with an id in its path has no test resource, suggest one under `resources:` (how alice creates an object she owns). Ask before writing config.
3. Call `run_security_tests` (with the environment and checks given, if any).
4. Explain each finding in plain language, most severe first: what an attacker could do, the exact request that proved it (as which user, with which status), and the fix. Group by OWASP API Top 10 category.
5. Treat "inconclusive" and "not run" honestly: say what wasn't proven and why (a failed control request, writes refused, no test resource).
6. For scanner results, list only new findings and expired risk acceptances. Mention when there's no baseline yet (`save_scanner_baseline` on main).

Never mark a finding as accepted, raise thresholds, or disable a check to make the result pass. Accepting a risk is a decision for a named person with an expiry date, in `.qa-mcp/security-accepted.yaml`.
