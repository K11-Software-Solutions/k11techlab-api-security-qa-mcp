"""Command line: start the MCP server (default), run security tests in CI, or save the scanner baseline."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__

USAGE = f"""k11-api-security-qa-mcp {__version__}

Usage:
  k11-api-security-qa-mcp                  start the MCP server on stdio
  k11-api-security-qa-mcp run [opts]       OWASP API Top 10 tests + scanner results, write the report
  k11-api-security-qa-mcp baseline         save current scanner findings as the baseline (do this on main)
  k11-api-security-qa-mcp init             write a starter .qa-mcp/security.yaml
  k11-api-security-qa-mcp --version

run options:
  --env NAME              environment from .qa-mcp/api-test.yaml (production-like names are refused)
  --checks a,b            auth, bola, bfla, mass_assignment, data_exposure, headers, errors, rate_limit
  --no-api / --no-scanners
  --report-dir PATH       default .qa-mcp/security-report
  --fail-on LEVEL         high (default: critical or high) | critical | medium | never

The project is QA_MCP_ROOT or the current directory.
"""


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    if not argv:
        from .server import serve

        serve()
        return 0
    cmd = argv[0]
    if cmd in ("--version", "-v"):
        print(__version__)
        return 0
    if cmd in ("--help", "-h", "help"):
        print(USAGE)
        return 0
    root = Path(os.environ.get("QA_MCP_ROOT") or os.getcwd()).resolve()
    if cmd == "init":
        from .config import CONFIG, INIT

        p = root / CONFIG
        if p.exists():
            print(f"{CONFIG} already exists", file=sys.stderr)
            return 1
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(INIT, "utf8")
        print(f"Wrote {CONFIG}")
        return 0
    if cmd == "baseline":
        from . import sarif
        from .config import load

        sec = load(root)
        if not sec.sarif:
            print("No 'sarif:' paths in .qa-mcp/security.yaml", file=sys.stderr)
            return 1
        findings, files = sarif.collect(root, sec.sarif)
        p = sarif.save_baseline(root, findings)
        print(f"Baseline saved: {p.relative_to(root).as_posix()} ({len(findings)} findings from {len(files)} file(s))")
        return 0
    if cmd != "run":
        print(f"Unknown command: {cmd}\n\n{USAGE}", file=sys.stderr)
        return 2
    p = argparse.ArgumentParser(prog="k11-api-security-qa-mcp run")
    p.add_argument("--env")
    p.add_argument("--checks")
    p.add_argument("--no-api", action="store_true")
    p.add_argument("--no-scanners", action="store_true")
    p.add_argument("--report-dir", default=".qa-mcp/security-report")
    p.add_argument("--fail-on", default="high", choices=["critical", "high", "medium", "never"])
    a = p.parse_args(argv[1:])
    from .run import run

    try:
        out = run(root, a.env, a.checks.split(",") if a.checks else None, not a.no_api, not a.no_scanners, a.report_dir)
    except (ValueError, OSError) as e:
        print(f"run failed: {e}", file=sys.stderr)
        return 1
    doc, s = out["report"], out["report"]["summary"]
    print(f"{doc['status']}: {s['critical']} critical, {s['high']} high, {s['medium']} medium, {s['low']} low; "
          f"API tests {s['api_tests']['passed']} passed, {s['api_tests']['failed']} failed. Report: {out['paths']['markdown']}")
    for f in doc["api"]["findings"]:
        if f["severity"] in ("critical", "high", "medium"):
            print(f"  - {f['severity']}: {f['id']} {f['title']} ({f['endpoint']})")
    if doc["status"] != "completed":
        print(f"  ! {doc['reason']}", file=sys.stderr)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf8") as fh:
            fh.write((root / out["paths"]["markdown"]).read_text("utf8") + "\n")
    if a.fail_on == "never":
        return 0
    levels = {"critical": ("critical",), "high": ("critical", "high"), "medium": ("critical", "high", "medium")}[a.fail_on]
    return 1 if doc["status"] != "completed" or any(s[x] for x in levels) else 0


if __name__ == "__main__":
    raise SystemExit(main())
