"""Scanner results (SARIF 2.1.0) from any tool, judged against a baseline and written risk acceptances.

Semgrep, CodeQL, Trivy, Gitleaks, Checkov, Bandit, ZAP and most others write SARIF. Findings are
fingerprinted (the tool's partialFingerprints when present, else tool + rule + file + message), so
only findings this change INTRODUCED count against a release: the baseline holds what main already
had. Accepted risks live in .qa-mcp/security-accepted.yaml with an owner, a reason and an expiry
date; an expired acceptance counts again, so "we'll fix it later" can't become forever.

    accepted:
      - rule: python.lang.security.audit.md5-used        # or fingerprint: ...
        path: src/legacy/hash.py                          # optional
        owner: "@security-lead"
        reason: legacy checksum, not used for passwords
        expires: 2026-12-31
"""

from __future__ import annotations

import glob
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import date
from pathlib import Path

import yaml

BASELINE = ".qa-mcp/security-baseline.json"
ACCEPTED = ".qa-mcp/security-accepted.yaml"
ORDER = ("critical", "high", "medium", "low", "info")


@dataclass
class ScanFinding:
    tool: str
    rule: str
    severity: str
    message: str
    path: str = ""
    line: int | None = None
    fingerprint: str = ""
    status: str = "new"        # new | existing | accepted | acceptance_expired
    acceptance: dict = field(default_factory=dict)
    file: str = ""             # the SARIF file it came from


def _severity(result: dict, rule: dict) -> str:
    props = {**(rule.get("properties") or {}), **(result.get("properties") or {})}
    for key in ("security-severity", "securitySeverity"):
        if key in props:
            try:
                s = float(props[key])
            except (TypeError, ValueError):
                break
            return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"
    tag = str(props.get("severity") or props.get("problem.severity") or "").lower()
    if tag in ORDER:
        return tag
    level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level") or "warning"
    return {"error": "high", "warning": "medium", "note": "low", "none": "info"}.get(level, "medium")


def parse_sarif(path: Path, root: Path) -> list[ScanFinding]:
    try:
        doc = json.loads(Path(path).read_text("utf-8-sig"))
    except (OSError, ValueError) as e:
        raise ValueError(f"{path.name}: not readable SARIF ({e})") from None
    if not isinstance(doc, dict) or "runs" not in doc:
        raise ValueError(f"{path.name}: not a SARIF file (no 'runs')")
    out: list[ScanFinding] = []
    rel_file = path.relative_to(root).as_posix() if path.is_relative_to(root) else path.name
    for run in doc.get("runs") or []:
        driver = ((run.get("tool") or {}).get("driver") or {})
        tool = str(driver.get("name") or "scanner")
        rules = {r.get("id"): r for r in driver.get("rules") or [] if isinstance(r, dict)}
        for res in run.get("results") or []:
            if res.get("suppressions"):
                continue  # suppressed in the tool itself (e.g. nosemgrep), with its own justification
            rule_id = str(res.get("ruleId") or (res.get("rule") or {}).get("id") or "rule")
            rule = rules.get(rule_id, {})
            msg = str((res.get("message") or {}).get("text") or rule.get("shortDescription", {}).get("text") or rule_id)
            loc = ((res.get("locations") or [{}])[0].get("physicalLocation") or {})
            uri = str((loc.get("artifactLocation") or {}).get("uri") or "")
            uri = re.sub(r"^file://", "", uri).replace("\\", "/")
            line = (loc.get("region") or {}).get("startLine")
            fp = next(iter((res.get("partialFingerprints") or res.get("fingerprints") or {}).values()), "")
            if not fp:
                norm = re.sub(r"\d+", "#", msg)[:200]
                fp = hashlib.sha256(f"{tool}|{rule_id}|{uri}|{norm}".encode()).hexdigest()[:24]
            out.append(ScanFinding(tool, rule_id, _severity(res, rule), msg[:300], uri, line, f"{tool}:{fp}", file=rel_file))
    return out


def collect(root: Path, patterns: list[str]) -> tuple[list[ScanFinding], list[str]]:
    root = Path(root).resolve()
    findings, files = [], []
    for pattern in patterns:
        if ".." in Path(pattern).parts or Path(pattern).is_absolute():
            raise ValueError(f"SARIF pattern must stay inside the project: {pattern}")
        for hit in sorted(glob.glob(str(root / pattern), recursive=True)):
            p = Path(hit).resolve()
            if p.is_file() and root in p.parents:
                files.append(p.relative_to(root).as_posix())
                findings += parse_sarif(p, root)
    return findings, files


def load_baseline(root: Path) -> set[str] | None:
    p = Path(root) / BASELINE
    if not p.is_file():
        return None
    return set(json.loads(p.read_text("utf8")).get("fingerprints", []))


def save_baseline(root: Path, findings: list[ScanFinding]) -> Path:
    p = Path(root) / BASELINE
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"fingerprints": sorted({f.fingerprint for f in findings}),
                             "count": len(findings)}, indent=2) + "\n", "utf8")
    return p


def load_acceptances(root: Path) -> list[dict]:
    p = Path(root) / ACCEPTED
    if not p.is_file():
        return []
    data = yaml.safe_load(p.read_text("utf8")) or {}
    items = data.get("accepted") or []
    for i, a in enumerate(items):
        if not isinstance(a, dict) or not (a.get("rule") or a.get("fingerprint")):
            raise ValueError(f"{ACCEPTED}: entry {i + 1} needs 'rule' or 'fingerprint'")
        for k in ("owner", "reason", "expires"):
            if not a.get(k):
                raise ValueError(f"{ACCEPTED}: entry {i + 1} needs '{k}' (every accepted risk has an owner, a reason and an expiry)")
    return items


def _matches(a: dict, f: ScanFinding) -> bool:
    if a.get("fingerprint"):
        return a["fingerprint"] in (f.fingerprint, f.fingerprint.split(":", 1)[-1])
    if a.get("rule") != f.rule:
        return False
    return not a.get("path") or f.path.endswith(str(a["path"]).replace("\\", "/"))


def judge(findings: list[ScanFinding], baseline: set[str] | None, acceptances: list[dict], today: date | None = None) -> None:
    today = today or date.today()
    for f in findings:
        acc = next((a for a in acceptances if _matches(a, f)), None)
        if acc:
            exp = acc["expires"] if isinstance(acc["expires"], date) else date.fromisoformat(str(acc["expires"]))
            f.acceptance = {"owner": acc["owner"], "reason": acc["reason"], "expires": exp.isoformat()}
            f.status = "accepted" if exp >= today else "acceptance_expired"
        elif baseline is not None and f.fingerprint in baseline:
            f.status = "existing"
        else:
            f.status = "new"


def as_dicts(findings: list[ScanFinding]) -> list[dict]:
    return [asdict(f) for f in sorted(findings, key=lambda f: (ORDER.index(f.severity), f.status != "new", f.tool, f.rule))]
