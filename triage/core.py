"""Read Semgrep SARIF and Bandit JSON, dedupe, suppress, diff a baseline, and gate a build."""

from __future__ import annotations

import hashlib
import json
import re

from dataclasses import dataclass, field
from datetime import date
from pathlib import PurePosixPath


SEVERITIES = ["info", "low", "medium", "high", "critical"]


@dataclass(frozen=True)
class Finding:
    tool: str
    rule_id: str
    path: str
    line: int
    severity: str
    cwe: int | None
    message: str
    code: str


@dataclass
class Group:
    key: str
    path: str
    line: int
    severity: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def tools(self) -> list[str]:
        return sorted({finding.tool for finding in self.findings})

    @property
    def fingerprints(self) -> list[str]:
        return sorted(fingerprint(finding) for finding in self.findings)


@dataclass(frozen=True)
class Suppression:
    fingerprint: str
    reason: str
    expires: date
    by: str


def normalize_path(raw: str, project: str) -> str:
    """Normalize a source path and remove the project-root prefix."""
    path = str(raw).replace("\\", "/")

    if path.startswith("file://"):
        path = path[len("file://"):]

    parts = [part for part in path.split("/") if part not in ("", ".")]

    # Keep only the path after the last occurrence of the project directory.
    project_positions = [
        index for index, part in enumerate(parts) if part == project
    ]

    if project_positions:
        parts = parts[project_positions[-1] + 1:]

    return "/".join(parts)


def fingerprint(f: Finding) -> str:
    """Return a stable fingerprint that does not depend on line number."""
    normalized_code = " ".join(f.code.split())
    raw = f"{f.tool}|{f.rule_id}|{f.path}|{normalized_code}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _severity_from_sarif_level(level: str) -> str:
    mapping = {
        "error": "high",
        "warning": "medium",
        "note": "low",
        "none": "info",
    }
    return mapping.get(str(level).lower(), "medium")


def _severity_from_security_score(value) -> str | None:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None

    if not (0 < score <= 10):
        return None

    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def _extract_cwe(tags) -> int | None:
    """Return the first CWE number found in a list of rule tags."""
    if not isinstance(tags, list):
        return None

    for tag in tags:
        match = re.match(r"^CWE-(\d+)", str(tag), re.IGNORECASE)
        if match:
            return int(match.group(1))

    return None


def load_semgrep_sarif(path, project: str) -> list[Finding]:
    """Load findings from every run in a Semgrep SARIF file."""
    with open(path, "r", encoding="utf-8") as file:
        sarif = json.load(file)

    findings = []

    for run in sarif.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        rules = driver.get("rules", [])

        # Build a rule lookup for this run only.
        rules_by_id = {
            rule.get("id"): rule
            for rule in rules
            if rule.get("id") is not None
        }

        for result in run.get("results", []):
            rule_id = str(result.get("ruleId", ""))
            rule = rules_by_id.get(rule_id, {})

            properties = rule.get("properties", {})

            # 1. Prefer Semgrep's security-severity score.
            severity = _severity_from_security_score(
                properties.get("security-severity")
            )

            # 2. Otherwise use result.level.
            if severity is None:
                level = result.get("level")

                # 3. Otherwise use the rule's default configuration.
                if not level:
                    level = (
                        rule.get("defaultConfiguration", {}).get("level")
                    )

                # 4. Final fallback is warning.
                if not level:
                    level = "warning"

                severity = _severity_from_sarif_level(level)

            cwe = _extract_cwe(properties.get("tags", []))

            # Use the first reported location.
            locations = result.get("locations", [])
            physical_location = {}

            if locations:
                physical_location = (
                    locations[0]
                    .get("physicalLocation", {})
                )

            artifact = physical_location.get("artifactLocation", {})
            region = physical_location.get("region", {})

            raw_path = artifact.get("uri", "")
            normalized = normalize_path(raw_path, project)

            line = region.get("startLine", 0)

            message = result.get("message", {}).get("text", "")

            snippet = region.get("snippet", {}).get("text", "")
            code = snippet.splitlines()[0] if snippet else ""

            findings.append(
                Finding(
                    tool="semgrep",
                    rule_id=rule_id,
                    path=normalized,
                    line=int(line),
                    severity=severity,
                    cwe=cwe,
                    message=message,
                    code=code,
                )
            )

    return findings


def _extract_bandit_code(code_text: str, target_line: int) -> str:
    """Select the source-code line matching Bandit's reported line number."""
    for source_line in str(code_text).splitlines():
        match = re.match(r"^\s*(\d+)\s+(.*)$", source_line)

        if match and int(match.group(1)) == target_line:
            return match.group(2)

    return ""


def load_bandit(path, project: str) -> list[Finding]:
    """Load findings from a Bandit JSON report."""
    with open(path, "r", encoding="utf-8") as file:
        report = json.load(file)

    findings = []

    for result in report.get("results", []):
        rule_id = str(result.get("test_id", ""))
        line = int(result.get("line_number", 0))

        raw_severity = str(
            result.get("issue_severity", "")
        ).upper()

        severity_mapping = {
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
        }

        severity = severity_mapping.get(raw_severity, "info")

        # Low confidence downgrades severity by exactly one level.
        confidence = str(
            result.get("issue_confidence", "")
        ).upper()

        if confidence == "LOW":
            severity_index = SEVERITIES.index(severity)
            severity = SEVERITIES[max(0, severity_index - 1)]

        issue_cwe = result.get("issue_cwe") or {}
        cwe = issue_cwe.get("id")

        code = _extract_bandit_code(
            result.get("code", ""),
            line,
        )

        findings.append(
            Finding(
                tool="bandit",
                rule_id=rule_id,
                path=normalize_path(
                    result.get("filename", ""),
                    project,
                ),
                line=line,
                severity=severity,
                cwe=int(cwe) if cwe is not None else None,
                message=result.get("issue_text", ""),
                code=code,
            )
        )

    return findings


def issue_key(f: Finding, equivalences: dict[str, str]) -> str:
    """Return the common issue key used to group equivalent findings."""
    tool_rule = f"{f.tool}:{f.rule_id}"

    if tool_rule in equivalences:
        return equivalences[tool_rule]

    if f.cwe is not None:
        return f"CWE-{f.cwe}"

    return tool_rule


def dedupe(
    findings: list[Finding],
    equivalences: dict[str, str] | None = None,
) -> list[Group]:
    """Group findings by path, line, and issue key."""
    if equivalences is None:
        equivalences = {}

    grouped = {}

    for finding in findings:
        key = issue_key(finding, equivalences)
        group_id = (finding.path, finding.line, key)

        if group_id not in grouped:
            grouped[group_id] = Group(
                key=key,
                path=finding.path,
                line=finding.line,
                severity=finding.severity,
                findings=[],
            )

        group = grouped[group_id]
        group.findings.append(finding)

        # Keep the highest severity in the group.
        if SEVERITIES.index(finding.severity) > SEVERITIES.index(
            group.severity
        ):
            group.severity = finding.severity

    groups = list(grouped.values())

    # Stable member ordering, independent of input order.
    for group in groups:
        group.findings.sort(
            key=lambda f: (
                f.tool,
                f.rule_id,
                f.path,
                f.line,
                fingerprint(f),
            )
        )

    # Highest severity first, then path, line, and issue key.
    groups.sort(
        key=lambda group: (
            -SEVERITIES.index(group.severity),
            group.path,
            group.line,
            group.key,
        )
    )

    return groups


def load_suppressions(
    entries: list[dict],
) -> tuple[list[Suppression], list[dict]]:
    """Validate suppression entries without raising for invalid entries."""
    valid = []
    invalid = []

    for entry in entries:
        if not isinstance(entry, dict):
            invalid.append(entry)
            continue

        fp = entry.get("fingerprint")
        reason = entry.get("reason")
        expires_value = entry.get("expires")
        by = entry.get("by")

        # Fingerprints must be exactly 64 lowercase hexadecimal characters.
        if not isinstance(fp, str) or not re.fullmatch(
            r"[0-9a-f]{64}", fp
        ):
            invalid.append(entry)
            continue

        # Reason must contain at least 10 non-whitespace characters.
        if not isinstance(reason, str) or len(reason.strip()) < 10:
            invalid.append(entry)
            continue

        if not isinstance(by, str) or not by.strip():
            invalid.append(entry)
            continue

        try:
            expiry_date = date.fromisoformat(expires_value)
        except (TypeError, ValueError):
            invalid.append(entry)
            continue

        valid.append(
            Suppression(
                fingerprint=fp,
                reason=reason.strip(),
                expires=expiry_date,
                by=by.strip(),
            )
        )

    return valid, invalid


def apply_suppressions(
    groups: list[Group],
    suppressions: list[Suppression],
    today: date,
) -> tuple[list[Group], list[Group]]:
    """Separate active groups from groups with a valid, unexpired suppression."""
    active = []
    suppressed = []

    suppression_by_fingerprint = {
        suppression.fingerprint: suppression
        for suppression in suppressions
        if suppression.expires >= today
    }

    for group in groups:
        is_suppressed = any(
            fp in suppression_by_fingerprint
            for fp in group.fingerprints
        )

        if is_suppressed:
            suppressed.append(group)
        else:
            active.append(group)

    return active, suppressed


def diff_baseline(
    groups: list[Group],
    baseline: set[str],
) -> tuple[list[Group], list[Group], list[str]]:
    """Separate new and existing groups and identify fixed fingerprints."""
    new = []
    existing = []

    current_fingerprints = set()

    for group in groups:
        group_fingerprints = set(group.fingerprints)
        current_fingerprints.update(group_fingerprints)

        if group_fingerprints.intersection(baseline):
            existing.append(group)
        else:
            new.append(group)

    fixed = sorted(baseline - current_fingerprints)

    return new, existing, fixed


def gate(new_active: list[Group], fail_on: str) -> bool:
    """Return True when no new group reaches the configured failure severity."""
    threshold = SEVERITIES.index(fail_on)

    return not any(
        SEVERITIES.index(group.severity) >= threshold
        for group in new_active
    )