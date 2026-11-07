
"""Command-line interface for SAST triage."""

import argparse
import json
import sys

from datetime import date
from pathlib import Path

from triage.core import (
    SEVERITIES,
    load_semgrep_sarif,
    load_bandit,
    dedupe,
    load_suppressions,
    apply_suppressions,
    diff_baseline,
    gate,
)


def read_json(path, default):
    """Read JSON from a file, or return the default if no path was supplied."""
    if path is None:
        return default

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def group_to_dict(group):
    """Convert a Group into the required JSON representation."""
    return {
        "key": group.key,
        "path": group.path,
        "line": group.line,
        "severity": group.severity,
        "tools": group.tools,
        "fingerprints": group.fingerprints,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="triage")

    parser.add_argument("--sarif", required=True)
    parser.add_argument("--bandit", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--equivalences")
    parser.add_argument("--baseline")
    parser.add_argument("--suppressions")
    parser.add_argument("--today")
    parser.add_argument(
        "--fail-on",
        default="high",
        choices=SEVERITIES,
    )

    args = parser.parse_args(argv)

    try:
        # Determine the date used to validate suppression expiry.
        today = (
            date.fromisoformat(args.today)
            if args.today
            else date.today()
        )

        # 1. Load scanner findings.
        semgrep_findings = load_semgrep_sarif(
            args.sarif,
            args.project,
        )

        bandit_findings = load_bandit(
            args.bandit,
            args.project,
        )

        all_findings = semgrep_findings + bandit_findings

        # 2. Load optional configuration files.
        equivalences = read_json(args.equivalences, {})
        baseline_data = read_json(args.baseline, [])
        suppression_entries = read_json(args.suppressions, [])

        baseline = set(baseline_data)

        # 3. Deduplicate findings.
        groups = dedupe(all_findings, equivalences)

        # 4. Validate and apply suppressions.
        suppressions, invalid_suppressions = load_suppressions(
            suppression_entries
        )

        active_groups, suppressed_groups = apply_suppressions(
            groups,
            suppressions,
            today,
        )

        # 5. Compare active groups with the baseline.
        new_groups, existing_groups, fixed = diff_baseline(
            active_groups,
            baseline,
        )

        # 6. Apply the severity gate to new, active groups.
        passed = gate(new_groups, args.fail_on)

        # 7. Build the required output.
        output = {
            "passed": passed,
            "new": [group_to_dict(g) for g in new_groups],
            "existing": [group_to_dict(g) for g in existing_groups],
            "suppressed": [
                group_to_dict(g) for g in suppressed_groups
            ],
            "fixed": fixed,
            "invalid_suppressions": len(invalid_suppressions),
        }

        print(json.dumps(output, indent=2))

        return 0 if passed else 1

    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
