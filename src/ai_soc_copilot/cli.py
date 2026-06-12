from __future__ import annotations

import argparse
from pathlib import Path

from .detection import detect, load_rules
from .parser import load_events
from .report import write_report
from .triage import severity_bucket


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Defensive SOC alert triage assistant")
    parser.add_argument("--input", required=True, type=Path, help="Path to JSONL security events")
    parser.add_argument("--rules", default=Path("rules/detections.json"), type=Path, help="Path to local detection rules")
    parser.add_argument("--output", default=Path("reports/incident_report.md"), type=Path, help="Markdown report path")
    parser.add_argument("--max-events", default=1000, type=int, help="Maximum number of events to process")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    events = load_events(args.input, max_events=args.max_events)
    rules = load_rules(args.rules)
    findings = detect(events, rules)
    write_report(findings, args.output)

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        counts[severity_bucket(finding.score)] += 1

    print(f"Processed alerts: {len(events)}")
    print(f"Critical severity: {counts['critical']}")
    print(f"High severity: {counts['high']}")
    print(f"Medium severity: {counts['medium']}")
    print(f"Low severity: {counts['low']}")
    print(f"Report written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
