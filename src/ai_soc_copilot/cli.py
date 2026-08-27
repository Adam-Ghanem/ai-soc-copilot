from __future__ import annotations

import argparse
import json
from pathlib import Path

from .case_builder import build_cases
from .case_store import CASE_STATUSES, CaseStore, CaseStoreError
from .detection import detect, load_rules
from .parser import load_events
from .report import write_report
from .triage import severity_bucket


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Defensive SOC alert triage assistant")
    parser.add_argument("--input", type=Path, help="Path to JSONL security events")
    parser.add_argument("--rules", default=Path("rules/detections.json"), type=Path, help="Path to local detection rules")
    parser.add_argument("--output", default=Path("reports/incident_report.md"), type=Path, help="Markdown report path")
    parser.add_argument("--case-json", default=Path("reports/cases.json"), type=Path, help="Structured case export path")
    parser.add_argument("--case-store", default=Path("reports/case_store.json"), type=Path, help="Persistent local case store")
    parser.add_argument("--max-events", default=1000, type=int, help="Maximum number of events to process")
    parser.add_argument(
        "--case-action",
        choices=("list", "show", "status", "note"),
        help="Operate on persisted SOC cases instead of running analysis",
    )
    parser.add_argument("--case-id", help="Case ID for show/status/note actions")
    parser.add_argument("--status", choices=CASE_STATUSES, help="New case status")
    parser.add_argument("--note", help="Analyst note to append to a case")
    return parser


def _require_case_args(args: argparse.Namespace) -> None:
    if args.case_action in {"show", "status", "note"} and not args.case_id:
        raise SystemExit("--case-id is required for this case action")
    if args.case_action == "status" and not args.status:
        raise SystemExit("--status is required for the status action")
    if args.case_action == "note" and not args.note:
        raise SystemExit("--note is required for the note action")


def _run_case_action(args: argparse.Namespace) -> int:
    _require_case_args(args)
    store = CaseStore(args.case_store)
    try:
        if args.case_action == "list":
            print(json.dumps(store.list_cases(), indent=2))
        elif args.case_action == "show":
            print(json.dumps(store.get(args.case_id), indent=2))
        elif args.case_action == "status":
            print(json.dumps(store.transition(args.case_id, args.status), indent=2))
        elif args.case_action == "note":
            print(json.dumps(store.add_note(args.case_id, args.note), indent=2))
    except CaseStoreError as exc:
        print(f"Case error: {exc}")
        return 2
    return 0


def main() -> int:
    args = build_parser().parse_args()
    if args.case_action:
        return _run_case_action(args)
    if not args.input:
        raise SystemExit("--input is required unless --case-action is used")
    if args.max_events < 1:
        raise SystemExit("--max-events must be at least 1")

    events = load_events(args.input, max_events=args.max_events)
    rules = load_rules(args.rules)
    findings = detect(events, rules)
    cases = build_cases(findings)
    write_report(findings, args.output)
    args.case_json.parent.mkdir(parents=True, exist_ok=True)
    args.case_json.write_text(json.dumps(cases, indent=2), encoding="utf-8")

    persisted = CaseStore(args.case_store).upsert_detected_cases(cases)

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        counts[severity_bucket(finding.score)] += 1

    print(f"Processed events: {len(events)}")
    print(f"Findings: {len(findings)}")
    print(f"Cases: {len(cases)}")
    print(f"Persisted cases: {len(persisted)}")
    print(f"Critical severity: {counts['critical']}")
    print(f"High severity: {counts['high']}")
    print(f"Medium severity: {counts['medium']}")
    print(f"Low severity: {counts['low']}")
    print(f"Markdown report written to {args.output}")
    print(f"Structured cases written to {args.case_json}")
    print(f"Case store written to {args.case_store}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
