from __future__ import annotations

import json
from pathlib import Path

from .models import DetectionRule, Finding, SecurityEvent
from .enrichment import enrich_event

_SEVERITY_BASE = {
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 90,
}


def load_rules(path: Path) -> list[DetectionRule]:
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"Rules file not found: {path}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("Rules file must contain a JSON array")
    return [DetectionRule.from_dict(item) for item in raw]


def detect(events: list[SecurityEvent], rules: list[DetectionRule]) -> list[Finding]:
    findings: list[Finding] = []
    for event in events:
        evidence = f"{event.message} {json.dumps(event.attributes, sort_keys=True)}".lower()
        for rule in rules:
            if rule.event_type != event.event_type:
                continue
            if all(keyword in evidence for keyword in rule.keywords):
                score = _score(rule, event)
                findings.append(
                    Finding(
                        event=event,
                        rule=rule,
                        score=score,
                        enrichment=enrich_event(event),
                    )
                )
    return sorted(findings, key=lambda finding: finding.score, reverse=True)


def _score(rule: DetectionRule, event: SecurityEvent) -> int:
    score = _SEVERITY_BASE[rule.severity]
    if event.attributes.get("privileged") is True:
        score += 8
    if event.attributes.get("external") is True:
        score += 6
    if event.attributes.get("asset_criticality") == "high":
        score += 7
    return min(score, 100)
