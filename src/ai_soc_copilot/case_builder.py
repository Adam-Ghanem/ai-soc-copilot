from __future__ import annotations

from collections import defaultdict
from hashlib import sha256

from .models import Finding
from .triage import severity_bucket

_PRIORITY_BY_SEVERITY = {
    "critical": "P1",
    "high": "P2",
    "medium": "P3",
    "low": "P4",
}


def build_cases(findings: list[Finding]) -> list[dict[str, object]]:
    """Group findings into analyst-ready SOC cases.

    The grouping is deterministic and local-only. It does not call external
    services and it does not infer facts that are not present in the evidence.
    """
    groups: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for finding in findings:
        groups[(finding.event.host, finding.event.user)].append(finding)

    cases: list[dict[str, object]] = []
    for (host, user), grouped in groups.items():
        ordered = sorted(grouped, key=lambda item: item.event.timestamp)
        max_score = max(item.score for item in ordered)
        severity = severity_bucket(max_score)
        seed = "|".join([host, user, *[item.rule.rule_id for item in ordered]])
        case_id = "CASE-" + sha256(seed.encode("utf-8")).hexdigest()[:10].upper()
        tactics = sorted({item.rule.tactic for item in ordered})
        observables = sorted(_observables(ordered))
        cases.append(
            {
                "case_id": case_id,
                "priority": _PRIORITY_BY_SEVERITY[severity],
                "risk_score": max_score,
                "title": _title(host, user, ordered),
                "host": host,
                "user": user,
                "tactics": tactics,
                "observables": observables,
                "timeline": [f"{item.event.timestamp} - {item.rule.name}: {item.event.message}" for item in ordered],
                "recommended_actions": _recommended_actions(ordered),
                "finding_count": len(ordered),
            }
        )
    return sorted(cases, key=lambda item: (-int(item["risk_score"]), str(item["case_id"])))


def _title(host: str, user: str, findings: list[Finding]) -> str:
    if len(findings) == 1:
        return findings[0].rule.name
    return f"Correlated activity on {host} for {user}"


def _recommended_actions(findings: list[Finding]) -> list[str]:
    actions = []
    for finding in findings:
        if finding.rule.analyst_action not in actions:
            actions.append(finding.rule.analyst_action)
    actions.append("Document analyst decision, evidence reviewed, and any containment approval before closing the case.")
    return actions


def _observables(findings: list[Finding]) -> set[str]:
    values: set[str] = set()
    for finding in findings:
        for key in ("src_ip", "dest_ip", "process", "file_hash", "url"):
            value = finding.event.attributes.get(key)
            if isinstance(value, str) and value.strip():
                values.add(f"{key}={value.strip()}")
    return values
