from __future__ import annotations

from collections import Counter

from .models import Finding


def severity_bucket(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def summarize_findings(findings: list[Finding]) -> dict[str, object]:
    buckets = Counter(severity_bucket(finding.score) for finding in findings)
    tactics = Counter(finding.rule.tactic for finding in findings)
    affected_hosts = sorted({finding.event.host for finding in findings})
    affected_users = sorted({finding.event.user for finding in findings})

    return {
        "total_findings": len(findings),
        "severity": dict(buckets),
        "top_tactics": dict(tactics.most_common(5)),
        "affected_hosts": affected_hosts,
        "affected_users": affected_users,
    }


def analyst_note(finding: Finding) -> str:
    return (
        f"{finding.rule.name} matched on host `{finding.event.host}` for user "
        f"`{finding.event.user}`. Score: {finding.score}/100. "
        f"Recommended action: {finding.rule.analyst_action}"
    )
