from __future__ import annotations

from pathlib import Path

from .models import Finding
from .triage import analyst_note, severity_bucket, summarize_findings


def render_markdown(findings: list[Finding]) -> str:
    summary = summarize_findings(findings)
    lines: list[str] = [
        "# AI SOC Copilot Incident Triage Report",
        "",
        "## Executive summary",
        "",
        f"- Total findings: **{summary['total_findings']}**",
        f"- Severity distribution: `{summary['severity']}`",
        f"- Affected hosts: `{', '.join(summary['affected_hosts']) or 'none'}`",
        f"- Affected users: `{', '.join(summary['affected_users']) or 'none'}`",
        "",
        "## Analyst queue",
        "",
    ]

    if not findings:
        lines.append("No findings matched the local detection rules.")
        return "\n".join(lines) + "\n"

    for index, finding in enumerate(findings, start=1):
        lines.extend(
            [
                f"### {index}. {finding.rule.name}",
                "",
                f"- Rule ID: `{finding.rule.rule_id}`",
                f"- Severity: **{severity_bucket(finding.score)}**",
                f"- Score: **{finding.score}/100**",
                f"- Tactic: `{finding.rule.tactic}`",
                f"- Host: `{finding.event.host}`",
                f"- User: `{finding.event.user}`",
                f"- Source: `{finding.event.source}`",
                f"- Evidence: {finding.event.message}",
                f"- Local enrichment: `{finding.enrichment}`",
                "",
                "**Analyst note:** " + analyst_note(finding),
                "",
            ]
        )
    return "\n".join(lines)


def write_report(findings: list[Finding], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_markdown(findings), encoding="utf-8")
