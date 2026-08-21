from pathlib import Path

from ai_soc_copilot.detection import detect, load_rules
from ai_soc_copilot.parser import load_events
from ai_soc_copilot.triage import severity_bucket, summarize_findings


def test_sample_events_generate_findings() -> None:
    events = load_events(Path("samples/security_events.jsonl"))
    rules = load_rules(Path("rules/detections.json"))
    findings = detect(events, rules)

    assert len(findings) == 5
    assert findings[0].score >= findings[-1].score
    assert any(finding.rule.rule_id == "IAM-004" for finding in findings)


def test_severity_bucket_boundaries() -> None:
    assert severity_bucket(95) == "critical"
    assert severity_bucket(70) == "high"
    assert severity_bucket(40) == "medium"
    assert severity_bucket(10) == "low"


def test_summary_contains_core_soc_fields() -> None:
    events = load_events(Path("samples/security_events.jsonl"))
    rules = load_rules(Path("rules/detections.json"))
    findings = detect(events, rules)
    summary = summarize_findings(findings)

    assert summary["total_findings"] == 5
    assert "idm-01" in summary["affected_hosts"]
    assert "admin.demo" in summary["affected_users"]


def test_empty_summary_is_deterministic() -> None:
    summary = summarize_findings([])

    assert summary == {
        "total_findings": 0,
        "severity": {},
        "top_tactics": {},
        "affected_hosts": [],
        "affected_users": [],
    }
