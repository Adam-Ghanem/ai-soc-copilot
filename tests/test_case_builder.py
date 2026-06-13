from ai_soc_copilot.case_builder import build_cases
from ai_soc_copilot.detection import detect, load_rules
from ai_soc_copilot.parser import load_events


def test_case_builder_groups_findings_by_host_and_user(tmp_path):
    events_path = tmp_path / "events.jsonl"
    rules_path = tmp_path / "rules.json"
    events_path.write_text(
        "\n".join(
            [
                '{"timestamp":"2026-06-01T10:00:00Z","event_type":"auth","source":"siem","host":"wkst-01","user":"analyst.demo","message":"failed login followed by success","attributes":{"src_ip":"198.51.100.10","asset_criticality":"high"}}',
                '{"timestamp":"2026-06-01T10:04:00Z","event_type":"endpoint","source":"edr","host":"wkst-01","user":"analyst.demo","message":"tamper protection disabled","attributes":{"process":"security-agent","privileged":true}}',
            ]
        ),
        encoding="utf-8",
    )
    rules_path.write_text(
        """
        [
          {"rule_id":"AUTH-001","name":"Failed then success","event_type":"auth","severity":"high","tactic":"Identity monitoring","keywords":["failed","success"],"analyst_action":"Review source and confirm user activity."},
          {"rule_id":"ENDPOINT-005","name":"Control disabled","event_type":"endpoint","severity":"high","tactic":"Endpoint monitoring","keywords":["tamper","disabled"],"analyst_action":"Review endpoint health before containment."}
        ]
        """,
        encoding="utf-8",
    )

    findings = detect(load_events(events_path), load_rules(rules_path))
    cases = build_cases(findings)

    assert len(cases) == 1
    assert cases[0]["priority"] == "P2"
    assert cases[0]["host"] == "wkst-01"
    assert cases[0]["finding_count"] == 2
    assert any("src_ip=198.51.100.10" in value for value in cases[0]["observables"])
