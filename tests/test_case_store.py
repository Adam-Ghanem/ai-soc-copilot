from pathlib import Path

import pytest

from ai_soc_copilot.case_store import CaseStore, CaseStoreError


BASE_CASE = {
    "case_id": "CASE-ABC123",
    "priority": "P2",
    "risk_score": 80,
    "title": "Suspicious authentication activity",
    "host": "host-01",
    "user": "analyst",
    "tactics": ["Credential Access"],
    "observables": ["src_ip=10.0.0.5"],
    "timeline": ["2026-08-27T10:00:00Z - Rule: failed login"],
    "recommended_actions": ["Review authentication activity."],
    "finding_count": 1,
}


def test_case_creation_and_reload(tmp_path: Path) -> None:
    store = CaseStore(tmp_path / "cases.json")
    created = store.upsert_detected_cases([BASE_CASE])[0]

    assert created["status"] == "open"
    assert created["case_id"] == "CASE-ABC123"
    assert len(created["audit_trail"]) == 1

    reloaded = CaseStore(tmp_path / "cases.json").get("CASE-ABC123")
    assert reloaded["status"] == "open"
    assert reloaded["created_at"] == created["created_at"]


def test_status_lifecycle_is_strict(tmp_path: Path) -> None:
    store = CaseStore(tmp_path / "cases.json")
    store.upsert_detected_cases([BASE_CASE])

    store.transition("CASE-ABC123", "investigating")
    store.transition("CASE-ABC123", "contained")
    resolved = store.transition("CASE-ABC123", "resolved")

    assert resolved["status"] == "resolved"
    assert [entry["action"] for entry in resolved["audit_trail"]] == [
        "case_created",
        "status_changed",
        "status_changed",
        "status_changed",
    ]

    with pytest.raises(CaseStoreError, match="Invalid case transition"):
        store.transition("CASE-ABC123", "contained")


def test_resolved_case_can_be_reopened_for_investigation(tmp_path: Path) -> None:
    store = CaseStore(tmp_path / "cases.json")
    store.upsert_detected_cases([BASE_CASE])
    store.transition("CASE-ABC123", "resolved")

    reopened = store.transition("CASE-ABC123", "investigating")
    assert reopened["status"] == "investigating"


def test_notes_are_audited_and_bounded(tmp_path: Path) -> None:
    store = CaseStore(tmp_path / "cases.json")
    store.upsert_detected_cases([BASE_CASE])

    case = store.add_note("CASE-ABC123", "Reviewed source IP against known-good activity.")
    assert case["analyst_notes"][0]["text"].startswith("Reviewed source IP")
    assert case["audit_trail"][-1]["action"] == "analyst_note_added"

    with pytest.raises(CaseStoreError, match="cannot be empty"):
        store.add_note("CASE-ABC123", "   ")

    with pytest.raises(CaseStoreError, match="exceeds"):
        store.add_note("CASE-ABC123", "x" * 2001)


def test_refresh_preserves_analyst_state(tmp_path: Path) -> None:
    store = CaseStore(tmp_path / "cases.json")
    store.upsert_detected_cases([BASE_CASE])
    store.transition("CASE-ABC123", "investigating")
    store.add_note("CASE-ABC123", "Analyst is reviewing evidence.")

    updated = dict(BASE_CASE)
    updated["risk_score"] = 90
    updated["finding_count"] = 2
    refreshed = store.upsert_detected_cases([updated])[0]

    assert refreshed["risk_score"] == 90
    assert refreshed["status"] == "investigating"
    assert len(refreshed["analyst_notes"]) == 1
    assert refreshed["audit_trail"][-1]["action"] == "case_refreshed"
