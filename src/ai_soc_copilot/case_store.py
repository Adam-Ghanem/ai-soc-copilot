from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CASE_STATUSES = ("open", "investigating", "contained", "resolved")
_ALLOWED_TRANSITIONS = {
    "open": {"investigating", "resolved"},
    "investigating": {"contained", "resolved"},
    "contained": {"resolved"},
    "resolved": {"investigating"},
}
_MAX_NOTE_LENGTH = 2000


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class CaseStoreError(ValueError):
    """Raised when a case-store operation is invalid."""


class CaseStore:
    """Small, local, atomic JSON case store for analyst workflow state."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def list_cases(self) -> list[dict[str, Any]]:
        data = self._read()
        cases = list(data["cases"].values())
        return sorted(cases, key=lambda case: (-int(case["risk_score"]), case["case_id"]))

    def get(self, case_id: str) -> dict[str, Any]:
        case = self._read()["cases"].get(case_id)
        if case is None:
            raise CaseStoreError(f"Case not found: {case_id}")
        return case

    def upsert_detected_cases(self, cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
        data = self._read()
        stored = data["cases"]
        for incoming in cases:
            case_id = _required_case_id(incoming)
            existing = stored.get(case_id)
            if existing is None:
                stored[case_id] = _new_case(incoming)
            else:
                _refresh_case(existing, incoming)
        self._write(data)
        return [stored[_required_case_id(case)] for case in cases]

    def transition(self, case_id: str, status: str) -> dict[str, Any]:
        if status not in CASE_STATUSES:
            raise CaseStoreError(f"Unsupported case status: {status}")
        data = self._read()
        case = _get_case(data, case_id)
        current = str(case["status"])
        if status == current:
            return case
        if status not in _ALLOWED_TRANSITIONS[current]:
            raise CaseStoreError(f"Invalid case transition: {current} -> {status}")
        case["status"] = status
        _audit(case, "status_changed", {"from": current, "to": status})
        self._write(data)
        return case

    def add_note(self, case_id: str, note: str) -> dict[str, Any]:
        cleaned = note.strip()
        if not cleaned:
            raise CaseStoreError("note cannot be empty")
        if len(cleaned) > _MAX_NOTE_LENGTH:
            raise CaseStoreError(f"note exceeds {_MAX_NOTE_LENGTH} characters")
        data = self._read()
        case = _get_case(data, case_id)
        entry = {"timestamp": utc_now(), "text": cleaned}
        case.setdefault("analyst_notes", []).append(entry)
        _audit(case, "analyst_note_added", {"length": len(cleaned)})
        self._write(data)
        return case

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"schema_version": 1, "cases": {}}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CaseStoreError(f"Unable to read case store: {self.path}") from exc
        if not isinstance(raw, dict) or not isinstance(raw.get("cases", {}), dict):
            raise CaseStoreError("Invalid case store format")
        return {"schema_version": 1, "cases": raw["cases"]}

    def _write(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent, text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def _new_case(incoming: dict[str, Any]) -> dict[str, Any]:
    case = dict(incoming)
    case["status"] = "open"
    case["created_at"] = utc_now()
    case["updated_at"] = case["created_at"]
    case["analyst_notes"] = []
    case["audit_trail"] = [
        {"timestamp": case["created_at"], "action": "case_created", "details": {}}
    ]
    return case


def _refresh_case(existing: dict[str, Any], incoming: dict[str, Any]) -> None:
    preserved = {
        "case_id": existing["case_id"],
        "status": existing["status"],
        "created_at": existing["created_at"],
        "analyst_notes": existing.get("analyst_notes", []),
        "audit_trail": existing.get("audit_trail", []),
    }
    existing.clear()
    existing.update(incoming)
    existing.update(preserved)
    existing["updated_at"] = utc_now()
    _audit(existing, "case_refreshed", {"finding_count": incoming.get("finding_count", 0)})


def _get_case(data: dict[str, Any], case_id: str) -> dict[str, Any]:
    if not isinstance(case_id, str) or not case_id.strip():
        raise CaseStoreError("case_id cannot be empty")
    case = data["cases"].get(case_id.strip())
    if case is None:
        raise CaseStoreError(f"Case not found: {case_id}")
    return case


def _required_case_id(case: dict[str, Any]) -> str:
    value = case.get("case_id")
    if not isinstance(value, str) or not value.strip():
        raise CaseStoreError("case_id is required")
    return value.strip()


def _audit(case: dict[str, Any], action: str, details: dict[str, Any]) -> None:
    timestamp = utc_now()
    case.setdefault("audit_trail", []).append(
        {"timestamp": timestamp, "action": action, "details": details}
    )
    case["updated_at"] = timestamp
