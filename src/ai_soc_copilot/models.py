from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Severity = Literal["low", "medium", "high", "critical"]

_ALLOWED_EVENT_TYPES = {"auth", "process", "network", "identity", "endpoint"}
_ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}


@dataclass(frozen=True)
class SecurityEvent:
    timestamp: str
    event_type: str
    source: str
    host: str
    user: str
    message: str
    attributes: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def from_dict(raw: dict[str, Any]) -> "SecurityEvent":
        required = ["timestamp", "event_type", "source", "host", "user", "message"]
        missing = [field_name for field_name in required if field_name not in raw]
        if missing:
            raise ValueError(f"Missing required event fields: {', '.join(missing)}")

        event_type = _clean_string(raw["event_type"], "event_type", 32).lower()
        if event_type not in _ALLOWED_EVENT_TYPES:
            raise ValueError(f"Unsupported event_type: {event_type}")

        attributes = raw.get("attributes", {})
        if not isinstance(attributes, dict):
            raise ValueError("attributes must be an object")

        return SecurityEvent(
            timestamp=_clean_string(raw["timestamp"], "timestamp", 64),
            event_type=event_type,
            source=_clean_string(raw["source"], "source", 64),
            host=_clean_string(raw["host"], "host", 128),
            user=_clean_string(raw["user"], "user", 128),
            message=_clean_string(raw["message"], "message", 500),
            attributes=attributes,
        )


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    name: str
    event_type: str
    severity: Severity
    tactic: str
    keywords: tuple[str, ...]
    analyst_action: str

    @staticmethod
    def from_dict(raw: dict[str, Any]) -> "DetectionRule":
        severity = _clean_string(raw.get("severity", "medium"), "severity", 16).lower()
        if severity not in _ALLOWED_SEVERITIES:
            raise ValueError(f"Unsupported severity: {severity}")

        keywords = raw.get("keywords", [])
        if not isinstance(keywords, list) or not all(isinstance(item, str) for item in keywords):
            raise ValueError("keywords must be a list of strings")

        return DetectionRule(
            rule_id=_clean_string(raw["rule_id"], "rule_id", 64),
            name=_clean_string(raw["name"], "name", 120),
            event_type=_clean_string(raw["event_type"], "event_type", 32).lower(),
            severity=severity,  # type: ignore[arg-type]
            tactic=_clean_string(raw["tactic"], "tactic", 80),
            keywords=tuple(keyword.lower() for keyword in keywords),
            analyst_action=_clean_string(raw["analyst_action"], "analyst_action", 300),
        )


@dataclass(frozen=True)
class Finding:
    event: SecurityEvent
    rule: DetectionRule
    score: int
    enrichment: dict[str, str]


def _clean_string(value: Any, field_name: str, max_length: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{field_name} cannot be empty")
    if len(cleaned) > max_length:
        raise ValueError(f"{field_name} exceeds {max_length} characters")
    return cleaned
