from __future__ import annotations

import json
from pathlib import Path

from .models import SecurityEvent


def load_events(path: Path, max_events: int = 1000) -> list[SecurityEvent]:
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"Input file not found: {path}")
    if max_events < 1 or max_events > 10000:
        raise ValueError("max_events must be between 1 and 10000")

    events: list[SecurityEvent] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if line_number > max_events:
                break
            stripped = line.strip()
            if not stripped:
                continue
            try:
                raw = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_number}: {exc.msg}") from exc
            if not isinstance(raw, dict):
                raise ValueError(f"Line {line_number} must be a JSON object")
            events.append(SecurityEvent.from_dict(raw))
    return events
