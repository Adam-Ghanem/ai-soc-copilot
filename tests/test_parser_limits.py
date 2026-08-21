from pathlib import Path

import pytest

from ai_soc_copilot.parser import load_events


def test_load_events_rejects_invalid_max_events(tmp_path: Path) -> None:
    events = tmp_path / "events.jsonl"
    events.write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="max_events"):
        load_events(events, max_events=0)

    with pytest.raises(ValueError, match="max_events"):
        load_events(events, max_events=10001)
