"""
RawEvent Loader

Responsible for deterministic replay of stored RawEvent objects
from append-only JSONL storage.

No detection logic.
No mutation.
Pure reconstruction layer.
"""

import json
from pathlib import Path
from typing import List
from uuid import UUID
from datetime import datetime

from src.core.raw_event import RawEvent
from src.core.event_types import SourceType, EventType


class RawEventLoader:

    def __init__(self, file_path: str):
        self.file_path = Path(file_path)

    def load(self) -> List[RawEvent]:
        events = []

        if not self.file_path.exists():
            return events

        with self.file_path.open("r", encoding="utf-8") as f:
            for line in f:
                data = json.loads(line.strip())
                event = self._deserialize(data)
                events.append(event)

        return events

    def _deserialize(self, data: dict) -> RawEvent:
        return RawEvent(
            event_id=UUID(data["event_id"]),
            timestamp=datetime.fromisoformat(data["timestamp"]),
            source_type=SourceType(data["source_type"]),
            event_type=EventType(data["event_type"]),
            raw_message=data["raw_message"],
            host=data["host"],
            log_source=data["log_source"],
            source_ip=data.get("source_ip"),
            username=data.get("username"),
            process_name=data.get("process_name"),
            file_path=data.get("file_path"),
            file_hash=data.get("file_hash"),
            service=data.get("service"),
            port=data.get("port")
        )
