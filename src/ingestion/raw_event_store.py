import json
from pathlib import Path
from typing import Any
from uuid import UUID
from datetime import datetime
from enum import Enum

from src.core.raw_event import RawEvent


class RawEventStore:
    """
    Append-only JSONL persistence layer for RawEvent.
    Responsible for safe serialization and storage.
    """

    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        self.file_path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: RawEvent) -> None:
        if not isinstance(event, RawEvent):
            raise TypeError("Only RawEvent instances can be stored.")

        event_dict = self._serialize_event(event)

        with self.file_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(event_dict))
            file.write("\n")

    def _serialize_event(self, event: RawEvent) -> dict[str, Any]:
        serialized: dict[str, Any] = {}

        for field, value in event.__dict__.items():
            serialized[field] = self._convert(value)

        return serialized

    def _convert(self, value: Any) -> Any:
        if isinstance(value, UUID):
            return str(value)

        if isinstance(value, datetime):
            return value.isoformat()

        if isinstance(value, Enum):
            return value.value

        return value
