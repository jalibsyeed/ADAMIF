"""
RawEvent Model

Represents a single atomic fact observed from system telemetry.
This class must contain no interpretation, severity, or attack classification.
"""

from dataclasses import dataclass
from typing import Optional
from uuid import UUID
from datetime import datetime

from .event_types import SourceType, EventType


@dataclass(frozen=True)
class RawEvent:
    # Mandatory Fields
    event_id: UUID
    timestamp: datetime
    source_type: SourceType
    event_type: EventType
    raw_message: str
    host: str
    log_source: str

    # Optional Context Fields
    source_ip: Optional[str] = None
    username: Optional[str] = None
    process_name: Optional[str] = None
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    service: Optional[str] = None
    port: Optional[int] = None

    def __post_init__(self):
        # Validate mandatory text fields
        if not self.raw_message:
            raise ValueError("raw_message cannot be empty")

        if not self.host:
            raise ValueError("host cannot be empty")

        if not self.log_source:
            raise ValueError("log_source cannot be empty")

        # Validate type integrity
        if not isinstance(self.event_id, UUID):
            raise TypeError("event_id must be a UUID")

        if not isinstance(self.timestamp, datetime):
            raise TypeError("timestamp must be a datetime")

        if not isinstance(self.source_type, SourceType):
            raise TypeError("source_type must be a SourceType enum")

        if not isinstance(self.event_type, EventType):
            raise TypeError("event_type must be an EventType enum")
