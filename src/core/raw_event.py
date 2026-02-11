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
