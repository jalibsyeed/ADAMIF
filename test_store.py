from src.core.raw_event import RawEvent
from src.core.event_types import SourceType, EventType
from src.ingestion.raw_event_store import RawEventStore
from uuid import uuid4
from datetime import datetime, timezone

# Create a dummy RawEvent matching the schema exactly
event = RawEvent(
    event_id=uuid4(),
    timestamp=datetime.now(timezone.utc),
    source_type=SourceType.SYSTEMD_JOURNAL,
    event_type=EventType.AUTH_FAILURE,
    raw_message="Failed password for testuser from 192.168.1.100",
    host="kali",
    log_source="journalctl",
    source_ip="192.168.1.100",
    username="testuser",
    service="sshd",
    port=22
)

store = RawEventStore("data/raw_events.jsonl")
store.append(event)

print("Event stored successfully.")
