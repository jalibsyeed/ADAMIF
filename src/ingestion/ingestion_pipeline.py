"""
Ingestion pipeline orchestration.

Coordinates:
- LogReader
- AuthLogParser
- RawEventStore

This layer performs:
Raw log → Parsed RawEvent → Persistent storage

No detection logic.
No reporting.
No attack classification.

----------------------------------------------------------------------
Operational Modes
----------------------------------------------------------------------

Default Behavior:
Append-only storage (forensic-grade, SOC-safe).

Optional Reset Mode:
Explicitly wipes storage file before ingestion.
Intended strictly for testing / lab environments.

Reset mode must be consciously enabled.
It is NEVER default.
"""

from typing import List
from pathlib import Path

from src.core.raw_event import RawEvent
from src.ingestion.log_reader import LogReader
from src.ingestion.auth_log_parser import AuthLogParser
from src.ingestion.raw_event_store import RawEventStore


class IngestionPipeline:
    """
    Orchestrates ingestion flow.
    """

    def __init__(
        self,
        log_file_path: str,
        storage_path: str,
        reset_storage: bool = False
    ):
        self.reader = LogReader(log_file_path)
        self.parser = AuthLogParser()
        self.store = RawEventStore(storage_path)
        self.storage_path = Path(storage_path)
        self.reset_storage = reset_storage

    def run(self) -> List[RawEvent]:
        """
        Execute ingestion pipeline.

        Returns:
            List of RawEvent objects created during this run.
        """

        if self.reset_storage:
            self._reset_storage()

        events: List[RawEvent] = []

        for line in self.reader.read_lines():
            event = self.parser.parse(line)

            if event is not None:
                self.store.append(event)
                events.append(event)

        return events

    # -------------------------------------------------------
    # Controlled Reset Mode
    # -------------------------------------------------------

    def _reset_storage(self):
        """
        Explicit storage wipe.
        Intended only for controlled testing environments.
        """

        if self.storage_path.exists():
            print("[WARNING] Reset mode enabled. Clearing existing RawEvent storage.")
            self.storage_path.unlink()
        else:
            print("[INFO] Reset mode enabled. No existing storage file found.")
