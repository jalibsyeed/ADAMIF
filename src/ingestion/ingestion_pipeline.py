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
"""

from typing import List

from src.core.raw_event import RawEvent
from src.ingestion.log_reader import LogReader
from src.ingestion.auth_log_parser import AuthLogParser
from src.ingestion.raw_event_store import RawEventStore


class IngestionPipeline:
    """
    Orchestrates ingestion flow.
    """

    def __init__(self, log_file_path: str, storage_path: str):
        self.reader = LogReader(log_file_path)
        self.parser = AuthLogParser()
        self.store = RawEventStore(storage_path)

    def run(self) -> List[RawEvent]:
        """
        Execute ingestion pipeline.

        Returns:
            List of RawEvent objects created during this run.
        """

        events: List[RawEvent] = []

        for line in self.reader.read_lines():
            event = self.parser.parse(line)

            if event is not None:
                self.store.append(event)
                events.append(event)

        return events
