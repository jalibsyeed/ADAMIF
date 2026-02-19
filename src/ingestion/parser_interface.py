"""
Parser interface definition for ingestion layer.

All log parsers must implement this contract.

Parsers:
- Accept raw log line (string)
- Return RawEvent or None
- Perform no detection logic
- Perform no aggregation
- Perform no severity classification
"""

from abc import ABC, abstractmethod
from typing import Optional

from src.core.raw_event import RawEvent


class LogParser(ABC):
    """
    Abstract base class for all log parsers.

    Enforces a strict contract:
    parse() must return either a valid RawEvent or None.
    """

    @abstractmethod
    def parse(self, raw_line: str) -> Optional[RawEvent]:
        """
        Parse a raw log line into a RawEvent.

        Returns:
            RawEvent if parsing is successful and the line is relevant.
            None if the line should be ignored.
        """
        pass
