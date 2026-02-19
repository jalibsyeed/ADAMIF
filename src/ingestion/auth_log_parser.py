"""
SSH authentication log parser.

Implements LogParser contract.
Responsible ONLY for translating raw journal log lines
into normalized RawEvent objects.

No detection logic.
No aggregation.
No severity.
"""

import ipaddress
from datetime import datetime
from uuid import uuid4
from typing import Optional
from zoneinfo import ZoneInfo

from src.core.raw_event import RawEvent
from src.core.event_types import SourceType, EventType
from src.ingestion.parser_interface import LogParser


class AuthLogParser(LogParser):

    def parse(self, raw_line: str) -> Optional[RawEvent]:
        try:
            if "sshd" not in raw_line:
                return None

            parts = raw_line.split()
            if len(parts) < 5:
                return None

            month = parts[0]
            day = parts[1]
            time_str = parts[2]
            host = parts[3]

            # Extract message safely
            if "]: " not in raw_line:
                return None

            message = raw_line.split("]: ", 1)[1].strip()

            event_type = self._map_event_type(message)
            if event_type is None:
                return None

            timestamp = self._normalize_timestamp(month, day, time_str)

            source_ip = self._extract_ip(message)
            port = self._extract_port(message)
            username = self._extract_username(message)

            return RawEvent(
                event_id=uuid4(),
                timestamp=timestamp,
                source_type=SourceType.SYSTEMD_JOURNAL,
                event_type=event_type,
                raw_message=message,
                host=host,
                log_source="journalctl",
                source_ip=source_ip,
                username=username,
                service="sshd",
                port=port
            )

        except Exception:
            return None

    def _map_event_type(self, message: str) -> Optional[EventType]:
        if "Failed password for" in message:
            return EventType.AUTH_FAILURE

        if "Accepted password for" in message or "Accepted publickey for" in message:
            return EventType.AUTH_SUCCESS

        if "Invalid user" in message:
            return EventType.INVALID_USER_ATTEMPT

        if "Connection closed" in message:
            return EventType.SSH_CONNECTION_CLOSED

        return None

    def _normalize_timestamp(self, month: str, day: str, time_str: str) -> datetime:
        current_year = datetime.now().year
        dt_str = f"{current_year} {month} {day} {time_str}"
        dt = datetime.strptime(dt_str, "%Y %b %d %H:%M:%S")

        # Deterministic Phase 1 behavior (UTC)
        dt = dt.replace(tzinfo=ZoneInfo("UTC"))
        return dt

    def _extract_ip(self, message: str) -> Optional[str]:
        if "from " not in message:
            return None

        try:
            candidate = message.split("from ", 1)[1].split()[0]
            ip_obj = ipaddress.ip_address(candidate)
            return str(ip_obj)
        except Exception:
            return None

    def _extract_port(self, message: str) -> Optional[int]:
        if "port " not in message:
            return None

        try:
            return int(message.split("port ", 1)[1].split()[0])
        except Exception:
            return None

    def _extract_username(self, message: str) -> Optional[str]:
        # Case: Failed password for invalid user <username>
        if "for invalid user " in message:
            parts = message.split("for invalid user ", 1)
            return parts[1].split()[0]

        # Case: Invalid user <username>
        if "Invalid user " in message:
            parts = message.split("Invalid user ", 1)
            return parts[1].split()[0]

        # Case: Accepted/Failed password for <username>
        if "for " in message:
            parts = message.split("for ", 1)
            return parts[1].split()[0]

        return None
