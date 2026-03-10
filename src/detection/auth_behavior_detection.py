"""
Authentication Behavior Detection Engine

Detects:
- Password spraying
- Username enumeration
- Low-and-slow brute force

Design Limitation (Phase 1):
This engine emits only one AttackEvent per rule per IP per run.
Multi-wave correlation and alert merging are deferred to Phase 2.
"""

from collections import defaultdict
from datetime import timedelta
from typing import List
from uuid import uuid4

from src.core.raw_event import RawEvent
from src.core.attack_event import AttackEvent
from src.core.attack_types import AttackType, SeverityLevel
from src.core.event_types import EventType


class AuthBehaviorDetectionEngine:

    # Thresholds (Phase 1 configurable constants)
    SPRAY_USER_THRESHOLD = 5
    SPRAY_WINDOW_MINUTES = 5

    ENUM_THRESHOLD = 3
    ENUM_WINDOW_MINUTES = 2

    SLOW_BRUTE_THRESHOLD = 10
    SLOW_BRUTE_WINDOW_MINUTES = 10

    def detect(self, events: List[RawEvent]) -> List[AttackEvent]:
        attacks = []

        events_by_ip = defaultdict(list)

        for event in events:
            if event.source_ip:
                events_by_ip[event.source_ip].append(event)

        for ip, ip_events in events_by_ip.items():
            ip_events.sort(key=lambda e: e.timestamp)

            spray = self._detect_password_spray(ip, ip_events)
            if spray:
                attacks.append(spray)

            enum = self._detect_enumeration(ip, ip_events)
            if enum:
                attacks.append(enum)

            slow = self._detect_slow_brute(ip, ip_events)
            if slow:
                attacks.append(slow)

        return attacks

    # -------------------------------------------------
    # Password Spray Detection
    # -------------------------------------------------

    def _detect_password_spray(self, ip: str, events: List[RawEvent]):
        failures = [
            e for e in events
            if e.event_type == EventType.AUTH_FAILURE and e.username
        ]

        for i in range(len(failures)):
            window = [failures[i]]

            for j in range(i + 1, len(failures)):
                if failures[j].timestamp - failures[i].timestamp <= timedelta(
                    minutes=self.SPRAY_WINDOW_MINUTES
                ):
                    window.append(failures[j])
                else:
                    break

            distinct_users = {e.username for e in window}

            if len(distinct_users) >= self.SPRAY_USER_THRESHOLD:
                notes = (
                    f"Password spray detected: "
                    f"{len(window)} failed attempts across "
                    f"{len(distinct_users)} distinct usernames "
                    f"within {self.SPRAY_WINDOW_MINUTES} minutes "
                    f"from IP {ip}. "
                    f"Indicates distributed credential guessing."
                )

                return self._build_attack(
                    ip,
                    window,
                    AttackType.PASSWORD_SPRAY,
                    SeverityLevel.HIGH,
                    confidence=0.85,
                    notes=notes
                )

        return None

    # -------------------------------------------------
    # Username Enumeration Detection
    # -------------------------------------------------

    def _detect_enumeration(self, ip: str, events: List[RawEvent]):
        invalids = [
            e for e in events
            if e.event_type == EventType.INVALID_USER_ATTEMPT
        ]

        for i in range(len(invalids)):
            window = [invalids[i]]

            for j in range(i + 1, len(invalids)):
                if invalids[j].timestamp - invalids[i].timestamp <= timedelta(
                    minutes=self.ENUM_WINDOW_MINUTES
                ):
                    window.append(invalids[j])
                else:
                    break

            if len(window) >= self.ENUM_THRESHOLD:
                notes = (
                    f"Username enumeration detected: "
                    f"{len(window)} invalid user attempts "
                    f"within {self.ENUM_WINDOW_MINUTES} minutes "
                    f"from IP {ip}. "
                    f"Suggests account discovery activity."
                )

                return self._build_attack(
                    ip,
                    window,
                    AttackType.USERNAME_ENUMERATION,
                    SeverityLevel.MEDIUM,
                    confidence=0.80,
                    notes=notes
                )

        return None

    # -------------------------------------------------
    # Slow Brute Force Detection
    # -------------------------------------------------

    def _detect_slow_brute(self, ip: str, events: List[RawEvent]):
        failures = [
            e for e in events
            if e.event_type == EventType.AUTH_FAILURE
        ]

        for i in range(len(failures)):
            window = [failures[i]]

            for j in range(i + 1, len(failures)):
                if failures[j].timestamp - failures[i].timestamp <= timedelta(
                    minutes=self.SLOW_BRUTE_WINDOW_MINUTES
                ):
                    window.append(failures[j])
                else:
                    break

            if len(window) >= self.SLOW_BRUTE_THRESHOLD:
                notes = (
                    f"Low-and-slow brute-force detected: "
                    f"{len(window)} authentication failures "
                    f"within {self.SLOW_BRUTE_WINDOW_MINUTES} minutes "
                    f"from IP {ip}. "
                    f"Pattern suggests evasion attempt."
                )

                return self._build_attack(
                    ip,
                    window,
                    AttackType.ABNORMAL_AUTH_PATTERN,
                    SeverityLevel.MEDIUM,
                    confidence=0.75,
                    notes=notes
                )

        return None

    # -------------------------------------------------
    # Attack Builder
    # -------------------------------------------------

    def _build_attack(
        self,
        ip,
        window,
        attack_type,
        severity,
        confidence,
        notes
    ):
        window.sort(key=lambda e: e.timestamp)

        return AttackEvent(
            attack_id=uuid4(),
            attack_type=attack_type,
            start_time=window[0].timestamp,
            end_time=window[-1].timestamp,
            source_ip=ip,
            target_service="sshd",
            related_event_ids=[e.event_id for e in window],
            frequency=len(window),
            confidence=confidence,
            severity=severity,
            analysis_notes=notes
        )
