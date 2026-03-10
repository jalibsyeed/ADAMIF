"""
Design Limitation (Phase 1):

This detection engine emits only ONE AttackEvent per source IP
per detection execution.

If multiple independent brute-force waves occur from the same IP
within the same dataset, only the first qualifying window will
generate an AttackEvent.

Multi-wave detection, historical tracking, and cross-rule
correlation are intentionally deferred to Phase 2
(Correlation & Intelligence Layer).
"""
"""
SSH Detection Engine

Responsible for detecting:
- Burst brute-force attempts
- Slow brute-force attempts

Operates strictly on RawEvent objects.
No ingestion logic.
No correlation.
"""

from typing import List, Dict
from datetime import timedelta
from uuid import uuid4

from src.core.raw_event import RawEvent
from src.core.attack_event import AttackEvent
from src.core.attack_types import AttackType, SeverityLevel
from src.core.event_types import EventType


class SSHDetectionEngine:
    """
    Rule-based SSH brute-force detection engine.
    """

    # Detection thresholds
    BURST_THRESHOLD = 5
    BURST_WINDOW_SECONDS = 60

    SLOW_THRESHOLD = 10
    SLOW_WINDOW_SECONDS = 300

    def detect(self, events: List[RawEvent]) -> List[AttackEvent]:
        """
        Detect brute-force patterns grouped by source IP.
        """
        ip_groups: Dict[str, List[RawEvent]] = {}

        for event in events:
            if event.event_type == EventType.AUTH_FAILURE and event.source_ip:
                ip_groups.setdefault(event.source_ip, []).append(event)

        attacks: List[AttackEvent] = []

        for ip, ip_events in ip_groups.items():
            ip_events.sort(key=lambda e: e.timestamp)

            burst = self._sliding_window_detect(
                ip_events,
                self.BURST_THRESHOLD,
                self.BURST_WINDOW_SECONDS
            )

            if burst:
                attacks.append(
                    self._build_attack_event(
                        ip,
                        burst,
                        severity=SeverityLevel.HIGH,
                        confidence=0.90,
                        detection_type="burst"
                    )
                )
                continue

            slow = self._sliding_window_detect(
                ip_events,
                self.SLOW_THRESHOLD,
                self.SLOW_WINDOW_SECONDS
            )

            if slow:
                attacks.append(
                    self._build_attack_event(
                        ip,
                        slow,
                        severity=SeverityLevel.MEDIUM,
                        confidence=0.75,
                        detection_type="slow"
                    )
                )

        return attacks

    def _sliding_window_detect(
        self,
        events: List[RawEvent],
        threshold: int,
        window_seconds: int
    ) -> List[RawEvent] | None:
        """
        Sliding window detection logic.
        """

        for i in range(len(events)):
            window_events = [events[i]]

            for j in range(i + 1, len(events)):
                delta = events[j].timestamp - events[i].timestamp
                if delta <= timedelta(seconds=window_seconds):
                    window_events.append(events[j])
                else:
                    break

            if len(window_events) >= threshold:
                return window_events

        return None

    def _build_attack_event(
        self,
        ip: str,
        evidence_events: List[RawEvent],
        severity: SeverityLevel,
        confidence: float,
        detection_type: str
    ) -> AttackEvent:

        start_time = evidence_events[0].timestamp
        end_time = evidence_events[-1].timestamp
        frequency = len(evidence_events)

        if detection_type == "burst":
            notes = (
                f"Detected burst brute-force pattern: "
                f"{frequency} failed authentication attempts "
                f"within {self.BURST_WINDOW_SECONDS} seconds "
                f"from source IP {ip}. "
                f"Confidence elevated due to high event density."
            )
        else:
            notes = (
                f"Detected slow brute-force pattern: "
                f"{frequency} failed authentication attempts "
                f"within {self.SLOW_WINDOW_SECONDS} seconds "
                f"from source IP {ip}. "
                f"Pattern indicates potential evasion attempt."
            )

        return AttackEvent(
            attack_id=uuid4(),
            attack_type=AttackType.SSH_BRUTE_FORCE,
            start_time=start_time,
            end_time=end_time,
            source_ip=ip,
            target_service="sshd",
            related_event_ids=[e.event_id for e in evidence_events],
            frequency=frequency,
            confidence=confidence,
            severity=severity,
            analysis_notes=notes
        )
