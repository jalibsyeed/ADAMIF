"""
PHASE 1 LIMITATION NOTICE:

This detection engine emits only ONE AttackEvent per IP
per detection run.

If multiple independent brute-force waves occur from the same IP
within the same dataset, only the first qualifying window
will generate an AttackEvent.

Multi-wave detection and incident correlation are intentionally
deferred to Phase 2 (Correlation & Intelligence Layer).
"""
"""
SSH brute-force detection engine.

Operates ONLY on RawEvent objects.
Produces AttackEvent objects.

No log parsing.
No mutation.
No severity guessing.
No ML.
"""

from collections import defaultdict
from datetime import timedelta
from typing import List
from uuid import uuid4

from src.core.raw_event import RawEvent
from src.core.attack_event import AttackEvent
from src.core.attack_types import AttackType, SeverityLevel


class SSHDetectionEngine:

    BURST_THRESHOLD = 5
    BURST_WINDOW_SECONDS = 60

    SLOW_THRESHOLD = 10
    SLOW_WINDOW_SECONDS = 300  # 5 minutes

    def detect(self, events: List[RawEvent]) -> List[AttackEvent]:
        """
        Detect brute-force patterns in provided RawEvents.
        """

        # Sort events by timestamp
        events = sorted(events, key=lambda e: e.timestamp)

        # Filter only AUTH_FAILURE with valid IP
        failure_events = [
            e for e in events
            if e.event_type.name == "AUTH_FAILURE" and e.source_ip is not None
        ]

        # Group by source_ip
        grouped = defaultdict(list)
        for event in failure_events:
            grouped[event.source_ip].append(event)

        attack_events: List[AttackEvent] = []

        for ip, ip_events in grouped.items():
            attack = self._detect_for_ip(ip, ip_events)
            if attack:
                attack_events.append(attack)

        return attack_events

    def _detect_for_ip(self, ip: str, events: List[RawEvent]) -> AttackEvent | None:
        """
        Apply burst and slow detection rules for a single IP.
        """

        # Burst Rule
        burst_attack = self._sliding_window_detect(
            events,
            threshold=self.BURST_THRESHOLD,
            window_seconds=self.BURST_WINDOW_SECONDS
        )

        if burst_attack:
            return self._build_attack_event(
                ip,
                burst_attack,
                severity=SeverityLevel.HIGH,
                confidence=0.9
            )

        # Slow Rule (only if burst not triggered)
        slow_attack = self._sliding_window_detect(
            events,
            threshold=self.SLOW_THRESHOLD,
            window_seconds=self.SLOW_WINDOW_SECONDS
        )

        if slow_attack:
            return self._build_attack_event(
                ip,
                slow_attack,
                severity=SeverityLevel.MEDIUM,
                confidence=0.75
            )

        return None

    def _sliding_window_detect(self, events: List[RawEvent], threshold: int, window_seconds: int):
        """
        Sliding window detection logic.
        Returns list of events if threshold met, else None.
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
        confidence: float
    ) -> AttackEvent:

        start_time = evidence_events[0].timestamp
        end_time = evidence_events[-1].timestamp

        return AttackEvent(
            attack_id=uuid4(),
            attack_type=AttackType.SSH_BRUTE_FORCE,
            start_time=start_time,
            end_time=end_time,
            source_ip=ip,
            target_service="sshd",
            related_event_ids=[e.event_id for e in evidence_events],
            frequency=len(evidence_events),
            confidence=confidence,
            severity=severity
        )
