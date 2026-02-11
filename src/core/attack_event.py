"""
AttackEvent Model

Represents an interpreted security-relevant behavior
derived from one or more RawEvent instances.
"""

from dataclasses import dataclass
from typing import List
from uuid import UUID
from datetime import datetime

from .attack_types import AttackType, SeverityLevel


@dataclass(frozen=True)
class AttackEvent:
    # Identity
    attack_id: UUID

    # Classification
    attack_type: AttackType

    # Time Window
    start_time: datetime
    end_time: datetime

    # Context
    source_ip: str
    target_service: str

    # Evidence
    related_event_ids: List[UUID]

    # Analysis
    frequency: int
    confidence: float
    severity: SeverityLevel

    def __post_init__(self):
        # Validate time window
        if self.end_time < self.start_time:
            raise ValueError("end_time cannot be earlier than start_time")

        # Validate frequency
        if self.frequency <= 0:
            raise ValueError("frequency must be greater than 0")

        # Validate confidence range
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("confidence must be between 0.0 and 1.0")

        # Validate related events
        if not self.related_event_ids:
            raise ValueError("AttackEvent must reference at least one RawEvent")

        # Validate types
        if not isinstance(self.attack_type, AttackType):
            raise TypeError("attack_type must be an AttackType enum")

        if not isinstance(self.severity, SeverityLevel):
            raise TypeError("severity must be a SeverityLevel enum")
