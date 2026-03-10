"""
AttackEvent Model

Represents an interpreted security-relevant behavior
derived from one or more RawEvent instances.

This model is immutable and must contain:
- Classification
- Time window
- Evidence linkage
- Quantitative metrics
- Structured reasoning (analysis_notes)
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

    # Analysis Metrics
    frequency: int
    confidence: float
    severity: SeverityLevel

    # Structured reasoning (NEW — Phase 1 explainability enhancement)
    analysis_notes: str

    def __post_init__(self):
        # Time validation
        if self.end_time < self.start_time:
            raise ValueError("end_time cannot be earlier than start_time")

        # Frequency validation
        if self.frequency <= 0:
            raise ValueError("frequency must be greater than 0")

        # Confidence validation
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("confidence must be between 0.0 and 1.0")

        # Evidence validation
        if not self.related_event_ids:
            raise ValueError("AttackEvent must reference at least one RawEvent")

        # Enum validation
        if not isinstance(self.attack_type, AttackType):
            raise TypeError("attack_type must be an AttackType enum")

        if not isinstance(self.severity, SeverityLevel):
            raise TypeError("severity must be a SeverityLevel enum")

        # Reasoning validation
        if not self.analysis_notes or not self.analysis_notes.strip():
            raise ValueError("analysis_notes cannot be empty")
