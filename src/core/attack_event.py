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
