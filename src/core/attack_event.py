"""
AttackEvent Model

Represents an interpreted security-relevant behavior
derived from one or more RawEvent instances.
"""

from dataclasses import dataclass
from typing import List
from uuid import UUID
from datetime import datetime


@dataclass(frozen=True)
class AttackEvent:
    # Identity
    attack_id: UUID

    # Classification
    attack_type: str  # Example: "SSH_BRUTE_FORCE"

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
    severity: str
