"""
Strict attack classifications and severity levels.
Prevents free-text inconsistencies.
"""

from enum import Enum


class AttackType(str, Enum):
    SSH_BRUTE_FORCE = "SSH_BRUTE_FORCE"
    PASSWORD_SPRAY = "PASSWORD_SPRAY"
    USERNAME_ENUMERATION = "USERNAME_ENUMERATION"
    ABNORMAL_AUTH_PATTERN = "ABNORMAL_AUTH_PATTERN"
    SUSPICIOUS_FILE_ACTIVITY = "SUSPICIOUS_FILE_ACTIVITY"


class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
