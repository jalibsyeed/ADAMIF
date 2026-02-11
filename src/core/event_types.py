"""
Event type definitions for RawEvent.

These enums restrict allowed values and prevent free-text inconsistencies.
"""

from enum import Enum


class SourceType(str, Enum):
    AUTH_LOG = "AUTH_LOG"
    SYSTEMD_JOURNAL = "SYSTEMD_JOURNAL"
    FILE_WATCHER = "FILE_WATCHER"


class EventType(str, Enum):
    AUTH_SUCCESS = "AUTH_SUCCESS"
    AUTH_FAILURE = "AUTH_FAILURE"
    INVALID_USER_ATTEMPT = "INVALID_USER_ATTEMPT"
    SSH_CONNECTION_CLOSED = "SSH_CONNECTION_CLOSED"
    FILE_CREATED = "FILE_CREATED"
    FILE_MODIFIED = "FILE_MODIFIED"
    FILE_DELETED = "FILE_DELETED"
