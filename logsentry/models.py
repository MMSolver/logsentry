"""Data models shared across LogSentry's parser, detector, and reporter."""

from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional


@dataclass
class LogEvent:
    """A single parsed SSH/auth log line.

    Attributes:
        timestamp: When the event occurred (year defaults to the current
            year, since syslog timestamps omit it).
        ip: Source IP address the event originated from.
        username: Username involved in the login attempt, if any.
        event_type: One of "failed", "accepted", "invalid_user".
        port: Source port of the connection, if present in the log line.
        raw: The original, unmodified log line this event was parsed from.
    """

    timestamp: datetime
    ip: str
    username: Optional[str]
    event_type: str  # one of "failed", "accepted", "invalid_user"
    port: Optional[int]
    raw: str


@dataclass
class Alert:
    """A detected threat, produced by aggregating LogEvents for one IP.

    Attributes:
        ip: Source IP address the alert was raised for.
        severity: One of "LOW", "MEDIUM", "HIGH", "CRITICAL".
        alert_type: e.g. "brute_force", "user_enumeration",
            "successful_breach".
        failed_count: Number of failed login attempts observed for this IP.
        usernames_tried: Distinct usernames attempted by this IP.
        first_seen: Timestamp of the earliest event contributing to this
            alert.
        last_seen: Timestamp of the latest event contributing to this alert.
        description: Human-readable summary of why the alert was raised.
    """

    ip: str
    severity: str  # one of "LOW", "MEDIUM", "HIGH", "CRITICAL"
    alert_type: str  # e.g. "brute_force", "user_enumeration", "successful_breach"
    failed_count: int
    usernames_tried: List[str]
    first_seen: datetime
    last_seen: datetime
    description: str
