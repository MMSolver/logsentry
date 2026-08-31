"""Parses SSH/auth log lines into LogEvent objects.

Handles the SSH daemon log line formats produced by OpenSSH's syslog
output: failed password attempts (with or without "invalid user"),
accepted logins (password or publickey), and "Invalid user" notices.
Timestamps in syslog lines omit the year, so it is backfilled with the
current year at parse time.
"""

import re
from datetime import datetime
from typing import Iterator, Optional

from logsentry.models import LogEvent

# Syslog-style leading timestamp, e.g. "Nov 12 08:23:45". The day field may
# be a single digit (optionally padded with extra whitespace by real
# syslog); \s+ tolerates either.
_TIMESTAMP_PATTERN = re.compile(
    r"^(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
)

# Tried in this order (most specific first) inside parse_line.
_FAILED_INVALID_USER_PATTERN = re.compile(
    r"Failed password for invalid user (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)"
)
_FAILED_PASSWORD_PATTERN = re.compile(
    r"Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)"
)
_ACCEPTED_PATTERN = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)"
)
_INVALID_USER_PATTERN = re.compile(r"Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)")


def _parse_timestamp(line: str) -> Optional[datetime]:
    """Extract and parse a leading syslog timestamp, backfilling the year.

    Syslog lines omit the year (e.g. "Nov 12 08:23:45"), so the current
    year is substituted in. Returns None if no timestamp is found at the
    start of the line or it cannot be parsed.
    """
    match = _TIMESTAMP_PATTERN.match(line)
    if match is None:
        return None

    normalized = f"{match.group('mon')} {int(match.group('day')):02d} {match.group('time')}"
    try:
        parsed = datetime.strptime(normalized, "%b %d %H:%M:%S")
    except ValueError:
        return None

    return parsed.replace(year=datetime.now().year)


def parse_line(line: str) -> Optional[LogEvent]:
    """Parse a single SSH/auth log line into a LogEvent, or None if it
    doesn't match a recognized SSH login-attempt pattern.

    Recognized formats, tried most-specific first:
        1. "Failed password for invalid user X from IP port PORT" -> failed
        2. "Failed password for X from IP port PORT" -> failed
        3. "Accepted password|publickey for X from IP port PORT" -> accepted
        4. "Invalid user X from IP" (no port) -> invalid_user

    Lines that match none of these patterns return None; no exception is
    raised for irrelevant/garbage input.
    """
    event_type: str
    username: str
    ip: str
    port: Optional[int]

    match = _FAILED_INVALID_USER_PATTERN.search(line)
    if match is not None:
        username, ip, port_str = match.groups()
        event_type = "failed"
        port = int(port_str)
    else:
        match = _FAILED_PASSWORD_PATTERN.search(line)
        if match is not None:
            username, ip, port_str = match.groups()
            event_type = "failed"
            port = int(port_str)
        else:
            match = _ACCEPTED_PATTERN.search(line)
            if match is not None:
                username, ip, port_str = match.groups()
                event_type = "accepted"
                port = int(port_str)
            else:
                match = _INVALID_USER_PATTERN.search(line)
                if match is not None:
                    username, ip = match.groups()
                    event_type = "invalid_user"
                    port = None
                else:
                    return None

    timestamp = _parse_timestamp(line)
    if timestamp is None:
        return None

    return LogEvent(
        timestamp=timestamp,
        ip=ip,
        username=username,
        event_type=event_type,
        port=port,
        raw=line.rstrip("\n"),
    )


def parse_file(path: str) -> Iterator[LogEvent]:
    """Stream-parse a log file into LogEvents, one line at a time.

    A generator: the file is read line-by-line (never loaded fully into
    memory), and lines that parse_line cannot recognize are silently
    skipped rather than raising.
    """
    with open(path, "r", encoding="utf-8") as log_file:
        for line in log_file:
            event = parse_line(line)
            if event is not None:
                yield event
