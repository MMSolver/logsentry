"""Tests for logsentry.parser (TDD red step -- parser.py does not exist yet).

Covers the four SSH auth-log line formats, timestamp year backfill,
graceful skipping of unrelated lines, and parse_file's generator/streaming
behavior.
"""

import inspect
from datetime import datetime

from logsentry.parser import parse_file, parse_line


def test_parse_line_failed_invalid_user():
    """'Failed password for invalid user X' -> failed event, username set."""
    line = (
        "Nov 12 08:23:45 host sshd[1234]: Failed password for invalid user "
        "admin from 203.0.113.5 port 54321 ssh2"
    )
    event = parse_line(line)

    assert event is not None
    assert event.event_type == "failed"
    assert event.username == "admin"
    assert event.ip == "203.0.113.5"
    assert event.port == 54321


def test_parse_line_failed_valid_user():
    """'Failed password for X' (no 'invalid user') -> failed event."""
    line = (
        "Nov 12 08:23:46 host sshd[1234]: Failed password for root from "
        "203.0.113.5 port 54322 ssh2"
    )
    event = parse_line(line)

    assert event is not None
    assert event.event_type == "failed"
    assert event.username == "root"
    assert event.ip == "203.0.113.5"
    assert event.port == 54322


def test_parse_line_accepted_password():
    """'Accepted password for X' -> accepted event."""
    line = (
        "Nov 12 09:00:00 host sshd[5678]: Accepted password for deploy "
        "from 10.0.0.8 port 51000 ssh2"
    )
    event = parse_line(line)

    assert event is not None
    assert event.event_type == "accepted"
    assert event.username == "deploy"
    assert event.ip == "10.0.0.8"
    assert event.port == 51000


def test_parse_line_accepted_publickey():
    """'Accepted publickey for X' -> accepted event (publickey variant)."""
    line = (
        "Nov 12 09:00:01 host sshd[5678]: Accepted publickey for deploy "
        "from 10.0.0.8 port 51000 ssh2"
    )
    event = parse_line(line)

    assert event is not None
    assert event.event_type == "accepted"
    assert event.username == "deploy"
    assert event.ip == "10.0.0.8"
    assert event.port == 51000


def test_parse_line_invalid_user_no_port():
    """'Invalid user X from IP' (no port in the line) -> invalid_user event."""
    line = "Nov 12 09:05:00 host sshd[9999]: Invalid user test from 192.168.1.50"
    event = parse_line(line)

    assert event is not None
    assert event.event_type == "invalid_user"
    assert event.username == "test"
    assert event.ip == "192.168.1.50"
    assert event.port is None


def test_parse_line_unrelated_line_returns_none():
    """A non-SSH / garbage syslog line does not match any pattern -> None."""
    line = "Nov 12 09:10:00 host CRON[111]: (root) CMD (run-parts /etc/cron.hourly)"
    assert parse_line(line) is None

    assert parse_line("not even close to a log line") is None


def test_parse_line_timestamp_year_defaults_to_current_year():
    """Syslog timestamps omit the year; parser must backfill datetime.now().year."""
    line = (
        "Nov 12 08:23:45 host sshd[1234]: Failed password for root from "
        "203.0.113.5 port 54322 ssh2"
    )
    event = parse_line(line)

    assert event is not None
    assert event.timestamp.year == datetime.now().year


def test_parse_file_skips_irrelevant_lines(tmp_path):
    """parse_file mixes valid and irrelevant lines; only valid ones yield events."""
    log_path = tmp_path / "auth.log"
    log_path.write_text(
        "\n".join(
            [
                "Nov 12 08:23:45 host sshd[1234]: Failed password for root "
                "from 203.0.113.5 port 54322 ssh2",
                "Nov 12 08:23:50 host CRON[111]: (root) CMD (run-parts /etc/cron.hourly)",
                "Nov 12 08:24:00 host sshd[1235]: Accepted password for deploy "
                "from 10.0.0.8 port 51000 ssh2",
                "some completely unrelated garbage line",
                "Nov 12 08:24:10 host sshd[1236]: Invalid user test from 192.168.1.50",
            ]
        ),
        encoding="utf-8",
    )

    events = list(parse_file(str(log_path)))

    assert len(events) == 3
    assert [e.event_type for e in events] == ["failed", "accepted", "invalid_user"]


def test_parse_file_returns_generator(tmp_path):
    """parse_file must be a generator (streaming), not eagerly return a list."""
    log_path = tmp_path / "auth.log"
    log_path.write_text(
        "Nov 12 08:23:45 host sshd[1234]: Failed password for root from "
        "203.0.113.5 port 54322 ssh2\n",
        encoding="utf-8",
    )

    result = parse_file(str(log_path))

    assert inspect.isgenerator(result)
