"""Tests for logsentry.detector (TDD red step -- detector.py/config.py do
not exist yet).

Covers the fixture-driven scenarios (brute-force burst, user enumeration,
successful breach) plus synthetic sliding-window boundary cases, the full
severity scoring table (spec section 6.4), description content, and
severity sortability.

The threshold/window/enum_threshold values below (5, 60, 5) and the
severity boundaries (50, 15, 15) mirror the defaults `logsentry/config.py`
is specified to define in Task 7. They are hardcoded here rather than
imported so this file's only import failure is `logsentry.detector`
(config.py is created alongside detector.py in the green step).
"""

from datetime import datetime, timedelta
from pathlib import Path

from logsentry.detector import detect
from logsentry.models import LogEvent
from logsentry.parser import parse_file

FIXTURE_PATH = Path(__file__).parent / "sample_logs" / "auth.log"

# The two attacker IPs baked into tests/sample_logs/auth.log (Task 5).
BURST_IP = "203.0.113.5"  # 32-attempt brute-force burst, 8 distinct usernames
BREACH_IP = "198.51.100.23"  # 6 failed then 1 accepted

# Mirrors logsentry/config.py defaults (spec section 8 / Task 7).
THRESHOLD = 5
WINDOW = 60
ENUM_THRESHOLD = 5
HIGH_FAILED_COUNT = 50
HIGH_UNIQUE_USERS = 15

BASE_TIME = datetime(2026, 8, 30, 8, 0, 0)


def _event(ip, username, event_type, offset_seconds, base=BASE_TIME, port=40000):
    """Build a synthetic LogEvent `offset_seconds` after `base`."""
    return LogEvent(
        timestamp=base + timedelta(seconds=offset_seconds),
        ip=ip,
        username=username,
        event_type=event_type,
        port=port,
        raw=f"synthetic {event_type} for {username} from {ip}",
    )


# --- 1 & 2: fixture-driven brute-force + user enumeration for BURST_IP ----


def test_detect_fixture_burst_ip_produces_brute_force_alert():
    """The 32-attempt burst from BURST_IP must yield a brute_force alert."""
    events = list(parse_file(str(FIXTURE_PATH)))
    alerts = detect(events)

    assert any(a.ip == BURST_IP and a.alert_type == "brute_force" for a in alerts)


def test_detect_fixture_burst_ip_produces_user_enumeration_alert():
    """The same burst tries 8 distinct usernames -> user_enumeration alert too."""
    events = list(parse_file(str(FIXTURE_PATH)))
    alerts = detect(events)

    assert any(
        a.ip == BURST_IP and a.alert_type == "user_enumeration" for a in alerts
    )


# --- 3: fixture-driven successful breach for BREACH_IP --------------------


def test_detect_fixture_breach_ip_produces_exactly_one_critical_breach_alert():
    """6 failed + 1 accepted from BREACH_IP -> exactly one CRITICAL
    successful_breach alert (breach supersedes a plain brute_force alert
    for the same IP -- it must not be double-reported)."""
    events = list(parse_file(str(FIXTURE_PATH)))
    alerts = detect(events)

    breach_ip_alerts = [a for a in alerts if a.ip == BREACH_IP]

    assert len(breach_ip_alerts) == 1
    assert breach_ip_alerts[0].alert_type == "successful_breach"
    assert breach_ip_alerts[0].severity == "CRITICAL"


# --- 4, 5, 6: sliding-window boundary (synthetic) --------------------------


def test_detect_sliding_window_boundary_inclusive_triggers_brute_force():
    """Exactly `threshold` failed attempts spanning exactly `window` seconds
    IS a brute_force alert (boundary is inclusive at the threshold count)."""
    ip = "192.0.2.10"
    events = [
        _event(ip, "root", "failed", offset) for offset in (0, 15, 30, 45, 60)
    ]

    alerts = detect(events, threshold=THRESHOLD, window=WINDOW, enum_threshold=ENUM_THRESHOLD)

    assert any(a.ip == ip and a.alert_type == "brute_force" for a in alerts)


def test_detect_below_threshold_produces_no_brute_force_alert():
    """`threshold - 1` failed attempts within the window -> no brute_force alert."""
    ip = "192.0.2.11"
    events = [_event(ip, "root", "failed", offset) for offset in (0, 15, 30, 45)]

    alerts = detect(events, threshold=THRESHOLD, window=WINDOW, enum_threshold=ENUM_THRESHOLD)

    assert not any(a.ip == ip and a.alert_type == "brute_force" for a in alerts)


def test_detect_attempts_spread_outside_window_produces_no_brute_force_alert():
    """`threshold` failed attempts, but each consecutive pair is spaced more
    than `window` seconds apart -> no single window contains them all, so
    no brute_force alert."""
    ip = "192.0.2.12"
    gap = WINDOW + 10
    events = [_event(ip, "root", "failed", i * gap) for i in range(THRESHOLD)]

    alerts = detect(events, threshold=THRESHOLD, window=WINDOW, enum_threshold=ENUM_THRESHOLD)

    assert not any(a.ip == ip and a.alert_type == "brute_force" for a in alerts)


# --- 7: severity scoring table (spec 6.4), one synthetic case each --------


def test_detect_severity_failed_then_accepted_is_critical():
    ip = "192.0.2.20"
    events = [
        _event(ip, "root", "failed", 0),
        _event(ip, "root", "failed", 5),
        _event(ip, "root", "accepted", 10),
    ]

    alerts = detect(events, threshold=THRESHOLD, window=WINDOW, enum_threshold=ENUM_THRESHOLD)
    matching = [a for a in alerts if a.ip == ip]

    assert matching
    assert any(a.severity == "CRITICAL" for a in matching)


def test_detect_severity_50_plus_failed_attempts_no_breach_is_high():
    ip = "192.0.2.21"
    events = [_event(ip, "root", "failed", i) for i in range(HIGH_FAILED_COUNT)]

    alerts = detect(events, threshold=THRESHOLD, window=WINDOW, enum_threshold=ENUM_THRESHOLD)
    matching = [a for a in alerts if a.ip == ip]

    assert matching
    assert any(a.severity == "HIGH" for a in matching)


def test_detect_severity_15_plus_distinct_usernames_no_breach_is_high():
    ip = "192.0.2.22"
    events = [_event(ip, f"user{i}", "failed", i) for i in range(HIGH_UNIQUE_USERS)]

    alerts = detect(events, threshold=THRESHOLD, window=WINDOW, enum_threshold=ENUM_THRESHOLD)
    matching = [a for a in alerts if a.ip == ip]

    assert matching
    assert any(a.severity == "HIGH" for a in matching)


def test_detect_severity_15_to_49_failed_attempts_is_medium():
    ip = "192.0.2.23"
    events = [_event(ip, "root", "failed", i) for i in range(20)]  # in [15, 49]

    alerts = detect(events, threshold=THRESHOLD, window=WINDOW, enum_threshold=ENUM_THRESHOLD)
    matching = [a for a in alerts if a.ip == ip]

    assert matching
    assert any(a.severity == "MEDIUM" for a in matching)


def test_detect_severity_threshold_to_14_failed_attempts_is_low():
    ip = "192.0.2.24"
    events = [_event(ip, "root", "failed", i) for i in range(10)]  # in [threshold, 14]

    alerts = detect(events, threshold=THRESHOLD, window=WINDOW, enum_threshold=ENUM_THRESHOLD)
    matching = [a for a in alerts if a.ip == ip]

    assert matching
    assert any(a.severity == "LOW" for a in matching)


# --- 8: description content -------------------------------------------------


def test_detect_alert_description_contains_ip_and_failed_count():
    """description isn't asserted verbatim, just that it's meaningful --
    it should mention the IP and the failed count."""
    ip = "192.0.2.25"
    events = [_event(ip, "root", "failed", i) for i in range(7)]

    alerts = detect(events, threshold=THRESHOLD, window=WINDOW, enum_threshold=ENUM_THRESHOLD)
    matching = [a for a in alerts if a.ip == ip]

    assert matching
    alert = matching[0]
    assert alert.description
    assert ip in alert.description
    assert str(alert.failed_count) in alert.description


# --- 9: severities are checkable / sortable by priority ---------------------


def test_detect_alerts_severities_are_sortable_by_priority():
    """When multiple alerts of different severities exist, they can be
    sorted CRITICAL > HIGH > MEDIUM > LOW (reporter.py relies on this)."""
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    critical_ip = "192.0.2.30"
    high_ip = "192.0.2.31"
    medium_ip = "192.0.2.32"
    low_ip = "192.0.2.33"

    events = []
    events += [
        _event(critical_ip, "root", "failed", 0),
        _event(critical_ip, "root", "accepted", 5),
    ]
    events += [_event(high_ip, "root", "failed", i) for i in range(HIGH_FAILED_COUNT)]
    events += [_event(medium_ip, "root", "failed", i) for i in range(20)]
    events += [_event(low_ip, "root", "failed", i) for i in range(10)]

    alerts = detect(events, threshold=THRESHOLD, window=WINDOW, enum_threshold=ENUM_THRESHOLD)

    # Every severity produced is one of the four valid literals.
    assert {a.severity for a in alerts} <= set(severity_order)

    ip_by_severity = {a.severity: a.ip for a in alerts}
    assert ip_by_severity.get("CRITICAL") == critical_ip
    assert ip_by_severity.get("HIGH") == high_ip
    assert ip_by_severity.get("MEDIUM") == medium_ip
    assert ip_by_severity.get("LOW") == low_ip

    ordered = sorted(alerts, key=lambda a: severity_order.index(a.severity))

    assert ordered[0].severity == "CRITICAL"
    assert ordered[-1].severity == "LOW"
