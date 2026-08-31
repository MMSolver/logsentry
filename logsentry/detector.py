"""Turns parsed LogEvents into Alerts using sliding-window brute-force
detection, user-enumeration detection, and successful-breach detection
(spec section 6).

Detection order per IP (spec section 13 step 5):
    1. Successful breach (highest priority -- supersedes everything else
       for that IP).
    2. Brute-force (sliding window over failed attempts).
    3. User enumeration (distinct usernames within the same window that
       triggered brute-force).

All thresholds and severity boundaries come from `logsentry.config` --
no magic numbers live in this module.
"""

from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

from logsentry import config
from logsentry.models import Alert, LogEvent


def _max_failed_window(
    failed_events: List[LogEvent], window_seconds: int
) -> Optional[Tuple[int, Set[str], datetime, datetime]]:
    """Find the largest run of failed attempts (by timestamp) that all fall
    within `window_seconds` of each other.

    Sorts the IP's failed events by timestamp (O(n log n)), then scans once
    with a two-pointer sliding window: `left` only ever advances forward,
    so the scan itself is O(n). Overall complexity per IP is therefore
    O(n log n), dominated by the sort -- never O(n^2), even on an
    adversarial (e.g. all-same-timestamp) input.

    Returns (failed_count, distinct_usernames, first_seen, last_seen) for
    the widest such window, or None if there are no failed events at all.
    The window boundary is inclusive: a span of exactly `window_seconds`
    counts as "within" the window.
    """
    if not failed_events:
        return None

    sorted_events = sorted(failed_events, key=lambda e: e.timestamp)

    left = 0
    best_left, best_right = 0, 0
    for right in range(len(sorted_events)):
        while (
            sorted_events[right].timestamp - sorted_events[left].timestamp
        ).total_seconds() > window_seconds:
            left += 1
        if right - left > best_right - best_left:
            best_left, best_right = left, right

    window_slice = sorted_events[best_left : best_right + 1]
    usernames = {e.username for e in window_slice if e.username}
    return (
        len(window_slice),
        usernames,
        window_slice[0].timestamp,
        window_slice[-1].timestamp,
    )


def _detect_breach(ip: str, ip_events: List[LogEvent]) -> Optional[Alert]:
    """Detect a "failed attempts followed by a successful login" pattern
    for one IP (spec section 6.3) -- CRITICAL, highest priority.

    Walks the IP's events in chronological order; as soon as an "accepted"
    event is seen with at least one prior "failed" event, a breach alert is
    built from every failed attempt seen so far (usernames_tried, first
    seen at the earliest of those failed attempts, last seen at the
    successful login). Returns None if the IP never has an accepted event
    preceded by a failed one.
    """
    sorted_events = sorted(ip_events, key=lambda e: e.timestamp)

    failed_so_far: List[LogEvent] = []
    for event in sorted_events:
        if event.event_type == "failed":
            failed_so_far.append(event)
        elif event.event_type == "accepted" and failed_so_far:
            usernames = sorted({e.username for e in failed_so_far if e.username})
            failed_count = len(failed_so_far)
            description = (
                f"{ip} made {failed_count} failed login attempt(s) followed by a "
                f"successful login as '{event.username}' -- possible successful breach"
            )
            return Alert(
                ip=ip,
                severity="CRITICAL",
                alert_type="successful_breach",
                failed_count=failed_count,
                usernames_tried=usernames,
                first_seen=failed_so_far[0].timestamp,
                last_seen=event.timestamp,
                description=description,
            )

    return None


def _score_severity(failed_count: int, unique_usernames: int, threshold: int) -> str:
    """Score severity for a brute-force/user-enumeration alert per the
    spec 6.4 table, using `config.py`'s boundaries.

    CRITICAL is not scored here: it applies only to the failed-then-accepted
    (successful_breach) pattern, handled entirely by `_detect_breach`.
    Callers only invoke this once `failed_count >= threshold` already holds
    (that's the brute-force eligibility check), so LOW is a safe default
    for the remaining [threshold, MEDIUM_FAILED_COUNT) range.
    """
    if failed_count >= config.HIGH_FAILED_COUNT or unique_usernames >= config.HIGH_UNIQUE_USERS:
        return "HIGH"
    if failed_count >= config.MEDIUM_FAILED_COUNT:
        return "MEDIUM"
    return "LOW"


def _brute_force_description(ip: str, failed_count: int, usernames: List[str], window_seconds: int) -> str:
    """Build a human-readable description for a brute_force alert."""
    return (
        f"{ip} made {failed_count} failed login attempts within a {window_seconds}s "
        f"window, trying {len(usernames)} distinct username(s)"
    )


def _user_enumeration_description(ip: str, failed_count: int, usernames: List[str], window_seconds: int) -> str:
    """Build a human-readable description for a user_enumeration alert."""
    return (
        f"{ip} tried {len(usernames)} distinct usernames within a {window_seconds}s "
        f"window ({failed_count} failed attempts total) -- possible user enumeration"
    )


def detect(
    events: List[LogEvent],
    threshold: int = config.DEFAULT_THRESHOLD,
    window: int = config.DEFAULT_WINDOW,
    enum_threshold: int = config.ENUM_THRESHOLD,
) -> List[Alert]:
    """Detect brute-force, user-enumeration, and successful-breach patterns
    across `events`, returning the resulting Alerts (spec section 6).

    Merging judgment call (documented per the plan's Task 7 instructions):
    for an IP whose brute-force-eligible window also tries
    `>= enum_threshold` distinct usernames, this function emits **two**
    separate Alert objects for that IP -- one `alert_type="brute_force"`
    and one `alert_type="user_enumeration"` -- rather than collapsing them
    into a single alert. Both describe the same underlying window (same
    failed_count/usernames_tried/first_seen/last_seen/severity) but carry
    distinct `alert_type` values, since callers (tests, and eventually
    reporter.py) need to be able to tell "this IP is flooding" apart from
    "this IP is also fishing for valid usernames" as independently
    reachable facts about the IP, not just prose folded into one
    description. `successful_breach` is the one alert_type that truly
    supersedes the others: if an IP has a failed-then-accepted pattern, it
    gets exactly one CRITICAL `successful_breach` alert and no separate
    brute_force/user_enumeration alert for the same IP -- a plain
    brute-force flood that ends in a successful login is a confirmed
    breach, not a brute-force attempt in progress, so reporting both would
    double-count the same underlying incident.

    Ordering is not guaranteed / not sorted here -- `reporter.py` sorts for
    display using `config.SEVERITY_ORDER`.
    """
    alerts: List[Alert] = []

    events_by_ip: Dict[str, List[LogEvent]] = defaultdict(list)
    for event in events:
        events_by_ip[event.ip].append(event)

    for ip, ip_events in events_by_ip.items():
        breach_alert = _detect_breach(ip, ip_events)
        if breach_alert is not None:
            alerts.append(breach_alert)
            continue  # breach supersedes brute_force/user_enumeration for this IP

        failed_events = [e for e in ip_events if e.event_type == "failed"]
        window_result = _max_failed_window(failed_events, window)
        if window_result is None:
            continue

        failed_count, username_set, first_seen, last_seen = window_result
        if failed_count < threshold:
            continue

        usernames_tried = sorted(username_set)
        severity = _score_severity(failed_count, len(usernames_tried), threshold)

        alerts.append(
            Alert(
                ip=ip,
                severity=severity,
                alert_type="brute_force",
                failed_count=failed_count,
                usernames_tried=usernames_tried,
                first_seen=first_seen,
                last_seen=last_seen,
                description=_brute_force_description(ip, failed_count, usernames_tried, window),
            )
        )

        if len(usernames_tried) >= enum_threshold:
            alerts.append(
                Alert(
                    ip=ip,
                    severity=severity,
                    alert_type="user_enumeration",
                    failed_count=failed_count,
                    usernames_tried=usernames_tried,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    description=_user_enumeration_description(ip, failed_count, usernames_tried, window),
                )
            )

    return alerts
