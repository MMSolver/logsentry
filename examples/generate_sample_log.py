"""Generates a deterministic, realistic sample SSH/auth log for LogSentry.

Produces a synthetic ``auth.log`` (OpenSSH syslog style) containing three
scenarios so the fixture exercises every detector code path (spec section
10, plan Task 5):

1. A handful of normal, spaced-out successful logins from different
   legitimate-looking internal IPs/users.
2. A heavy brute-force burst from one attacker IP: 30+ ``Failed password``
   attempts a couple of seconds apart, cycling through 8 distinct
   usernames (a mix of "invalid user" and valid-looking) -- enough to
   trigger both ``brute_force`` and ``user_enumeration`` under the spec's
   default thresholds (``threshold=5``, ``window=60``,
   ``ENUM_THRESHOLD=5``).
3. A second attacker IP that fails several times and then succeeds --
   enough to trigger ``successful_breach`` (CRITICAL).

All timestamps are sequential and computed from a fixed base ``datetime``
(no ``random`` calls) so the generated text is byte-for-byte stable across
runs -- this is what lets the output be committed as a test fixture in
``tests/sample_logs/auth.log``.
"""

import argparse
from datetime import datetime, timedelta
from typing import List

# Syslog lines omit the year; the parser backfills datetime.now().year at
# parse time, so the year chosen here is arbitrary and never surfaces.
_BASE_TIMESTAMP = datetime(2024, 8, 30, 8, 0, 0)

_SYSLOG_TIME_FORMAT = "%b %d %H:%M:%S"
_HOST_PREFIX = "sshd[1234]:"

# Usernames cycled through the brute-force burst -- a mix of common
# attacker guesses. Eight distinct names comfortably clears
# config.ENUM_THRESHOLD (5) within any 60-second window of the burst.
_BRUTE_FORCE_USERNAMES = [
    "root",
    "admin",
    "test",
    "oracle",
    "postgres",
    "guest",
    "ubuntu",
    "administrator",
]


def _fmt(ts: datetime) -> str:
    """Format a datetime as a syslog-style timestamp (e.g. 'Aug 30 08:00:00')."""
    return ts.strftime(_SYSLOG_TIME_FORMAT)


def _normal_logins(start: datetime) -> List[str]:
    """Build a handful of normal, spaced-out successful logins.

    Different legitimate-looking internal (10.0.0.x) IPs and users,
    minutes apart -- ordinary daily activity for the detector to ignore.
    """
    entries = [
        (0, "10.0.0.8", "deploy", "password", 51000),
        (12 * 60 + 33, "10.0.0.15", "admin", "publickey", 51122),
        (25 * 60 + 7, "10.0.0.22", "alice", "password", 51344),
        (41 * 60 + 52, "10.0.0.9", "bob", "password", 51455),
        (63 * 60 + 19, "10.0.0.8", "deploy", "publickey", 51900),
    ]
    lines = []
    for offset_seconds, ip, username, method, port in entries:
        ts = start + timedelta(seconds=offset_seconds)
        lines.append(
            f"{_fmt(ts)} {_HOST_PREFIX} Accepted {method} for {username} "
            f"from {ip} port {port} ssh2"
        )
    return lines


def _brute_force_burst(start: datetime, attacker_ip: str, attempt_count: int) -> List[str]:
    """Build a tight-window brute-force burst from a single attacker IP.

    Attempts are 2 seconds apart (well under the default 60s window) and
    cycle through _BRUTE_FORCE_USERNAMES, alternating between the
    "invalid user" and plain "Failed password" line formats so both
    parser patterns are exercised. `attempt_count` >= 30 with 8 distinct
    usernames guarantees both brute_force (>=5 failures/window) and
    user_enumeration (>=5 distinct usernames/window) trigger under the
    spec's default thresholds.
    """
    lines = []
    base_port = 42000
    for i in range(attempt_count):
        ts = start + timedelta(seconds=2 * i)
        username = _BRUTE_FORCE_USERNAMES[i % len(_BRUTE_FORCE_USERNAMES)]
        port = base_port + i
        if i % 2 == 0:
            lines.append(
                f"{_fmt(ts)} {_HOST_PREFIX} Failed password for invalid user "
                f"{username} from {attacker_ip} port {port} ssh2"
            )
        else:
            lines.append(
                f"{_fmt(ts)} {_HOST_PREFIX} Failed password for {username} "
                f"from {attacker_ip} port {port} ssh2"
            )
    return lines


def _successful_breach(start: datetime, attacker_ip: str, failed_count: int) -> List[str]:
    """Build a failed-then-accepted breach scenario for a second attacker IP.

    `failed_count` Failed password attempts against "root", 3 seconds
    apart, followed by one Accepted password -- this is what the detector
    treats as a successful_breach (CRITICAL), taking precedence over a
    plain brute_force alert for the same IP.
    """
    lines = []
    base_port = 40001
    for i in range(failed_count):
        ts = start + timedelta(seconds=3 * i)
        port = base_port + i
        lines.append(
            f"{_fmt(ts)} {_HOST_PREFIX} Failed password for root "
            f"from {attacker_ip} port {port} ssh2"
        )
    accepted_ts = start + timedelta(seconds=3 * failed_count)
    accepted_port = base_port + failed_count
    lines.append(
        f"{_fmt(accepted_ts)} {_HOST_PREFIX} Accepted password for root "
        f"from {attacker_ip} port {accepted_port} ssh2"
    )
    return lines


def generate_log(burst_size: int = 32) -> str:
    """Return the full deterministic sample auth.log text.

    `burst_size` controls the number of failed attempts in the
    brute-force burst (must stay >= 30 to satisfy the spec's "30+
    attempts" requirement and to clear both the brute_force and
    user_enumeration thresholds). Named `burst_size` rather than the
    plan's suggested `num_lines` since the generator composes three fixed
    scenarios rather than an arbitrary flat line count -- this is a
    deliberate deviation, flagged per the plan's "(or similar)" allowance.

    Timestamps are sequential and computed from a fixed base datetime (no
    randomness), so repeated calls produce byte-identical output -- this
    determinism is what makes the output safe to commit as a stable test
    fixture.
    """
    lines: List[str] = []

    normal_start = _BASE_TIMESTAMP
    lines.extend(_normal_logins(normal_start))

    burst_start = normal_start + timedelta(minutes=20)
    lines.extend(_brute_force_burst(burst_start, "203.0.113.5", burst_size))

    breach_start = burst_start + timedelta(minutes=5)
    lines.extend(_successful_breach(breach_start, "198.51.100.23", 6))

    return "\n".join(lines) + "\n"


def main() -> None:
    """CLI entry point: write generate_log()'s output to --output (default demo.log)."""
    parser = argparse.ArgumentParser(
        description="Generate a deterministic sample SSH/auth log for LogSentry."
    )
    parser.add_argument(
        "--output",
        default="demo.log",
        help="Path to write the generated log to (default: demo.log).",
    )
    args = parser.parse_args()

    log_text = generate_log()
    with open(args.output, "w", encoding="utf-8") as output_file:
        output_file.write(log_text)

    print(f"Wrote sample log to {args.output}")


if __name__ == "__main__":
    main()
