"""Central configuration for LogSentry's detection thresholds and severity
scoring boundaries (spec section 8).

`detector.py` must not hardcode any of these values -- every threshold used
in detection logic is defined here exactly once, and the CLI (Task 10) may
override the threshold/window defaults per-run without touching this file.
"""

from typing import List

# --- Sliding-window brute-force detection defaults (spec section 6.1) -----

#: Minimum number of failed login attempts from one IP, within `DEFAULT_WINDOW`
#: seconds, required to raise a brute_force alert.
DEFAULT_THRESHOLD: int = 5

#: Size, in seconds, of the sliding time window used for brute-force and
#: user-enumeration detection.
DEFAULT_WINDOW: int = 60

# --- User enumeration / credential stuffing (spec section 6.2) ------------

#: Minimum number of distinct usernames tried by one IP within a single
#: brute-force-eligible window to additionally raise a user_enumeration
#: alert.
ENUM_THRESHOLD: int = 5

# --- Severity scoring boundaries (spec section 6.4) ------------------------

#: failed_count at or above this value (regardless of unique usernames)
#: scores HIGH.
HIGH_FAILED_COUNT: int = 50

#: Distinct usernames tried at or above this value (regardless of failed
#: count) scores HIGH.
HIGH_UNIQUE_USERS: int = 15

#: failed_count at or above this value (and below HIGH_FAILED_COUNT) scores
#: MEDIUM. Below this (but at/above the detection threshold) scores LOW.
MEDIUM_FAILED_COUNT: int = 15

#: Severity literals ordered from most to least severe. reporter.py (Task 9)
#: sorts and filters (`--min-severity`) using this list rather than a
#: duplicated ad-hoc ordering.
SEVERITY_ORDER: List[str] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
