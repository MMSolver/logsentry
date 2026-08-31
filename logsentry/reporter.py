"""Renders detection results (`LogEvent`/`Alert`) as CLI output, JSON, CSV,
and HTML (spec section 7).

Security note (recorded during Task 8's audit of `parser.py`/`detector.py`,
binding on this module):

- `LogEvent`/`Alert` fields such as `ip`, `username`, `usernames_tried`,
  `description`, and `raw` are attacker-influenced (an SSH client controls
  what the daemon logs) and reach this module completely unescaped -- by
  design, since sanitizing at parse time would corrupt the data. The HTML
  renderer MUST run every log-derived string through `html.escape()` before
  interpolating it into a page.
- Those same fields may legally start with `=`, `+`, `-`, or `@`, which
  spreadsheet applications (Excel/Sheets) interpret as a formula prefix when
  a `.csv` is opened. The CSV renderer MUST neutralize such values (a
  leading `'` is prepended) in addition to using the `csv` module (never
  manual string concatenation) for correct delimiter/quote handling.
"""

import csv
import html
import json
from datetime import datetime
from typing import List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from logsentry import config
from logsentry.models import Alert, LogEvent

#: Severity -> rich color/style name (spec section 7.1).
_SEVERITY_STYLE = {
    "CRITICAL": "red",
    "HIGH": "yellow",
    "MEDIUM": "blue",
    "LOW": "grey58",
}

#: Characters that spreadsheet applications treat as a formula prefix.
_CSV_FORMULA_TRIGGER_CHARS = ("=", "+", "-", "@")

#: CSV column order, matching the CLI table exactly (spec: "same fields as
#: the CLI table").
_CSV_FIELDNAMES = [
    "Severity",
    "IP",
    "Type",
    "Failed",
    "Users",
    "First Seen",
    "Last Seen",
]


def _severity_sort_key(alert: Alert) -> int:
    """Sort key placing CRITICAL first, using `config.SEVERITY_ORDER` --
    never a hardcoded ad-hoc order duplicated from `config.py`. Unknown
    severities sort last.
    """
    try:
        return config.SEVERITY_ORDER.index(alert.severity)
    except ValueError:
        return len(config.SEVERITY_ORDER)


def _sorted_alerts(alerts: List[Alert]) -> List[Alert]:
    """Alerts sorted by severity descending (CRITICAL first)."""
    return sorted(alerts, key=_severity_sort_key)


def _summary_counts(events: List[LogEvent]) -> Tuple[int, int, int]:
    """Return (unique_ip_count, failed_total, accepted_total) for `events`.

    Shared by `render_cli`, `render_json`, and `render_html` so the summary
    statistics are computed in exactly one place.
    """
    unique_ips = {event.ip for event in events}
    failed_total = sum(1 for event in events if event.event_type == "failed")
    accepted_total = sum(1 for event in events if event.event_type == "accepted")
    return len(unique_ips), failed_total, accepted_total


def _neutralize_csv_formula(value: str) -> str:
    """Prefix `value` with a single quote if it starts with a character a
    spreadsheet application (Excel/Sheets) would interpret as a formula
    (`=`, `+`, `-`, `@`), preventing CSV/spreadsheet formula injection.
    Values that don't start with one of those characters are returned
    unchanged.
    """
    if value.startswith(_CSV_FORMULA_TRIGGER_CHARS):
        return "'" + value
    return value


def render_cli(
    events: List[LogEvent],
    alerts: List[Alert],
    console: Optional[Console] = None,
) -> None:
    """Print a summary panel and a severity-colored alert table to the
    terminal via `rich` (spec section 7.1).

    Rows are sorted by severity descending (CRITICAL first) using
    `config.SEVERITY_ORDER`. If `console` is not given, a new `Console` is
    created (making this function easy to call from `cli.py` while still
    being testable with an injected console).
    """
    if console is None:
        console = Console()

    unique_ip_count, failed_total, accepted_total = _summary_counts(events)

    summary_lines = (
        f"Total events: {len(events)}\n"
        f"Unique IPs: {unique_ip_count}\n"
        f"Total failed attempts: {failed_total}\n"
        f"Successful logins: {accepted_total}\n"
        f"Alerts raised: {len(alerts)}"
    )
    console.print(Panel(summary_lines, title="LogSentry Summary", expand=False))

    table = Table(show_header=True, header_style="bold")
    table.add_column("Severity")
    table.add_column("IP")
    table.add_column("Type")
    table.add_column("Failed", justify="right")
    table.add_column("Users", justify="right")
    table.add_column("First Seen")
    table.add_column("Last Seen")

    for alert in _sorted_alerts(alerts):
        style = _SEVERITY_STYLE.get(alert.severity, "white")
        table.add_row(
            f"[{style}]{alert.severity}[/{style}]",
            alert.ip,
            alert.alert_type,
            str(alert.failed_count),
            str(len(alert.usernames_tried)),
            alert.first_seen.isoformat(sep=" "),
            alert.last_seen.isoformat(sep=" "),
        )

    console.print(table)


def render_json(events: List[LogEvent], alerts: List[Alert], output_path: str) -> None:
    """Write a structured JSON report to `output_path` (spec section 7.2).

    Includes a summary block plus the full alert list (all `Alert` fields),
    with every `datetime` serialized via `.isoformat()`.
    """
    unique_ip_count, failed_total, accepted_total = _summary_counts(events)

    report = {
        "summary": {
            "total_events": len(events),
            "unique_ips": unique_ip_count,
            "total_failed_attempts": failed_total,
            "successful_logins": accepted_total,
            "alert_count": len(alerts),
        },
        "alerts": [
            {
                "ip": alert.ip,
                "severity": alert.severity,
                "alert_type": alert.alert_type,
                "failed_count": alert.failed_count,
                "usernames_tried": list(alert.usernames_tried),
                "first_seen": alert.first_seen.isoformat(),
                "last_seen": alert.last_seen.isoformat(),
                "description": alert.description,
            }
            for alert in _sorted_alerts(alerts)
        ],
    }

    with open(output_path, "w", encoding="utf-8") as json_file:
        json.dump(report, json_file, indent=2)


def render_csv(alerts: List[Alert], output_path: str) -> None:
    """Write one CSV row per alert to `output_path` (spec section 7.3).

    Uses the `csv` module exclusively (never manual string
    concatenation/joins) so delimiter and quote handling is always correct.
    On top of that, every log-derived field is passed through
    `_neutralize_csv_formula` so a value starting with `=`, `+`, `-`, or `@`
    (a CSV/spreadsheet formula-injection trigger) cannot execute as a
    formula when the file is opened in Excel/Sheets.
    """
    with open(output_path, "w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=_CSV_FIELDNAMES)
        writer.writeheader()
        for alert in _sorted_alerts(alerts):
            users_field = _neutralize_csv_formula(", ".join(alert.usernames_tried))
            writer.writerow(
                {
                    "Severity": alert.severity,
                    "IP": _neutralize_csv_formula(alert.ip),
                    "Type": alert.alert_type,
                    "Failed": alert.failed_count,
                    "Users": users_field,
                    "First Seen": alert.first_seen.isoformat(sep=" "),
                    "Last Seen": alert.last_seen.isoformat(sep=" "),
                }
            )


def _html_escape(value: str) -> str:
    """`html.escape()` with a short name local to this module, kept as a
    single choke point so every call site is easy to audit.
    """
    return html.escape(value, quote=True)


def render_html(events: List[LogEvent], alerts: List[Alert], output_path: str) -> None:
    """Write a single self-contained HTML report to `output_path` (spec
    section 7.4): inline `<style>`, a summary section, and a table of
    alerts colored by severity.

    Every log-derived string (ip, username(s), description) is passed
    through `html.escape()` before interpolation -- attacker-controlled log
    content (e.g. a username containing `<script>`) must never reach the
    page unescaped.
    """
    unique_ip_count, failed_total, accepted_total = _summary_counts(events)

    row_html_parts: List[str] = []
    for alert in _sorted_alerts(alerts):
        severity_class = alert.severity.lower()
        usernames_escaped = _html_escape(", ".join(alert.usernames_tried))
        row_html_parts.append(
            "<tr class=\"severity-{severity_class}\">"
            "<td><span class=\"badge badge-{severity_class}\">{severity}</span></td>"
            "<td>{ip}</td>"
            "<td>{alert_type}</td>"
            "<td>{failed_count}</td>"
            "<td>{usernames}</td>"
            "<td>{first_seen}</td>"
            "<td>{last_seen}</td>"
            "<td>{description}</td>"
            "</tr>".format(
                severity_class=severity_class,
                severity=_html_escape(alert.severity),
                ip=_html_escape(alert.ip),
                alert_type=_html_escape(alert.alert_type),
                failed_count=alert.failed_count,
                usernames=usernames_escaped,
                first_seen=_html_escape(alert.first_seen.isoformat(sep=" ")),
                last_seen=_html_escape(alert.last_seen.isoformat(sep=" ")),
                description=_html_escape(alert.description),
            )
        )
    rows_html = "\n".join(row_html_parts)

    generated_at = datetime.now().isoformat(sep=" ", timespec="seconds")

    page = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>LogSentry Report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; background: #0f1117; color: #e6e6e6; margin: 2rem; }}
  h1 {{ margin-bottom: 0.25rem; }}
  .generated {{ color: #9aa0a6; font-size: 0.85rem; margin-bottom: 1.5rem; }}
  .summary {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }}
  .stat {{ background: #1a1d27; border: 1px solid #2a2e3a; border-radius: 8px; padding: 0.75rem 1.25rem; min-width: 140px; }}
  .stat .value {{ font-size: 1.5rem; font-weight: 700; }}
  .stat .label {{ color: #9aa0a6; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.03em; }}
  table {{ border-collapse: collapse; width: 100%; background: #1a1d27; }}
  th, td {{ padding: 0.5rem 0.75rem; border-bottom: 1px solid #2a2e3a; text-align: left; font-size: 0.9rem; }}
  th {{ background: #12141c; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.03em; color: #9aa0a6; }}
  .badge {{ display: inline-block; padding: 0.15rem 0.6rem; border-radius: 999px; font-weight: 700; font-size: 0.75rem; }}
  .badge-critical {{ background: #4a1414; color: #ff6b6b; }}
  .badge-high {{ background: #4a3a14; color: #ffb84d; }}
  .badge-medium {{ background: #14304a; color: #6bb6ff; }}
  .badge-low {{ background: #2a2e3a; color: #b5b8bf; }}
  tr.severity-critical td {{ background: rgba(255, 107, 107, 0.06); }}
  tr.severity-high td {{ background: rgba(255, 184, 77, 0.05); }}
</style>
</head>
<body>
<h1>LogSentry Report</h1>
<div class="generated">Generated {generated_at}</div>
<div class="summary">
  <div class="stat"><div class="value">{total_events}</div><div class="label">Total events</div></div>
  <div class="stat"><div class="value">{unique_ips}</div><div class="label">Unique IPs</div></div>
  <div class="stat"><div class="value">{failed_total}</div><div class="label">Failed attempts</div></div>
  <div class="stat"><div class="value">{accepted_total}</div><div class="label">Successful logins</div></div>
  <div class="stat"><div class="value">{alert_count}</div><div class="label">Alerts</div></div>
</div>
<table>
  <thead>
    <tr>
      <th>Severity</th><th>IP</th><th>Type</th><th>Failed</th>
      <th>Users</th><th>First Seen</th><th>Last Seen</th><th>Description</th>
    </tr>
  </thead>
  <tbody>
{rows_html}
  </tbody>
</table>
</body>
</html>
""".format(
        generated_at=_html_escape(generated_at),
        total_events=len(events),
        unique_ips=unique_ip_count,
        failed_total=failed_total,
        accepted_total=accepted_total,
        alert_count=len(alerts),
        rows_html=rows_html,
    )

    with open(output_path, "w", encoding="utf-8") as html_file:
        html_file.write(page)
