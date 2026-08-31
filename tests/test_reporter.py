"""Tests for logsentry.reporter (render_cli, render_json, render_csv,
render_html).

Covers the two smoke tests required by the plan (Task 11 / spec section 11):
valid-JSON-with-expected-keys, and HTML-escapes-a-malicious-username. Also
covers CSV formula-injection neutralization and a CLI-render smoke test,
since reporter.py is otherwise untested.
"""

import csv
import html
import io
import json
from datetime import datetime

from rich.console import Console

from logsentry.models import Alert, LogEvent
from logsentry.reporter import render_cli, render_csv, render_html, render_json

BASE_TIME = datetime(2026, 8, 30, 8, 0, 0)


def _event(ip="203.0.113.5", username="root", event_type="failed"):
    return LogEvent(
        timestamp=BASE_TIME,
        ip=ip,
        username=username,
        event_type=event_type,
        port=40000,
        raw=f"synthetic {event_type} for {username} from {ip}",
    )


def _alert(
    ip="203.0.113.5",
    severity="HIGH",
    alert_type="brute_force",
    failed_count=12,
    usernames_tried=None,
    description="12 failed attempts from 203.0.113.5",
):
    return Alert(
        ip=ip,
        severity=severity,
        alert_type=alert_type,
        failed_count=failed_count,
        usernames_tried=usernames_tried if usernames_tried is not None else ["root"],
        first_seen=BASE_TIME,
        last_seen=BASE_TIME,
        description=description,
    )


# --- render_json -------------------------------------------------------


def test_render_json_output_is_valid_json_with_summary_and_alerts_keys(tmp_path):
    """render_json's output file must parse as JSON and expose both
    top-level keys the CLI/README document: "summary" and "alerts"."""
    events = [_event(event_type="failed"), _event(event_type="accepted")]
    alerts = [_alert()]
    output_path = tmp_path / "report.json"

    render_json(events, alerts, str(output_path))

    report = json.loads(output_path.read_text(encoding="utf-8"))

    assert "summary" in report
    assert "alerts" in report
    assert isinstance(report["alerts"], list)


def test_render_json_summary_and_alert_fields_match_input(tmp_path):
    """The summary counts and per-alert fields reflect the events/alerts
    passed in, not placeholders."""
    events = [_event(event_type="failed"), _event(event_type="accepted")]
    alerts = [_alert(ip="203.0.113.5", severity="HIGH", failed_count=12)]
    output_path = tmp_path / "report.json"

    render_json(events, alerts, str(output_path))

    report = json.loads(output_path.read_text(encoding="utf-8"))

    assert report["summary"]["total_events"] == 2
    assert report["summary"]["total_failed_attempts"] == 1
    assert report["summary"]["successful_logins"] == 1
    assert report["summary"]["alert_count"] == 1

    assert len(report["alerts"]) == 1
    assert report["alerts"][0]["ip"] == "203.0.113.5"
    assert report["alerts"][0]["severity"] == "HIGH"
    assert report["alerts"][0]["failed_count"] == 12


# --- render_html ---------------------------------------------------------


def test_render_html_escapes_malicious_username(tmp_path):
    """A username containing a <script> tag must not appear unescaped in
    the generated HTML report -- it must be html-escaped instead."""
    malicious_username = "<script>alert(1)</script>"
    events = [_event(username=malicious_username)]
    alerts = [
        _alert(
            usernames_tried=[malicious_username],
            description=f"attempted login as {malicious_username}",
        )
    ]
    output_path = tmp_path / "report.html"

    render_html(events, alerts, str(output_path))

    html_content = output_path.read_text(encoding="utf-8")

    assert "<script>alert(1)</script>" not in html_content
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_content


def test_render_html_escapes_malicious_ip_field(tmp_path):
    """The `ip` field is also attacker-influenced (spec/Task 8 audit note)
    and must be escaped too, not just usernames/description."""
    malicious_ip = '"><img src=x onerror=alert(1)>'
    events = [_event(ip=malicious_ip)]
    alerts = [_alert(ip=malicious_ip)]
    output_path = tmp_path / "report.html"

    render_html(events, alerts, str(output_path))

    html_content = output_path.read_text(encoding="utf-8")

    assert "<img src=x onerror=alert(1)>" not in html_content
    assert html.escape(malicious_ip, quote=True) in html_content


# --- render_csv ------------------------------------------------------------


def test_render_csv_neutralizes_formula_injection(tmp_path):
    """An IP/username field starting with '=' (a CSV formula-injection
    trigger character) must be prefixed with a single quote in the output
    so spreadsheet apps don't execute it as a formula."""
    formula_ip = "=cmd|'/c calc'!A1"
    alerts = [_alert(ip=formula_ip, usernames_tried=["root"])]
    output_path = tmp_path / "report.csv"

    render_csv(alerts, str(output_path))

    with open(output_path, newline="", encoding="utf-8") as csv_file:
        rows = list(csv.DictReader(csv_file))

    assert len(rows) == 1
    assert rows[0]["IP"] == "'" + formula_ip
    assert not rows[0]["IP"].startswith("=")


def test_render_csv_writes_expected_header_and_row_count(tmp_path):
    """render_csv writes exactly one data row per alert, with the documented
    column headers (same fields as the CLI table)."""
    alerts = [_alert(ip="203.0.113.5"), _alert(ip="198.51.100.23", severity="CRITICAL")]
    output_path = tmp_path / "report.csv"

    render_csv(alerts, str(output_path))

    with open(output_path, newline="", encoding="utf-8") as csv_file:
        reader = csv.reader(csv_file)
        rows = list(reader)

    assert rows[0] == ["Severity", "IP", "Type", "Failed", "Users", "First Seen", "Last Seen"]
    assert len(rows) == 3  # header + 2 alert rows


# --- render_cli --------------------------------------------------------


def test_render_cli_prints_summary_and_severity_for_each_alert():
    """render_cli writes a summary panel and one table row per alert to the
    given rich Console; verified by capturing plain-text console output."""
    events = [_event(event_type="failed"), _event(event_type="accepted")]
    alerts = [_alert(ip="203.0.113.5", severity="CRITICAL", alert_type="successful_breach")]
    buffer = io.StringIO()
    console = Console(file=buffer, width=120, no_color=True)

    render_cli(events, alerts, console=console)

    output = buffer.getvalue()

    assert "LogSentry Summary" in output
    assert "203.0.113.5" in output
    assert "CRITICAL" in output
    assert "successful_breach" in output
