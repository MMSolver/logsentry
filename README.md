# LogSentry

**A defensive CLI that parses SSH/auth logs and automatically flags brute-force attacks, credential-stuffing sweeps, and successful breaches.**

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://img.shields.io/badge/tests-passing-brightgreen)

LogSentry reads `sshd` log lines (the kind found in `/var/log/auth.log`), groups failed login attempts per IP address with a sliding time window, and raises severity-scored alerts — rendered as a colored terminal report or exported to JSON, CSV, or HTML.

---

## Features

- **Sliding-window brute-force detection** — flags any IP with `threshold`+ failed logins inside a `window`-second span (both configurable per run).
- **User-enumeration / credential-stuffing detection** — flags an IP trying many distinct usernames inside the same window, a signature of automated username-guessing.
- **Successful-breach detection** — the highest-priority check: an IP that fails repeatedly and then succeeds is flagged `CRITICAL`, since the brute-force may have worked.
- **Severity scoring** (`LOW` / `MEDIUM` / `HIGH` / `CRITICAL`) derived from failed-attempt counts and username diversity — no manual triage needed.
- **Four output formats** — a colored `rich` table in the terminal, or structured **JSON**, **CSV**, and self-contained **HTML** reports for sharing or archiving.
- **Streaming, memory-safe parsing** — log files are read line by line via a generator, not loaded entirely into memory.
- **Zero exotic dependencies** — standard library plus `rich`; the whole detection/reporting pipeline is plain Python.
- **Built-in sample-log generator** — produces a realistic, deterministic demo `auth.log` for trying the tool out or reproducing the results below.

## Installation

Requires Python 3.8+.

```bash
git clone <this-repo-url>
cd logsentry
pip install -r requirements.txt
```

To get the `logsentry` command on your `PATH`, install the package itself:

```bash
pip install -e .
```

If you'd rather not install it, every command below also works as `python -m logsentry ...` from the repository root.

## Usage

```bash
# Basic analysis — prints a colored report to the terminal
logsentry analyze /var/log/auth.log

# Custom brute-force threshold and time window
logsentry analyze auth.log --threshold 10 --window 120

# Export a structured JSON report
logsentry analyze auth.log --format json --output report.json

# Export CSV or HTML instead
logsentry analyze auth.log --format csv --output report.csv
logsentry analyze auth.log --format html --output report.html

# Only show HIGH and CRITICAL alerts
logsentry analyze auth.log --min-severity HIGH

# Generate a realistic demo log to try the tool on
logsentry generate-sample --output demo.log
```

All flags:

| Flag | Applies to | Meaning |
|---|---|---|
| `path` | `analyze` | Positional path to the log file to analyze. |
| `--threshold N` | `analyze` | Failed attempts from one IP within `--window` to trigger a `brute_force` alert (default `5`). |
| `--window N` | `analyze` | Sliding time window in seconds (default `60`). |
| `--format` | `analyze` | `cli` (default), `json`, `csv`, or `html`. |
| `--output PATH` | `analyze` | Output file path. Required for every `--format` other than `cli`. |
| `--min-severity` | `analyze` | Only report alerts at or above `LOW`/`MEDIUM`/`HIGH`/`CRITICAL`. |
| `--output PATH` | `generate-sample` | Where to write the generated sample log (default `demo.log`). |

## Demo

Generate the bundled sample log and analyze it:

```bash
$ logsentry generate-sample --output demo.log
Wrote sample log to demo.log

$ logsentry analyze demo.log
```

Real output from that run:

```
┌──── LogSentry Summary ────┐
│ Total events: 44          │
│ Unique IPs: 6             │
│ Total failed attempts: 38 │
│ Successful logins: 6      │
│ Alerts raised: 3          │
└───────────────────────────┘
┌──────────┬───────────────┬───────────────────┬────────┬───────┬─────────────────────┬─────────────────────┐
│ Severity │ IP            │ Type              │ Failed │ Users │ First Seen          │ Last Seen           │
├──────────┼───────────────┼───────────────────┼────────┼───────┼─────────────────────┼─────────────────────┤
│ CRITICAL │ 198.51.100.23 │ successful_breach │      6 │     1 │ 2026-08-30 08:25:00 │ 2026-08-30 08:25:18 │
│ MEDIUM   │ 203.0.113.5   │ brute_force       │     31 │     8 │ 2026-08-30 08:20:00 │ 2026-08-30 08:21:00 │
│ MEDIUM   │ 203.0.113.5   │ user_enumeration  │     31 │     8 │ 2026-08-30 08:20:00 │ 2026-08-30 08:21:00 │
└──────────┴───────────────┴───────────────────┴────────┴───────┴─────────────────────┴─────────────────────┘
```

In the terminal, rows are additionally color-coded by severity (red for `CRITICAL`, yellow/orange for `HIGH`, blue for `MEDIUM`, grey for `LOW`), with `CRITICAL` alerts sorted to the top. The `198.51.100.23` row is the sample's "several failed attempts followed by a successful login" scenario — exactly the case a defender needs to see first.

## How it works

1. **Parsing** (`parser.py`) — each log line is matched against four regexes for `Failed password` (with/without "invalid user"), `Accepted password`/`publickey`, and standalone `Invalid user` lines, producing a `LogEvent(timestamp, ip, username, event_type, port, raw)`. Lines that don't match are silently skipped. The file is read as a generator, so arbitrarily large logs don't need to fit in memory.
2. **Sliding-window brute-force detection** (`detector.py`) — for each IP, failed-login timestamps are sorted and swept with a two-pointer window: if any `window`-second span contains `threshold` or more failed attempts, that IP is flagged `brute_force`.
3. **User enumeration** — within that same eligible window, if the IP tried `enum_threshold`+ distinct usernames, the alert is additionally (or instead) reported as `user_enumeration`.
4. **Successful breach** — takes precedence over both of the above: if an IP's failed attempts are chronologically followed by an `accepted` login, it's reported as `successful_breach` and always scored `CRITICAL`, since the attack may have succeeded.
5. **Severity scoring** — everything else is scored from the failed-attempt count and username diversity: `HIGH` at 50+ failed attempts or 15+ distinct usernames, `MEDIUM` at 15–49 failed attempts, `LOW` from the detection threshold up to 14. All of these boundaries live in `config.py`, not scattered through the detection logic.
6. **Reporting** (`reporter.py`) — alerts are sorted CRITICAL → LOW and rendered as a `rich` terminal table, or exported to JSON/CSV/HTML (HTML output HTML-escapes every log-derived string, since log content is attacker-influenced input).

## Disclaimer

LogSentry is a **defensive** tool for analyzing authentication logs. Use it only on **your own systems or systems you are explicitly authorized to monitor**. It never connects to, scans, or interacts with any remote host — it only reads log files you give it.

## License

MIT — see [LICENSE](LICENSE).

## Roadmap

Stretch ideas, not yet implemented:

- `--follow` / `-f` live tail mode for real-time monitoring.
- GeoIP lookups to map attacker IPs to countries (optional dependency).
- Fail2ban-style export of an IP block list built from alerts.
- Support for other log sources (nginx access logs, Windows Event Log).
- YAML configuration file support as an alternative to CLI flags.
