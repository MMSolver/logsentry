"""Argparse-based CLI entry point for LogSentry (spec section 9).

Two subcommands::

    logsentry analyze <path> [--threshold N] [--window N]
                              [--format cli|json|csv|html] [--output PATH]
                              [--min-severity LOW|MEDIUM|HIGH|CRITICAL]
    logsentry generate-sample [--output PATH]

Import choice (documented per plan Task 10's "implementer's call"): rather
than shelling out to ``examples/generate_sample_log.py`` as a subprocess, or
duplicating its `generate_log()` logic inside `logsentry/`, this module
imports it directly -- ``from examples.generate_sample_log import
generate_log``. For that import to work from an *installed* console script
(whose process does not have the repo root on `sys.path` the way `python -m`
run from the repo root does), `pyproject.toml`'s package discovery was
extended to include ``examples*`` alongside ``logsentry*``, so `examples`
installs as a real top-level package next to `logsentry` under both
`pip install -e .` and a regular `pip install .`.
"""

import argparse
from functools import partial
from typing import List, Optional

from examples.generate_sample_log import generate_log
from logsentry import config
from logsentry.detector import detect
from logsentry.models import Alert
from logsentry.parser import parse_file
from logsentry.reporter import render_csv, render_cli, render_html, render_json

#: Accepted `--format` values for `analyze`.
_FORMAT_CHOICES = ("cli", "json", "csv", "html")

#: Accepted `--min-severity` values, taken from `config.SEVERITY_ORDER` so
#: this never drifts from the severities the detector can actually produce.
_SEVERITY_CHOICES = tuple(config.SEVERITY_ORDER)


def _filter_by_min_severity(alerts: List[Alert], min_severity: Optional[str]) -> List[Alert]:
    """Keep only alerts at or above `min_severity`, using
    `config.SEVERITY_ORDER` (most to least severe) as the ranking -- never a
    hardcoded ad-hoc order duplicated from `config.py`.

    `min_severity=None` (the default; no `--min-severity` given) returns
    `alerts` unchanged. An alert whose `severity` is not a recognized value
    is dropped rather than guessed about.
    """
    if min_severity is None:
        return alerts

    max_index = config.SEVERITY_ORDER.index(min_severity)
    kept: List[Alert] = []
    for alert in alerts:
        try:
            alert_index = config.SEVERITY_ORDER.index(alert.severity)
        except ValueError:
            continue
        if alert_index <= max_index:
            kept.append(alert)
    return kept


def _run_analyze(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Handle the `analyze` subcommand: parse, detect, filter, render.

    `parser` is the `analyze` subparser itself, used to raise a proper
    argparse usage error (exit code 2, printed usage) when `--format` is not
    `cli` but `--output` was not given -- per the spec, this must fail
    clearly rather than silently defaulting to some output path.
    """
    if args.format != "cli" and args.output is None:
        parser.error(f"--output is required when --format is '{args.format}' (not 'cli')")

    threshold = args.threshold if args.threshold is not None else config.DEFAULT_THRESHOLD
    window = args.window if args.window is not None else config.DEFAULT_WINDOW

    try:
        events = list(parse_file(args.path))
    except OSError as exc:
        parser.error(f"cannot read {args.path}: {exc.strerror or exc}")
    alerts = detect(events, threshold=threshold, window=window)
    alerts = _filter_by_min_severity(alerts, args.min_severity)

    if args.format == "cli":
        render_cli(events, alerts)
    elif args.format == "json":
        render_json(events, alerts, args.output)
    elif args.format == "csv":
        render_csv(alerts, args.output)
    elif args.format == "html":
        render_html(events, alerts, args.output)


def _run_generate_sample(args: argparse.Namespace) -> None:
    """Handle the `generate-sample` subcommand: write `generate_log()`'s
    output to `--output` (default `demo.log`).
    """
    log_text = generate_log()
    with open(args.output, "w", encoding="utf-8") as output_file:
        output_file.write(log_text)
    print(f"Wrote sample log to {args.output}")


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level `logsentry` argparse parser with its two
    subcommands (`analyze`, `generate-sample`).
    """
    parser = argparse.ArgumentParser(
        prog="logsentry",
        description="Parse SSH/auth logs and detect brute-force / anomalous login behavior.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser(
        "analyze", help="Analyze a log file for brute-force / anomalous login activity."
    )
    analyze_parser.add_argument("path", help="Path to the SSH/auth log file to analyze.")
    analyze_parser.add_argument(
        "--threshold",
        type=int,
        default=None,
        help=(
            "Failed attempts from one IP within --window to trigger a "
            f"brute_force alert (default: {config.DEFAULT_THRESHOLD})."
        ),
    )
    analyze_parser.add_argument(
        "--window",
        type=int,
        default=None,
        help=f"Sliding time window in seconds (default: {config.DEFAULT_WINDOW}).",
    )
    analyze_parser.add_argument(
        "--format",
        choices=_FORMAT_CHOICES,
        default="cli",
        help="Output format (default: cli).",
    )
    analyze_parser.add_argument(
        "--output",
        default=None,
        help="Output file path. Required when --format is not 'cli'.",
    )
    analyze_parser.add_argument(
        "--min-severity",
        choices=_SEVERITY_CHOICES,
        default=None,
        help="Only report alerts at or above this severity.",
    )
    analyze_parser.set_defaults(func=partial(_run_analyze, parser=analyze_parser))

    generate_parser = subparsers.add_parser(
        "generate-sample", help="Generate a deterministic sample SSH/auth log."
    )
    generate_parser.add_argument(
        "--output",
        default="demo.log",
        help="Path to write the generated log to (default: demo.log).",
    )
    generate_parser.set_defaults(func=_run_generate_sample)

    return parser


def main() -> None:
    """Entry point for the `logsentry` console script and `python -m logsentry`."""
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
