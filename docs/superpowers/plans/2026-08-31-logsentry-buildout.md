# LogSentry Implementation Plan

> **For agentic workers:** Execute task-by-task in this session, dispatching
> each task to the **named subagent** given in its `Agent:` field via the
> Agent tool (`.claude/agents/<name>.md` defines it). Steps use checkbox
> (`- [ ]`) syntax for tracking. This is a lighter, direct per-task
> delegation flow (no worktree/ledger ceremony) — appropriate for a single
> small local package built in one session, per the user's explicit request
> to follow the spec's build order and hand each step to its matching
> expert agent.

**Goal:** Build LogSentry, a Python CLI that parses SSH/auth logs and
detects brute-force / anomalous login behavior, end to end per the spec.

**Architecture:** Small standard-library-first Python package
(`logsentry/`) with clean separation: `parser.py` turns raw log lines into
`LogEvent` objects (generator-based, streaming), `detector.py` turns a list
of `LogEvent` into `Alert` objects using sliding-window brute-force logic,
`reporter.py` renders `Alert`s as CLI (rich)/JSON/CSV/HTML, `cli.py` wires
it together with `argparse`. `config.py` centralizes thresholds.

**Tech Stack:** Python 3.8+, `rich`, standard library only otherwise,
`pytest` for tests.

**Spec:** `logsentry-spec.md` (repo root) — the plan argues from this spec;
executors should read the relevant numbered section referenced in each task.

## Global Constraints

- Python 3.8+ compatible syntax only.
- No new runtime dependencies beyond `rich` (spec section 2).
- Every function has type hints and a short docstring (spec section 14).
- No magic numbers/strings in logic — all thresholds live in `config.py`
  (spec section 8, 14).
- Large file reads must use generators (spec section 5, 14).
- English names throughout (spec section 14).
- Package layout is fixed (spec section 3) — do not deviate from the given
  file tree.
- This is a defensive-only tool; it analyzes logs, it never touches a
  remote system.

---

## Task 1: Project scaffolding

**Agent:** python-pro

**Files:**
- Create: `logsentry/__init__.py`
- Create: `.gitignore`
- Create: `LICENSE` (MIT, current year, copyright holder: project author)
- Create: `requirements.txt`
- Create: `pyproject.toml`

**Requirements:**
- `.gitignore`: standard Python ignores (`__pycache__/`, `*.pyc`, `.venv/`,
  `venv/`, `*.egg-info/`, `build/`, `dist/`, `.pytest_cache/`, `.mypy_cache/`,
  IDE dirs like `.vscode/`, `.idea/`) plus generated demo/report artifacts
  (`demo.log`, `*.report.json`, `*.report.csv`, `*.report.html` — but do
  **not** ignore `tests/sample_logs/auth.log`, which is a committed fixture).
- `LICENSE`: standard MIT license text.
- `requirements.txt`: `rich>=13.0.0` and `pytest>=7.0.0` (pytest is a dev
  dependency but keep this project single-file for simplicity per spec's
  "keep dependencies minimal").
- `pyproject.toml`: project name `logsentry`, version `0.1.0`, Python
  `>=3.8`, dependency `rich>=13.0.0`, and a console-script entry point
  `logsentry = "logsentry.cli:main"` (the `main` function will be created in
  Task 8 — it's fine to reference it now).
- `logsentry/__init__.py`: package docstring one-liner + `__version__ = "0.1.0"`.

- [ ] Create all five files as specified.
- [ ] Run `python -c "import logsentry; print(logsentry.__version__)"` from
      the repo root to confirm the package imports.
- [ ] `git init` the repo if not already a git repo, `git add -A`,
      commit: `chore: project scaffolding (gitignore, license, pyproject, requirements)`.

---

## Task 2: Data models

**Agent:** python-pro

**Files:**
- Create: `logsentry/models.py`

**Spec reference:** section 4.

**Interfaces (produced, relied on by every later task):**
```python
@dataclass
class LogEvent:
    timestamp: datetime
    ip: str
    username: Optional[str]
    event_type: str  # one of "failed", "accepted", "invalid_user"
    port: Optional[int]
    raw: str

@dataclass
class Alert:
    ip: str
    severity: str  # one of "LOW", "MEDIUM", "HIGH", "CRITICAL"
    alert_type: str  # e.g. "brute_force", "user_enumeration", "successful_breach"
    failed_count: int
    usernames_tried: List[str]
    first_seen: datetime
    last_seen: datetime
    description: str
```

- [ ] Implement both dataclasses exactly as above (use `typing.Optional`/
      `typing.List` for 3.8 compatibility), each field documented in the
      class docstring.
- [ ] Sanity check: `python -c "from logsentry.models import LogEvent, Alert; print('ok')"`.
- [ ] Commit: `feat: add LogEvent and Alert data models`.

---

## Task 3: Parser tests (TDD red step)

**Agent:** test-automator

**Files:**
- Create: `tests/__init__.py` (empty)
- Create: `tests/test_parser.py`

**Spec reference:** section 5.

**Context — the parser API this test file targets (not yet implemented):**
```python
def parse_line(line: str) -> Optional[LogEvent]: ...
def parse_file(path: str) -> Iterator[LogEvent]: ...
```

**Requirements — write tests for:**
1. `Failed password for invalid user admin from 203.0.113.5 port 54321 ssh2`
   → `event_type="failed"`, `username="admin"`, `ip="203.0.113.5"`, `port=54321`.
2. `Failed password for root from 203.0.113.5 port 54322 ssh2`
   → `event_type="failed"`, `username="root"`, same ip, `port=54322`.
3. `Accepted password for deploy from 10.0.0.8 port 51000 ssh2`
   → `event_type="accepted"`, `username="deploy"`, `ip="10.0.0.8"`, `port=51000`.
4. `Accepted publickey for deploy from 10.0.0.8 port 51000 ssh2`
   → `event_type="accepted"` (publickey variant).
5. `Invalid user test from 192.168.1.50` (no port in the line)
   → `event_type="invalid_user"`, `username="test"`, `ip="192.168.1.50"`,
   `port=None`.
6. An unrelated/irrelevant line (e.g. a non-SSH syslog line, or garbage
   text) → `parse_line` returns `None`.
7. `timestamp` parsing: a syslog line has no year (`Nov 12 08:23:45 ...`) —
   assert the parsed `timestamp.year` equals `datetime.now().year`.
8. `parse_file`: write a small temp log file (use `tmp_path` pytest
   fixture) mixing 2-3 valid lines with 1-2 irrelevant lines, assert
   `list(parse_file(path))` has the right length and the irrelevant lines
   were silently skipped (no exception).
9. `parse_file` returns an iterator/generator, not a list — assert
   `inspect.isgenerator(parse_file(path))` or equivalent (it must not load
   the whole file into memory at once).

- [ ] Write these tests in `tests/test_parser.py` importing from
      `logsentry.parser` (module doesn't exist yet — that's expected).
- [ ] Run `pytest tests/test_parser.py -v` and confirm it fails with
      `ModuleNotFoundError: No module named 'logsentry.parser'` (or
      ImportError) — the right kind of failure, not a typo in the test file.
- [ ] Commit: `test: add failing parser tests (TDD red)`.

---

## Task 4: Parser implementation (TDD green step)

**Agent:** python-pro

**Files:**
- Create: `logsentry/parser.py`
- Test: `tests/test_parser.py` (from Task 3 — must pass, do not weaken it)

**Spec reference:** section 5.

**Interfaces (produced, relied on by Task 5, 6, 7, 8):**
```python
def parse_line(line: str) -> Optional[LogEvent]: ...
def parse_file(path: str) -> Iterator[LogEvent]: ...
```

**Requirements:**
- Four regexes, tried in this order (most specific first) inside
  `parse_line`:
  1. `Failed password for invalid user (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)`
     → `event_type="failed"`.
  2. `Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)`
     → `event_type="failed"` (only matches if #1 didn't).
  3. `Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)`
     → `event_type="accepted"`.
  4. `Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)` (no port group)
     → `event_type="invalid_user"`, `port=None`.
- Extract the leading syslog timestamp (`MMM DD HH:MM:SS`, e.g.
  `Nov 12 08:23:45`) with `datetime.strptime(..., "%b %d %H:%M:%S")`, then
  `.replace(year=datetime.now().year)` since syslog omits the year.
- Lines that match none of the four patterns return `None` from
  `parse_line` — no exception.
- `parse_file(path)` opens the file and `yield`s `LogEvent`s line by line
  (generator — do not read the whole file into a list first), skipping
  lines where `parse_line` returns `None`.
- Regexes must be anchored/specific enough to avoid catastrophic
  backtracking on adversarial input (avoid nested unbounded quantifiers).

- [ ] Implement `logsentry/parser.py` per the above.
- [ ] Run `pytest tests/test_parser.py -v` — all tests from Task 3 pass.
- [ ] Commit: `feat: implement SSH log line parser (TDD green)`.

---

## Task 5: Sample log generator + fixture

**Agent:** python-pro

**Files:**
- Create: `examples/__init__.py` (empty, so it can be imported/run as a
  module if convenient — optional but harmless)
- Create: `examples/generate_sample_log.py`
- Create: `tests/sample_logs/auth.log` (generated output, committed as a
  fixture)

**Spec reference:** section 10.

**Requirements — the generated log must contain:**
1. A handful (3-5) of normal, spaced-out successful logins from different
   legitimate IPs/users (e.g. `deploy`, `admin` from internal-looking IPs
   like `10.0.0.x`).
2. A heavy brute-force burst from one attacker IP (e.g. `203.0.113.5`):
   30+ `Failed password` attempts within a tight time window (well under
   60 seconds apart), trying a mix of usernames (some `invalid user`, some
   valid-looking) — this must be enough to trigger both `brute_force` and
   `user_enumeration` under the spec's default thresholds (`threshold=5`,
   `window=60`, `ENUM_THRESHOLD=5`).
3. A second attacker IP that does several `Failed password` attempts and
   then one `Accepted password` — this must trigger `successful_breach`
   (CRITICAL).
4. Timestamps: sequential, realistic, seconds apart within bursts (not
   literally random — deterministic so the fixture is stable), written in
   syslog format `MMM DD HH:MM:SS`.
5. Script structure: a `generate_log(num_lines: int = ...) -> str` (or
   similar) function that returns the full log text, plus a `if __name__ ==
   "__main__":` block using `argparse` with a `--output` flag (default
   `demo.log`) that writes the text to a file. This mirrors the `cli.py`
   `generate-sample` subcommand's behavior (Task 8 will likely import or
   shell out to this).

- [ ] Implement `examples/generate_sample_log.py`.
- [ ] Run it to produce output, and copy/write that exact output to
      `tests/sample_logs/auth.log`.
- [ ] Sanity-check with the Task 4 parser:
      `python -c "from logsentry.parser import parse_file; print(len(list(parse_file('tests/sample_logs/auth.log'))))"`
      prints a nonzero count with no exception.
- [ ] Commit: `feat: add sample log generator and auth.log test fixture`.

---

## Task 6: Detector tests (TDD red step)

**Agent:** test-automator

**Files:**
- Create: `tests/test_detector.py`

**Spec reference:** section 6.

**Context — the detector API this test file targets (not yet implemented):**
```python
def detect(events: List[LogEvent], threshold: int = 5, window: int = 60,
           enum_threshold: int = 5) -> List[Alert]: ...
```
(exact keyword-argument names must match `config.py`'s constants, added in
Task 7: `DEFAULT_THRESHOLD`, `DEFAULT_WINDOW`, `ENUM_THRESHOLD` — the
detector's defaults should reference those constants, not hardcode them
again.)

**Requirements — write tests for:**
1. Using `tests/sample_logs/auth.log` (parsed via `parse_file`), running
   `detect()` produces at least one `Alert` with `alert_type="brute_force"`
   for the heavy-burst attacker IP from Task 5.
2. The same run produces at least one `Alert` with
   `alert_type="user_enumeration"` for that IP (5+ distinct usernames in
   one window).
3. The same run produces exactly the `successful_breach` alert (CRITICAL)
   for the second attacker IP from Task 5, and its `severity == "CRITICAL"`.
4. Sliding window boundary: construct a small synthetic list of
   `LogEvent`s (not from the fixture) where an IP has exactly `threshold`
   failed attempts within `window` seconds → asserts a `brute_force` alert
   IS produced (boundary is inclusive at the threshold count).
5. Below threshold: an IP with `threshold - 1` failed attempts within the
   window → asserts NO `brute_force` alert for that IP.
6. Outside the window: an IP with `threshold` failed attempts but spread
   out so consecutive attempts exceed `window` seconds apart → asserts NO
   `brute_force` alert.
7. Severity scoring table (spec section 6.4), each as its own synthetic
   case:
   - failed-then-accepted → `CRITICAL`
   - 50+ failed attempts (no breach) → `HIGH`
   - 15+ distinct usernames (no breach) → `HIGH`
   - 15-49 failed attempts → `MEDIUM`
   - `threshold`-14 failed attempts → `LOW`
8. `Alert.description` is a non-empty, IP-and-count-bearing string (don't
   assert exact wording, just that it's meaningful — e.g. contains the IP
   and the failed count as substrings).
9. Alerts list ordering or at least severity values are checkable — assert
   that when multiple alerts exist, you can sort them CRITICAL > HIGH >
   MEDIUM > LOW (reporter.py will rely on this later; a simple assertion
   that all four severities are valid literals is enough here).

- [ ] Write these tests in `tests/test_detector.py`, importing `detect`
      from `logsentry.detector` (module doesn't exist yet).
- [ ] Run `pytest tests/test_detector.py -v`, confirm it fails on import
      (module not found) — not a typo.
- [ ] Commit: `test: add failing detector tests (TDD red)`.

---

## Task 7: Detector + config implementation (TDD green step)

**Agent:** python-pro

**Files:**
- Create: `logsentry/config.py`
- Create: `logsentry/detector.py`
- Test: `tests/test_detector.py` (from Task 6 — must pass, do not weaken it)

**Spec reference:** sections 6, 8.

**`config.py` requirements:**
```python
DEFAULT_THRESHOLD: int = 5
DEFAULT_WINDOW: int = 60
ENUM_THRESHOLD: int = 5

# severity boundaries (spec 6.4)
HIGH_FAILED_COUNT: int = 50
HIGH_UNIQUE_USERS: int = 15
MEDIUM_FAILED_COUNT: int = 15
```
Plus the ordered severity list `SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]`
for reporter sorting later. Every magic number from spec section 6.4 must
live here, not inline in `detector.py`.

**`detector.py` requirements — implement in this order (spec section 13
step 5), each layered on the last:**
1. **Brute-force (sliding window):** group failed events per IP, sort
   timestamps, and for each IP check whether any window of `window`
   seconds contains `>= threshold` failed attempts (two-pointer/sliding
   window over the sorted timestamp list — O(n) per IP, not O(n²)). Emit
   `alert_type="brute_force"`.
2. **User enumeration:** within the same detection pass, for an IP with a
   brute-force-eligible window, also count distinct `username`s tried in
   that window; if `>= enum_threshold` distinct usernames, additionally
   emit (or merge into the same alert as) `alert_type="user_enumeration"`.
   Prefer one `Alert` per IP with the most severe/most specific
   `alert_type` rather than duplicate alerts for the same IP — use your
   judgment, but document the choice in a docstring.
3. **Successful breach (highest priority):** for each IP, if it has 1+
   `failed` events chronologically followed by an `accepted` event, emit
   `alert_type="successful_breach"` with `severity="CRITICAL"`, and this
   should take precedence over/supersede a plain `brute_force` alert for
   the same IP (don't double-report the same IP as both `brute_force` and
   `successful_breach` — breach wins).
4. **Severity scoring** exactly per the spec 6.4 table, using the
   `config.py` constants:
   - failed-then-accepted → `CRITICAL`
   - `failed_count >= HIGH_FAILED_COUNT` or `len(usernames_tried) >= HIGH_UNIQUE_USERS` → `HIGH`
   - `MEDIUM_FAILED_COUNT <= failed_count < HIGH_FAILED_COUNT` → `MEDIUM`
   - `threshold <= failed_count < MEDIUM_FAILED_COUNT` → `LOW`
5. Build a human-readable `description` for every alert, e.g.
   `f"{ip} made {failed_count} failed attempts in {window}s, trying {len(usernames_tried)} distinct usernames"`
   (adapt wording per alert_type; breach alerts should mention the
   successful login explicitly).
6. Top-level `detect(events, threshold=DEFAULT_THRESHOLD, window=DEFAULT_WINDOW, enum_threshold=ENUM_THRESHOLD) -> List[Alert]`
   orchestrates all of the above and returns the final alert list (order
   doesn't need to be sorted here — `reporter.py` sorts for display).

- [ ] Implement `config.py` and `detector.py` per the above.
- [ ] Run `pytest tests/test_detector.py -v` — all tests from Task 6 pass.
- [ ] Also re-run `pytest tests/test_parser.py -v` to confirm no
      regression.
- [ ] Commit: `feat: implement brute-force/enumeration/breach detector and config (TDD green)`.

---

## Task 8: Security audit of parser + detector

**Agent:** security-auditor

**Files (read-only review):**
- `logsentry/parser.py`
- `logsentry/detector.py`
- `logsentry/config.py`

**Requirements:**
- Audit per your system prompt's checklist: ReDoS risk in the parser
  regexes on adversarial log lines, algorithmic complexity of the
  sliding-window detector on a large/adversarial event list (must not be
  worse than roughly O(n log n) per IP), memory behavior (parser must
  still be generator-based end to end), and any unsafe pattern (`eval`,
  `exec`, `shell=True`, etc. — expect none, but verify).
- Produce a short written report (file: `docs/superpowers/plans/task-8-security-audit.md`)
  listing findings with file:line and severity, or stating explicitly that
  no issues were found in a category.

- [ ] Read `parser.py`, `detector.py`, `config.py`.
- [ ] Write findings to `docs/superpowers/plans/task-8-security-audit.md`.
- [ ] If any Critical/Important finding is reported, hand it back for a
      python-pro fix-and-recheck before continuing to Task 9 (controller
      decision at execution time — not automatic).
- [ ] Commit the audit report: `docs: add security audit report for parser/detector`.

---

## Task 9: Reporter (CLI, then JSON/CSV/HTML)

**Agent:** python-pro

**Files:**
- Create: `logsentry/reporter.py`

**Spec reference:** section 7.

**Interfaces (consumes `Alert`/`LogEvent` from Task 2; produced functions
relied on by Task 10):**
```python
def render_cli(events: List[LogEvent], alerts: List[Alert], console: Optional["rich.console.Console"] = None) -> None: ...
def render_json(events: List[LogEvent], alerts: List[Alert], output_path: str) -> None: ...
def render_csv(alerts: List[Alert], output_path: str) -> None: ...
def render_html(events: List[LogEvent], alerts: List[Alert], output_path: str) -> None: ...
```

**Requirements:**
1. **CLI (`rich`):** a summary panel at the top (total events, unique IPs,
   total failed attempts, successful logins, alert count), then a
   `rich.table.Table` with columns **Severity | IP | Type | Failed |
   Users | First Seen | Last Seen**. Color by severity using
   `config.SEVERITY_ORDER`: CRITICAL=red, HIGH=yellow/orange,
   MEDIUM=blue, LOW=grey. Sort rows by severity descending (CRITICAL
   first) using `config.SEVERITY_ORDER` for the sort key — never a
   hardcoded ad-hoc order duplicated from `config.py`.
2. **JSON export:** structured, includes a summary block and the alert
   list with all `Alert` fields (datetimes as ISO 8601 strings via
   `.isoformat()`).
3. **CSV export:** one row per alert, same fields as the CLI table,
   written via the `csv` module (never manual string concatenation/joins
   — this avoids CSV injection and quoting bugs).
4. **HTML export:** a single self-contained HTML file with inline
   `<style>`, a table of alerts colored by severity, and a summary
   section. **Every log-derived string (ip, username, description, raw
   line if shown) must be HTML-escaped via `html.escape()` before
   interpolation** — this is a hard requirement (untrusted log content is
   attacker-influenced input).

- [ ] Implement all four functions in `logsentry/reporter.py`.
- [ ] Manual smoke test: build a couple of fake `LogEvent`/`Alert` objects
      in a throwaway script or `python -c` one-liner and call each
      function, confirm no exceptions and files are written with sane
      content (`cat`/open the JSON/CSV/HTML output).
- [ ] Commit: `feat: implement CLI, JSON, CSV and HTML reporters`.

---

## Task 10: CLI entry point

**Agent:** python-pro

**Files:**
- Create: `logsentry/cli.py`
- Modify: `pyproject.toml` (only if the Task 1 entry point string needs
  adjusting to match the real `main` function location — verify, don't
  blindly change)

**Spec reference:** section 9.

**Requirements — `argparse` with two subcommands:**
```
logsentry analyze <path> [--threshold N] [--window N] [--format cli|json|csv|html] [--output PATH] [--min-severity LOW|MEDIUM|HIGH|CRITICAL]
logsentry generate-sample [--output PATH]
```
- `analyze`: parses `path` via `logsentry.parser.parse_file`, runs
  `logsentry.detector.detect` with `--threshold`/`--window` (falling back
  to `config.DEFAULT_THRESHOLD`/`config.DEFAULT_WINDOW`), filters alerts by
  `--min-severity` (keep alerts at or above the given severity using
  `config.SEVERITY_ORDER`), then dispatches to the right `reporter.render_*`
  based on `--format` (default `cli`). For non-`cli` formats, `--output` is
  required (error out clearly via `argparse` if missing, rather than
  silently defaulting).
- `generate-sample`: calls into `examples/generate_sample_log.py`'s
  `generate_log()` and writes it to `--output` (default `demo.log`).
  Import it (add `examples/` handling as needed, e.g. via
  `importlib`/relative import, or move the shared generation logic into
  `logsentry/` if that's cleaner — implementer's call, document the choice).
- `def main() -> None:` is the entry point referenced by `pyproject.toml`'s
  `logsentry = "logsentry.cli:main"`.
- `python -m logsentry` also works — add `logsentry/__main__.py` that
  calls `cli.main()`.

- [ ] Implement `logsentry/cli.py` and `logsentry/__main__.py`.
- [ ] Verify `pyproject.toml`'s entry point still matches.
- [ ] Manual test: `pip install -e .` then run
      `logsentry generate-sample --output /tmp_or_scratch/demo.log` and
      `logsentry analyze /tmp_or_scratch/demo.log`, confirm a real colored
      table prints. Also test `--format json --output out.json` and
      `--min-severity HIGH`.
- [ ] Commit: `feat: add argparse CLI (analyze, generate-sample) and __main__ entry point`.

---

## Task 11: Full test suite pass + coverage check

**Agent:** test-automator

**Files:**
- Modify/extend: `tests/test_parser.py`, `tests/test_detector.py` as needed
- Create (if useful): `tests/test_reporter.py` — at least a couple of
  smoke tests (JSON output is valid JSON with expected keys; HTML output
  escapes a malicious-looking username like `<script>` from a crafted
  `Alert`/`LogEvent`)

**Requirements:**
- Run the **full** `pytest` suite from repo root, confirm all green.
- Confirm the total meaningful test count is at least 8-10 as required by
  spec section 11 (count actual test functions, not parametrize
  expansions padding the number).
- If any test is flaky/order-dependent (e.g. relies on wall-clock
  `datetime.now()` in a way that could break at midnight), fix it to be
  deterministic.
- Add the two `test_reporter.py` smoke tests described above if they don't
  already exist from Task 9 review.

- [ ] Run `pytest -v` from repo root, paste the full pass/fail summary in
      your report.
- [ ] Fix anything red; do not weaken assertions to force green.
- [ ] Commit: `test: reporter smoke tests, full suite green`.

---

## Task 12: README

**Agent:** docs-architect

**Files:**
- Create: `README.md`

**Spec reference:** section 12.

**Requirements:** exactly the section list from your system prompt
(Title/description/badges, Features, Installation, Usage, Demo, How it
works, Disclaimer, License, optional Roadmap from spec section 15). Every
command/flag documented must be verified against the real `cli.py` from
Task 10 — run `logsentry generate-sample` + `logsentry analyze` for real
to capture actual demo output for the Demo section's code block.

- [ ] Read `logsentry/cli.py`, `logsentry/config.py` before writing.
- [ ] Generate real demo output to quote in the README.
- [ ] Write `README.md`.
- [ ] Commit: `docs: add README with usage, demo and roadmap`.

---

## Task 13: Whole-codebase review

**Agent:** code-reviewer

**Files (read-only review):** everything under `logsentry/`, `tests/`,
`examples/`.

**Requirements:** per your system prompt's checklist — type hints,
docstrings, no magic numbers, generator use, dead code, bare excepts,
mutable defaults, layering (detector must not import `rich`, etc.).
Produce a prioritized findings report at
`docs/superpowers/plans/task-13-code-review.md`. Critical/Important
findings get routed back to python-pro for a fix pass before Task 14;
Minor findings get listed in the README's/plan's notes as accepted debt
(fine to leave).

- [ ] Review the full codebase.
- [ ] Write findings to `docs/superpowers/plans/task-13-code-review.md`.
- [ ] Commit the report: `docs: add whole-codebase review report`.

---

## Task 14: Final end-to-end verification

**Agent:** debugger

**Files:** none created; this is a verification pass (may touch any file
to fix a discovered bug).

**Spec reference:** section 13 step 11.

**Requirements — run for real, report actual output, per your system
prompt:**
1. `logsentry generate-sample --output demo.log` — succeeds, file has
   realistic content.
2. `logsentry analyze demo.log` — CLI table renders, CRITICAL breach alert
   appears at the top.
3. `logsentry analyze demo.log --format json --output demo.report.json` —
   valid JSON, spot-check structure.
4. `logsentry analyze demo.log --format csv --output demo.report.csv` —
   valid CSV, opens/parses cleanly.
5. `logsentry analyze demo.log --format html --output demo.report.html` —
   valid HTML, no unescaped log content.
6. `logsentry analyze demo.log --min-severity HIGH` — only HIGH/CRITICAL
   rows shown.
7. `pytest -v` from repo root — full green.
8. Fix any bug found (root cause, not a patch) and re-verify the specific
   failing step plus the full test suite.

- [ ] Run all of the above for real; do not simulate/assume output.
- [ ] Fix any bugs found.
- [ ] Final commit if fixes were made: `fix: <describe root cause fixed during final verification>`.
- [ ] Report a clean bill of health (all 8 checks pass) or the exact
      remaining issue if one couldn't be resolved.

---

## Self-Review Notes

- Spec coverage: sections 3-14 each map to at least one task above;
  section 15 (roadmap) is covered inside Task 12's README; section 16
  (subagents) is satisfied by the `.claude/agents/*.md` files created
  before this plan and the `Agent:` field on every task.
- No placeholders: every task gives exact regexes, exact field names,
  exact thresholds, and exact CLI flags rather than "add appropriate
  handling."
- Type consistency: `detect()`'s signature (Task 6/7), `Alert`/`LogEvent`
  fields (Task 2), and the reporter function signatures (Task 9) are
  reused verbatim across every task that touches them.
