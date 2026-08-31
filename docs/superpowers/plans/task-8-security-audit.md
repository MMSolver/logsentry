# Task 8 — Security Audit: `parser.py`, `detector.py`, `config.py`

**Auditor:** security-auditor persona
**Date:** 2026-08-31
**Scope:** `logsentry/parser.py`, `logsentry/detector.py`, `logsentry/config.py` (read-only review; `reporter.py`/`cli.py` do not exist yet — Task 9/10).
**Baseline:** `python -m pytest tests/ -q` → 22 passed (9 parser + 13 detector), 0 failed, confirming the audited code matches the "fully tested" state described in the task.

Overall verdict: **no Critical or Important findings.** Two Minor / informational
notes below, neither of which blocks Task 9.

---

## 1. ReDoS — parser regexes on adversarial log lines

Reviewed all five compiled patterns in `parser.py`:

- `_TIMESTAMP_PATTERN` (line 19-21)
- `_FAILED_INVALID_USER_PATTERN` (line 24-26)
- `_FAILED_PASSWORD_PATTERN` (line 27-29)
- `_ACCEPTED_PATTERN` (line 30-32)
- `_INVALID_USER_PATTERN` (line 33)

**Analysis:** none of these contain nested/overlapping quantifiers (no
`(a+)+`, `(a*)*`, or ambiguous alternation like `(a|a)+`) — the classic
shapes that cause catastrophic (exponential) backtracking. Each pattern is a
flat sequence of independently-quantified groups (`\S+`, `\d+`, `\s+`)
separated by required literals. A greedy `\S+`/`\d+` that fails to find its
following literal backtracks one character at a time, but each backtrack
step is an O(1) literal/class check — this degrades to linear time per
pattern, not exponential, even on pathological input engineered to force
maximum backtracking.

**Empirical confirmation:** timed all four content patterns and
`_TIMESTAMP_PATTERN` against adversarially constructed lines up to 500K–1M
characters — long unbroken digit/letter runs with no delimiter, a single
stray `.` deep in a long digit run (forces the IP group's four `\d+.\d+...`
chain to backtrack maximally), long runs of whitespace before the timestamp
fields, and full `parse_line()` calls on total-garbage and
near-miss-then-fail lines. All cases scaled linearly with input size (10×
input → ~10× time; no super-linear blowup at any size tested). Script used:
`redos_check.py` (see reasoning trace; not committed — ad hoc verification
only).

**Finding: none.** No ReDoS risk in the parser regex set.

---

## 2. Algorithmic complexity of the sliding-window detector

`_max_failed_window` (`detector.py:24-63`): sorts an IP's failed events by
timestamp — O(m log m) — then a single two-pointer pass where `left` only
ever advances forward — O(m). Total O(m log m) per IP, dominated by the
sort. The docstring's own claim of "never O(n²), even on an adversarial
(e.g. all-same-timestamp) input" was verified: when all timestamps are
identical, the `while (...) > window_seconds` condition is never true, so
`left` never advances and the scan is a single O(m) pass with no hidden
quadratic term.

`_detect_breach` (`detector.py:66-101`): sorts — O(m log m) — then one
linear pass. No quadratic behavior.

`detect()` (`detector.py:137-219`): groups events by IP in O(n), then calls
the two O(m log m) helpers per IP. Sum over all IPs of `m_i log m_i` is
bounded by `n log n`, satisfying the "not worse than roughly O(n log n) per
IP" requirement.

**Empirical confirmation:** ran `detect()` on synthetic event sets up to
80,000 events under three adversarial shapes — (a) single IP, all events at
the identical timestamp (worst case for the two-pointer window, since it
never contracts), (b) single IP with events spread one second apart
(continuous window sliding), (c) many distinct IPs. All three scaled
consistent with O(n log n) (roughly 8–9× time for a 16× input increase, far
from the ~256× a quadratic algorithm would show). No case exhibited
quadratic blowup.

**Finding: none.**

---

## 3. Generator / memory behavior

`parse_file` (`parser.py:114-125`) is a true generator (`yield`), opens the
file once via `with open(...)`, and iterates `for line in log_file:` —
Python's file iteration reads and yields one line at a time rather than
loading the file into memory. Confirmed generator-based end to end; no
intermediate list/buffer accumulates all events.

**Minor / informational (not a defect):** `detect()` takes `events:
List[LogEvent]` (a materialized list), not an iterator. This is
architecturally necessary — brute-force and breach detection need
random/sorted access across an IP's full event history, not a single
forward pass — and matches the Task 7 interface spec exactly. It does mean
a caller (Task 10's CLI) must hold the full parsed event list in memory
before calling `detect()`; for the local-CLI threat model this tool targets
(operator-supplied log files, not a network service processing untrusted
uploads), this is expected and does not need to change. Flagging only so
it's an explicit, considered tradeoff rather than an accidental one.

**Minor / informational (not a defect):** `parse_file`/`parse_line` have no
cap on a single line's length. Python's line-based file iteration must
buffer an entire "line" (i.e., up to the next `\n`) into memory before
`parse_line()` can run on it. A log file containing one pathologically long
line (e.g., a multi-GB line with no newline — not a realistic OpenSSH
syslog output, but not excluded by the parser either) would be fully
buffered. Given ReDoS itself is ruled out (section 1) this is a pure
memory-sizing concern, not a CPU-DoS one, and is low priority for a local
CLI tool reading operator-supplied files. If ever exposed to untrusted
remote log content, consider a defensive max-line-length guard in
`parse_file` (e.g., skip/truncate lines over N bytes) — not required now.

**Finding: none blocking; two informational notes above.**

---

## 4. Path handling

`parse_file(path)` (`parser.py:121`) calls `open(path, "r",
encoding="utf-8")` directly with no path sanitization and no
try/except — `FileNotFoundError`/`PermissionError`/`UnicodeDecodeError`
propagate to the caller unhandled. For this tool's threat model (a local CLI
where the path comes from the operator's own `--log` argument, not a
remote/attacker-controlled input), this is not a path-traversal
vulnerability — there's no privilege boundary being crossed; the user can
already read any file their own OS permissions allow, with or without this
tool. No unsanitized traversal into a location the invoking user couldn't
already reach directly.

**Note for Task 10 (CLI, out of scope here):** since these files don't
catch the exception, whatever surfaces a raw Python traceback (full local
path included) will currently propagate up to the CLI entry point. That's
an implemented-in-`cli.py` concern (friendly error message vs. raw
traceback), not a defect in `parser.py`/`detector.py`/`config.py` — flagging
forward for Task 10 rather than as a finding against these files.

`config.py` and `detector.py` do no file/path I/O at all — no findings to make there.

**Finding: none** in the audited files; one forward-looking note for Task 10.

---

## 5. Injection in exports (HTML/CSV)

**Not applicable to this audit.** `reporter.py` (Task 9) does not exist yet
in this repository — confirmed via directory listing (`logsentry/` contains
only `__init__.py`, `config.py`, `detector.py`, `models.py`, `parser.py`).
None of the three audited files render HTML, CSV, or any other output
format; `LogEvent.raw`/`.username`/`.ip` and `Alert.description` are stored
as plain Python strings with no escaping applied (correctly — escaping is
the renderer's job, not the parser's/detector's).

**Forward-looking note for Task 9:** the username, IP, and raw-line fields
are attacker-influenced (an SSH client controls what the daemon logs, e.g.
`Failed password for invalid user <script>alert(1)</script> from
1.2.3.4 port 22` parses cleanly today and produces a `LogEvent.username`
of `<script>alert(1)</script>` with no sanitization — by design, since
sanitization at parse time would corrupt the data). When `reporter.py` is
implemented, its HTML renderer **must** escape every log-derived string
before interpolation (e.g. via `html.escape()` or a templating engine's
autoescaping), and its CSV renderer must go through the `csv` module (not
manual string joins) so quoting/delimiter handling is correct. This is
exactly the Task 9 requirement already on record in the plan — noting it
here only to confirm *why* it's necessary: the audit of `parser.py`
confirms these fields really are unescaped, attacker-shaped strings by the
time they reach `Alert`/`LogEvent`.

Also worth flagging for Task 9: usernames/IPs beginning with `=`, `+`, `-`,
or `@` (CSV/Excel formula-injection trigger characters) are valid `\S+`
matches today (e.g. a username of `=cmd|'/c calc'!A1`) and will flow
unmodified into `Alert.usernames_tried`. Python's `csv` module does not
neutralize leading-formula characters (it only handles delimiter/quote
escaping) — Task 9 should either prefix such fields with a
neutralizing character (e.g. a leading `'` or space) or explicitly document
that CSV output is only safe to open in a hardened spreadsheet
configuration. Not a defect in the currently audited files — noted here
because the parser is what proves the attack string reaches `Alert`
unmodified.

**Finding: none** in the audited files (out of scope — code doesn't exist
yet); two concrete forward requirements recorded for Task 9's fix pass.

---

## 6. `eval`/`exec`/`pickle`/`shell=True` / unsafe subprocess

Searched `logsentry/` for `eval(`, `exec(`, `shell=True`, `pickle`,
`subprocess`, `os.system`:

```
grep -rn "eval(\|exec(\|shell=True\|pickle\|subprocess\|os.system" logsentry/
```

No matches anywhere in the package (not just the three audited files).

**Finding: none.**

---

## Minor correctness notes (non-security, recorded for completeness)

These don't affect security but were observed during the audit and are
worth a look during Task 9/10 polish — not blocking:

- `parser.py`'s IP-address regexes (`\d+\.\d+\.\d+\.\d+`) accept any
  digit-dot shape, including out-of-range octets like `999.999.999.999`.
  Not a security issue (no injection surface from extra digits), just a
  parsing-fidelity note.
- `_parse_timestamp` (`parser.py:49`) triggers a `DeprecationWarning` under
  Python's own test run (`strptime` without a year is ambiguous / will
  change behavior in Python 3.15). Purely a forward-compatibility note, not
  a security concern — flagging so it doesn't get missed before a future
  Python upgrade.

---

## Summary

| Category | Result |
|---|---|
| ReDoS in parser regexes | **None found** (verified analytically + empirically, linear scaling to 1M-char adversarial lines) |
| Detector algorithmic complexity | **None found** — O(n log n) confirmed analytically + empirically to 80K events, all-same-timestamp adversarial case included |
| Generator/memory behavior | **None found** — parser is generator-based end to end; two informational notes (not defects) about `detect()`'s necessary full-list input and unbounded single-line length |
| Path handling | **None found** in audited files; one forward note for Task 10 (don't leak raw tracebacks from CLI) |
| Export injection (HTML/CSV) | **N/A** — `reporter.py` not yet implemented; two concrete requirements recorded for its Task 9 fix pass (HTML escaping, CSV formula-injection prefixing) |
| `eval`/`exec`/`pickle`/`shell=True` | **None found** anywhere in `logsentry/` |

**No Critical or Important issues.** Task 9 can proceed without a
fix-and-recheck pass on `parser.py`/`detector.py`/`config.py`. Carry
forward the two concrete Task 9 requirements above (HTML escaping of
log-derived strings; CSV formula-injection prefixing) into that task's
implementation and re-audit `reporter.py` once it exists.
