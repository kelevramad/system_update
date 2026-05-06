# Hardening 5 — Quality and observability

> **Section**: 5 of [HARDENING_PLAN.md](../../HARDENING_PLAN.md)
> **Priority**: 🟢 P3
> **Status**: Specification — not implemented

## Why

The codebase currently emits diagnostic information as f-strings (`f'[EXEC] running {cmd}'`) printed to stdout. There is no consistent log level discipline, no structured fields, and no separation between "user-facing UI" and "operator-facing diagnostics". When something goes wrong on a user's machine, asking them for "the logs" produces an unstructured screen capture.

Test coverage is thin in three areas where bugs have already shipped: cache invalidation, smart-source filtering, and remote payload aggregation.

This section is **all P3** — nothing here unblocks a release. But each item compounds: better logs make every other PR easier to debug.

## Items

### 5.1 — Switch to structured logging

- **Files**: spread across the codebase
- **Effort**: L (1–3 days)
- **Plan**:
  1. Pick **stdlib `logging` with a custom `Formatter`** as the baseline. (Reject `structlog` unless we've already accepted a runtime dep — defer that decision and document it.)
  2. Add `src/system_update/logging_config.py` with `configure_logging(level: str, log_file: Path | None)` that:
     - Sets up a console handler with a one-line format: `%(asctime)s %(levelname)-7s %(name)s %(message)s`.
     - Sets up a file handler when `--log` is passed.
     - Adds a `LoggerAdapter` factory: `get_logger(name, **context)` that prepends `[k=v ...]` from the context.
  3. Replace `print(f'[EXEC] ...')` and similar with `log.info('exec', extra={'cmd': cmd, 'args': argv})` (or with the LoggerAdapter pattern). Find sites:
     ```bash
     git grep -nE "print\(\s*f?['\"]\[" src/
     ```
  4. Map verbosity:
     - `--debug` → `DEBUG`
     - default → `WARNING` (today's behavior)
     - `--log <file>` opens the file handler at `INFO` regardless of console level.
  5. Never log secrets. Add a `_REDACTED` set of substring patterns (e.g., `'password='`, `'authorization:'`) and scrub the formatter output. Defense-in-depth on top of 1.1.1 / 1.1.2.
- **Tests** (`tests/test_logging.py` — new file):
  - `--debug` produces DEBUG records.
  - File handler is created when `--log` passed.
  - Redaction strips known secret patterns from output.
  - LoggerAdapter context fields appear in formatted output.
- **Acceptance criteria**:
  - [ ] `git grep -nE "print\(\s*f?['\"]\[" src/` returns no hits.
  - [ ] All log lines parseable (consistent format).

### 5.2 — Test coverage in cache, smart filtering, remote aggregation

- **Files**: `tests/test_smart_cache.py`, `tests/test_config.py`, `tests/test_remote.py`
- **Effort**: M (½–1 day)
- **Plan**:
  1. **`cache.is_source_valid`** — currently relies on cache freshness comparisons. Add tests for:
     - Source present with fresh entry → valid.
     - Source present with expired entry → invalid.
     - Source absent → invalid.
     - Cross-day boundaries (TZ-aware comparisons; depends on hardening 2.2.3).
  2. **`config._apply_smart_sources_filtering`** ([src/system_update/config.py:268](../../src/system_update/config.py:268)) — smart-source whitelist logic. Test:
     - Whitelist with one source → only that source enabled.
     - Empty whitelist → behavior matches default (document either pass-through or no-op explicitly).
     - Unknown source name → ignored with a warning, not silently swapped in.
  3. **`remote.aggregate_scans`** with malformed payloads — depends on 3.2.2 (`RemoteScanPayload`). Test:
     - One host with valid payload + one with malformed → valid host counted, malformed listed in `errors`.
     - All hosts malformed → `AggregateReport(errors=[...], total_packages=0)`, no exception.
- **Acceptance criteria**:
  - [ ] Coverage report (`pytest --cov`) shows the targeted modules at ≥85%.

### 5.3 — Parser fuzzing with `hypothesis`

- **File**: [tests/test_scanners.py](../../tests/test_scanners.py)
- **Effort**: M (½–1 day)
- **Plan**:
  1. Add `hypothesis` to dev dependencies.
  2. Write strategies that produce realistic but adversarial inputs:
     - Random whitespace runs in column-aligned output.
     - Names with surrogate pairs, accented characters, and zero-width spaces.
     - Versions with a wide range of formats (`1.0`, `1.0.0-beta+build`, `2025.1.1`, `git+abc123`).
  3. For each scanner (`winget`, `scoop`, `choco`), write a property test: parser must either return a valid `AppInfo` or raise a parser-specific exception — never crash with `IndexError`/`AttributeError`/`KeyError`.
  4. Skip on machines that don't have the underlying tool installed; only the parser is exercised, against synthetic stdout.
- **Tests**: the fuzz tests themselves are the deliverable. Mark them `@pytest.mark.slow` so the regular suite stays fast; run them in CI on a separate job.
- **Acceptance criteria**:
  - [ ] Fuzz suite passes for ≥10000 examples per scanner.
  - [ ] No `IndexError`/`KeyError` escapes from parsers under fuzz.

### 5.4 — Windows CI E2E smoke

- **File**: CI configuration (`.github/workflows/*.yml`)
- **Effort**: L (1–3 days)
- **Plan**:
  1. Add a Windows job that:
     - Installs winget (preinstalled on `windows-latest` runners).
     - Runs `python -m system_update --no-cache --source winget --export json --output scan.json`.
     - Asserts `scan.json` is valid JSON and contains the expected schema fields.
     - Runs `--snapshot list` on a fresh state (expects empty list, not error).
     - Runs `--export html --output report.html` and asserts the file is non-empty.
  2. Cache `~/.system_update/` between runs only when explicitly requested via input — keep CI deterministic by default.
  3. Time budget: target < 5 minutes for the smoke job.
- **Tests**: not unit tests — CI itself is the test.
- **Acceptance criteria**:
  - [ ] Windows smoke job runs on every PR.
  - [ ] Failure produces an artifact (the partial scan.json + log).

## Implementation notes

- The branch `hardening/5-quality-and-observability` already exists with this spec.
- These items are independent. Land them in any order; 5.2 is the highest immediate value (catches regressions from other hardening PRs).
- 5.3 and 5.4 can land in parallel.
- Run before submitting:
  ```bash
  uv run ruff check .
  uv run pytest
  ```

## References

- Plan: `HARDENING_PLAN.md` § 5
- Python logging cookbook: <https://docs.python.org/3/howto/logging-cookbook.html>
- Hypothesis: <https://hypothesis.readthedocs.io/>
- GitHub Actions Windows runners: <https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners>
