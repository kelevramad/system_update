# Hardening 4 — Performance

> **Section**: 4 of [HARDENING_PLAN.md](../../HARDENING_PLAN.md)
> **Priority**: 🟡 P2 / 🟢 P3
> **Status**: Specification — not implemented

## Why

Six concrete bottlenecks are wasting wall-clock time and CPU on every scan. None of them require new features; all are local fixes.

Note: item 2.1.2 (rate-limiter sleep inside lock) is in the **2.1 Concurrency** spec — it's the single biggest win and lands there. This document covers the remaining six.

## Items

### 4.1 — Parallelize GitHub Advisory queries with a connection pool

- **File**: [src/system_update/security/github.py:32](../../src/system_update/security/github.py:32)
- **Effort**: M (½–1 day)
- **Problem**: One GET per package, no `Session`/keep-alive, no parallelism. For an inventory of 200 packages this is 200 sequential TLS handshakes.
- **Proposed fix**:
  1. Use `concurrent.futures.ThreadPoolExecutor(max_workers=N)` where `N` comes from `config.security.github_workers` (default `4`).
  2. Reuse a single `urllib3.PoolManager` (already a transitive dep via `pip-audit`/`requests`?) or, if we want to stick with stdlib, build a custom `urllib.request.OpenerDirector` and use it across calls — keep-alive happens at the HTTPS connection level when servers honor it.
  3. Respect GitHub's secondary rate limit: 60 req/h unauth, 5000/h authed. Add backoff on `403 X-RateLimit-Remaining: 0`.
- **Tests** (`tests/test_security.py`):
  - 10 packages → 10 mocked GETs, executed via thread pool, total wall time ≪ sum.
  - On `403` rate-limit response → request is retried after the `X-RateLimit-Reset` window (mocked time).
- **Acceptance criteria**:
  - [ ] Wall time for a 200-package scan drops measurably (`pytest` benchmark or manual timing in PR description).

### 4.2 — Compile winget regex at module level

- **File**: [src/system_update/scanners/winget.py:32](../../src/system_update/scanners/winget.py:32)
- **Effort**: S (≤2h)
- **Problem**: A regex inside the per-row loop is rebuilt each call. Cheap but pure waste — and a nudge toward fixing the parser holistically (see 2.2.2).
- **Proposed fix**:
  1. Move the regex(es) to module level: `_ROW_RE = re.compile(r'...')`.
  2. Audit other scanners with the same pattern: `git grep -nE "re\.(compile|search|match)" src/system_update/scanners/`.
- **Tests**: existing scanner tests cover this; no new tests required.
- **Acceptance criteria**:
  - [ ] No `re.compile`/`re.search` with a literal pattern inside a loop.

### 4.3 — Memoize cache JSON reads with mtime-based invalidation

- **File**: [src/system_update/cache.py:241](../../src/system_update/cache.py:241)
- **Effort**: M (½–1 day)
- **Problem**: `_read_raw()` reparses the full `cache.json` on every call. `is_valid`, `is_source_valid`, `stale_sources`, and `load` each call it; an interactive run touches the file 4–6 times.
- **Proposed fix**:
  1. Add a `_RawCache` struct holding `(data: dict, mtime: float)`.
  2. On each `_read_raw()` call: stat the file, compare `st_mtime` to the cached mtime, return cached `data` if unchanged.
  3. Invalidate (clear `_RawCache`) on every write.
- **Tests** (`tests/test_smart_cache.py`):
  - Successive `is_valid` calls touch the file once (assert via mocked `Path.read_text`).
  - External modification (mtime change) invalidates and re-reads.
  - Write-through invalidates correctly.
- **Acceptance criteria**:
  - [ ] Profile shows only one `read_text` per cache.json across `is_valid` + `is_source_valid` + `load`.

### 4.4 — Use real `tick_interval` in `remote.execute_many`

- **File**: [src/system_update/remote.py:285](../../src/system_update/remote.py:285)
- **Effort**: S (≤2h)
- **Problem**: The wait loop calls `wait(timeout=1)` instead of `wait(timeout=tick_interval)`, so it spins ~30× per minute even when `tick_interval=30s`. CPU waste at idle and noisier logs.
- **Proposed fix**:
  1. Change to `done, not_done = wait(futures, timeout=tick_interval)`.
  2. Re-iterate the loop only when there's progress (drain `done`).
- **Tests** (`tests/test_remote.py`):
  - With 5 instant futures and `tick_interval=10`, the loop completes in ~0s (not 5×).
- **Acceptance criteria**:
  - [ ] Idle CPU drops; loop iteration count matches `tick_interval`.

### 4.5 — Index `pip_apps` by name to remove O(N·M) lookup

- **File**: [src/system_update/security/pip.py:81](../../src/system_update/security/pip.py:81)
- **Effort**: S (≤2h)
- **Problem**: For each vulnerability, `next(a for a in pip_apps if a.name == name)` scans the full list. With 100 packages × 50 advisories that's 5000 comparisons; trivial today but quadratic.
- **Proposed fix**:
  1. Build `pip_index: dict[str, AppInfo] = {a.name.lower(): a for a in pip_apps}` once, before the loop.
  2. Replace `next(...)` with `pip_index.get(name.lower())`.
- **Tests** (`tests/test_security.py`):
  - Match by case-insensitive name.
  - Missing package → `None` (no `StopIteration`).
- **Acceptance criteria**:
  - [ ] No `next(... for ...)` quadratic pattern remains.

### 4.6 — Retry/backoff on transient HTTP errors

- **File**: [src/system_update/network.py](../../src/system_update/network.py)
- **Effort**: M (½–1 day)
- **Problem**: A single 429/503/timeout fails the whole scan path that depends on it. With the silenced-errors fix (2.3.1), the failure becomes visible; this PR makes it less likely to occur.
- **Proposed fix**:
  1. Wrap `fetch_json` and `fetch_bytes` with a retry decorator:
     - Retry on `URLError` whose underlying `errno` is connection-reset, on `HTTPError(429)`, on `HTTPError(5xx)`.
     - Don't retry on 4xx other than 429.
     - Exponential backoff: `delay = base * (2 ** attempt) + jitter`, capped at 30s.
     - `max_attempts = 3` by default; configurable via `network.retry_max_attempts`.
  2. Honor `Retry-After` header on 429/503 responses if present.
  3. Log each retry at INFO with attempt number, status, and final outcome.
- **Tests** (`tests/test_network.py`):
  - 429 then 200 → succeeds after one retry.
  - Three consecutive 503 → fails with the original error after `max_attempts`.
  - 404 → fails immediately (no retry).
  - `Retry-After: 2` honored.
- **Acceptance criteria**:
  - [ ] OSV/GitHub/PyPI scans tolerate transient hiccups.
  - [ ] Setting documented.

## Order of operations

Land in this order to keep diffs small and reviewable:

1. **4.2** — trivial, mechanical.
2. **4.5** — trivial, mechanical.
3. **4.4** — small, isolated.
4. **4.3** — slightly larger; needs careful invalidation review.
5. **4.6** — touches network helper; ensure tests for current callers stay green.
6. **4.1** — depends on 4.6 (uses retry) and on hardening 2.1.2 (per-host limiter).

## Implementation notes

- The branch `hardening/4-performance` already exists with this spec.
- Each item can ship as its own commit on this branch — keeps the PR readable.
- For 4.1 and 4.6, capture before/after timings (manual or `pytest-benchmark`) and include them in the PR description.
- Run before submitting:
  ```bash
  uv run ruff check .
  uv run pytest
  ```

## References

- Plan: `HARDENING_PLAN.md` § 4
- urllib3 PoolManager: <https://urllib3.readthedocs.io/en/stable/reference/urllib3.poolmanager.html>
- GitHub rate limits: <https://docs.github.com/en/rest/overview/resources-in-the-rest-api#rate-limiting>
- Retry-After header: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Retry-After>
