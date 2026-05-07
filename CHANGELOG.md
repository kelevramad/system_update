# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## 📝 License

This project is provided as-is for system administration and package management.

---

## 🆕 Latest Changes

### v8.2.0 (May 2026)
- **Security — Credentials Off Argv (Hardening 1.1)**: Added optional `pywinrm` HTTPS transport for remote execution. The legacy `winrs` path still works but now emits a one-shot warning when a password is supplied — `winrs -p:<pass>` puts the password on the spawned process's command line, which is readable by other local users via `Get-CimInstance Win32_Process`. Install with `uv pip install 'system-update-cli[remote-secure]'` and set `host.transport='pywinrm'`.
- **Security — Webhook Bearer Token Off Argv**: `_send_email_via_api` no longer shells out to `curl`. Bearer tokens now travel inside HTTP headers via `urllib.request`, so they never appear on a subprocess command line.
- **UX — Unified System Update Banner**: `--help` and the runtime startup banner now render the same Rich panel: version, runtime/venv, active profile, data-dir file inventory (status, size, mtime), cache TTL, supported sources, security feeds, and repo URL. The panel width matches Typer's help panels.
- **Tests**: Added regression coverage for both hardening items — the pywinrm path never spawns a subprocess, the missing-dep error message is actionable, the winrs fallback emits the security warning, and the email API path uses `urllib.request` with the `Authorization` header (no `curl`).

### v8.1.6 (May 2026)
- **Winget Upgrade Cache**: Winget, Registry, AppX, and MSIX update checkers now share one parsed `winget upgrade` table per `check_all_updates` run.
- **Parallel Consistency**: Parallel update checks no longer launch duplicate `winget upgrade` commands, reducing cost and avoiding inconsistent snapshots between sources.
- **Tests**: Added regression coverage proving all Winget-backed sources reuse a single command result during one check run.

### v8.1.5 (May 2026)
- **Windows Service Parsing**: Service executable paths without quotes now preserve spaces and arguments correctly, avoiding truncated `C:\Program` paths and `unknown` versions.
- **PowerShell JSON Parsing**: AppX/MSIX, Registry, Services, and PowerShell module scanners now tolerate warning text before JSON output and `null` responses.
- **Tests**: Added regression coverage for service executable path extraction and noisy PowerShell JSON output.

### v8.1.4 (May 2026)
- **Plugin Lifecycle**: Plugins can now register custom update checkers and package updaters, so custom sources participate in scan, check, and `--update-package` workflows.
- **Network Consistency**: VS Code extension version checks now use the shared network client, honoring API cache, timeout, rate-limit, and `network.enabled` settings.
- **Tests**: Added regression coverage for plugin checker/updater execution, shared-network VS extension checks, and smart-cache update-check mocks.

### v8.1.3 (May 2026)
- **MSIX Update Checks**: Added a real MSIX checker path so MSIX packages are no longer marked checked without running an update checker.
- **Windows Version Cleanup**: Driver, service, and PowerShell module scanners now normalize noisy version values before rendering tables.
- **UI Polish**: VS Code extensions now use a distinct `🔌` source icon instead of the plugin fallback icon.
- **Tests**: Added regression coverage for MSIX checking, Windows scanner version normalization, and the VS extensions icon.

### v8.1.2 (May 2026)
- **Security Hardening**: Custom notification scripts now execute without `shell=True`; PowerShell hooks are invoked explicitly with `powershell -File` on Windows.
- **Tests**: Added notification hook coverage to ensure custom scripts are launched with a shell-free argv.

### v8.1.1 (May 2026)
- **Readable Cache Files**: Removed cache compression code and the `compression_enabled` setting. `cache.json` is always written as plain, indented JSON so it can be inspected and edited easily.
- **Docs and Tests**: Updated cache documentation and smart-cache tests to reflect readable JSON-only cache files.

### v8.1.0 (May 2026)
- **Windows-Specific Enhancements (8.1)**: Completed Windows source coverage with AppX Store updates, driver inventory, service inventory, PowerShell modules, and VS Code extensions.
  - **AppX + Store Updates (8.1.1-8.1.2)**: AppX scanning now records package IDs and checks Store updates through `winget upgrade` with `msstore` results.
  - **Driver and Service Inventory (8.1.3-8.1.4)**: Added Windows driver scanning via `pnputil /enum-drivers` and service executable version discovery via `Get-CimInstance Win32_Service`.
  - **PowerShell and VS Extensions (8.1.5-8.1.6)**: Added PowerShell module scanning/update checks and VS Code extension scanning with Marketplace version checks.
- **UI polish**: Summary source labels now use `✨ Sources:` and phase timing lines show consistent emoji spacing.
- **Cache readability**: Cache files are plain, indented JSON again.
- **Tests**: Added Windows scanner/checker coverage and kept summary border regression checks active.

### v7.4.0 (May 2026)
- **Size Reduction (7.4)**: Reduced scan cache footprint with automatic pruning and selective package-field storage.
  - **Readable Cache (7.4.1)**: Cache files remain plain JSON because they are small and readability is more valuable.
  - **Data Pruning (7.4.2)**: Old source metadata, stale source package entries, and expired delta records are pruned automatically.
  - **Selective Storage (7.4.3)**: Cache storage fields are configurable and empty optional fields are omitted by default.
- **Tests**: Added size-reduction coverage for readable JSON writes, stale-source pruning, and selective field persistence.

### v7.3.0 (May 2026)
- **Network Optimization (7.3)**: Added a shared JSON HTTP client with configurable API caching, timeout handling, and per-host rate limiting.
  - **Batch API Requests (7.3.1)**: OSV security checks now use the querybatch endpoint for multiple packages in one request.
  - **Rate Limiting (7.3.2)**: API calls are throttled per host via the new `network.rate_limit_seconds` setting.
  - **Response Caching (7.3.3)**: JSON API responses are cached in `api_cache.json` with configurable TTL.
- **UI polish**: Summary source rows now wrap inside the panel so emoji-rich source chips do not overwrite borders.
- **Tests**: Added network coverage for response caching, rate limiting, and OSV batch payloads.

### v7.2.0 (May 2026)
- **Parallel Processing (7.2)**: Added bounded per-source worker pools for update checks, matching the scanner's parallel source execution.
  - **Worker Pool (7.2.1)**: `check_all_updates()` now dispatches source checkers through `ThreadPoolExecutor` and honors configured worker limits from the app.
  - **Shared Deduplication (7.2.2)**: Added a shared package dedupe helper used by scanner aggregation.
  - **Graceful Degradation (7.2.3)**: A failing source checker now marks that source as errored while other sources continue.
- **Tests**: Added parallel-processing coverage for concurrent checker execution, partial checker failure, and shared deduplication.

### v7.1.0 (May 2026)
- **Smart Caching (7.1)**: Added per-source cache freshness metadata so stale or missing sources can be rescanned incrementally while fresh sources remain cached.
  - **Incremental Scan (7.1.1)**: Partial cache hits now merge refreshed source results back into cached packages and clearly show cached vs scanned sources.
  - **Delta Cache (7.1.2)**: Cache writes include additive delta metadata for added, updated, and removed packages.
  - **LRU Memory Cache (7.1.3)**: Added a bounded hot-package cache for recently loaded package entries.
  - **Pre-fetch (7.1.4)**: Optional background cache prefetch can refresh near-expiry caches.
- **Source icons always on**: Summary, package tables, scan progress, update-check progress, and partial-cache messages now render source emoji chips. Custom/plugin sources use the `🧩` fallback.
- **CLI cleanup**: Removed `--icons`; icons now render by default.
- **Tests**: Added smart-cache coverage for per-source metadata, stale detection, deltas, LRU eviction, prefetch, partial-cache messaging, and plugin-source icon fallback.

### v6.5.0 (May 2026)
- **Plugin Architecture (6.5)**: Added local Python plugin loading from `~/.system_update/plugins` and configured `plugins.paths`.
  - **Custom Scanners (6.5.1)**: Plugins can register new package sources with `registry.register_scanner(...)`; custom sources work with `--source`, cache filtering, source labels, excludes, and `--save-config`.
  - **Custom Notifiers (6.5.2)**: Plugins can register notification channels with `registry.register_notifier(...)`; notifier plugins receive `updates_available` and `scan_complete` events with structured payloads.
  - **Plugin API (6.5.3)**: Public extension API exports `PluginRegistry`, `PluginContext`, `PluginScanner`, `PluginChecker`, `PluginUpdater`, `PluginNotifier`, `PluginLoadError`, and `load_plugins` from `system_update`.
- **Plugin visibility**: Added `--list-plugins` to show loaded scanner/checker/updater/notifier plugins and non-fatal load errors.
- **Help rendering fix**: Capped Typer/Rich help width to avoid clipped right borders in wide terminals with emoji-rich help panels.
- **Tests**: Added plugin tests covering scanner loading, custom source scanning, custom notifier events, dict-to-`AppInfo` coercion, and help panel width regression.

### v6.4.0 (May 2026)
- **Remote Management (6.4)**: Run `system-update` across multiple Windows machines from a single host
  - **WinRM Remote Execution (6.4.1)**: Uses Windows-native `winrs` (no extra dependencies). Password supplied via `SYSTEM_UPDATE_REMOTE_PASS` env var or `-p:` argv. Per-host duration / exit code / parsed JSON returned in a `RemoteResult` dataclass; transparent timeout + missing-`winrs` handling.
  - **Inventory Management (6.4.2)**: New `~/.system_update/inventory.json` with `RemoteHost` (name, address, user, transport, groups, description) + `Inventory` CRUD class. CLI `--remote add | remove | list` for management; case-insensitive name match replaces existing entries on `add`. `inventory.resolve(host, group)` precedence: single host → group → all hosts.
  - **Consolidated Reports (6.4.3)**: New `aggregate_scans()` merges per-host JSON exports into a unified report with `summary_per_host`, a `package_index` (host_count, hosts, versions, `consistent` flag flagging cross-host version drift), and an `errors` list. `--remote report --remote-output PATH` writes the full JSON; bare `--remote scan` prints the per-host summary table.
  - **Mass Update (6.4.4)**: `--remote update` fans out `--update-all --yes` to every targeted host in parallel (configurable via `--remote-timeout`); per-host pass/fail rendered in a Rich table. Also accepts `--remote-args "..."` to pass extra args to the remote `system-update` invocation.
- **New `🌐 Remote Management` help panel** with all `--remote-*` flags grouped together; new sub-help topic `remote` (`--explain remote` / `--remote help`) covering all 7 actions, the companion-flag matrix, credential handling, WinRM trusted-hosts setup, and 6 worked examples.
- **Remote verbose diagnostics**: Added `--remote-verbose` to print each host's stdout/stderr tail as soon as that host completes, making WinRM authentication failures, remote command errors, and timeout stderr easier to see directly in the CLI.
- **Remote debug diagnostics**: Added `--remote-debug` for stuck or silent hosts. It implies `--remote-verbose` and also prints target metadata, timeout, the remote `system-update` command, the redacted local `winrs` argv, a start message, and a periodic running heartbeat until the host completes or times out.
- **Tests**: +24 new tests in `tests/test_remote.py` covering `RemoteHost` round-trip, `Inventory` CRUD/persistence/groups/resolve precedence, `winrs` argv assembly, env-based password injection, missing-binary and timeout handling, parallel `execute_many` ordering, `aggregate_scans` merge / version-drift detection / error collection / bare-list payload tolerance.

### v6.3.0 (May 2026)
- **Dependency Graph (6.3)**: Added `--dependency-graph dot|conflicts|minimal|help`.
  - **Graphviz DOT Export (6.3.1)**: `--dependency-graph dot --graph-output deps.dot` writes a DOT graph with package nodes and best-effort npm/pnpm/pip dependency edges.
  - **Conflict Detection (6.3.2)**: `--dependency-graph conflicts` reports package names observed with multiple installed versions across sources.
  - **Minimal Update Set (6.3.3)**: `--dependency-graph minimal` suggests direct updates, keeping vulnerable packages and omitting dependency updates covered by selected parent updates.

### v6.2.2 (May 2026)
- **Unified progress UI**: Scan, update-check, and security phases now share `system_update.ui.progress.make_progress()` with a per-task duration column. Running tasks show `⏳`; finished rows lock in their actual task duration instead of all rows appearing to share the same elapsed time.
- **Banner and summary panels**: Startup context and scan summaries now render as grouped Rich panels with aligned file inventory, profile chips, source distribution chips, and security severity breakdowns.
- **Command failure diagnostics**: Failed subprocess stdout/stderr is captured in `system.log` for troubleshooting package-manager failures such as Chocolatey access-denied errors, while the interactive CLI and `errors.log` stay clean.
- **Version display fix**: The banner now reports the current package version instead of the stale `5.2.0` UI constant.

### v6.2.1 (May 2026)
- **Structured `errors.log` format**: Each WARNING/ERROR/CRITICAL line now carries the full debug context — `2026-05-02 13:19:23 | WARNING | logger.name | C:\path\file.py:42 | funcName() | pid=1234 tid=5678 | message`. When the record carries an exception, the full traceback is appended on indented lines so a single grep finds the entire failure context. Same `_DebugFormatter` is now applied to both `errors.log` (WARNING+) and `system.log` (DEBUG+ when `--log` / `--debug`).
- **`--format compact` redesigned**: was a single overflowing 50-char column that wrapped names across lines. Now a 3-column dense view (icon · package · current → latest) with `no_wrap` + ellipsis on the name and current columns, status markers in the latest column (`✓ up-to-date` green / `↑ <ver>` yellow / `🔥 <ver>` bold red / `✗ error` red / `? unknown` dim), up-to-date rows dimmed so update candidates pop, and a header row clarifying columns.
- **`--format verbose` Source column**: was `width=10` and truncated `🍫 choco…` / `🖥️ regis…`. Now `min_width=16` with `no_wrap=True` so `🍫 chocolatey` and `🖥️ registry` always fit on a single line (icons take 2 cells under Rich's measurement).
- **`tests/test_config.py`**: New tests covering the `_DebugFormatter` output (timestamp, file:line, funcName, pid/tid, traceback indentation) and `WarningFileHandler` level + formatter wiring.

### v6.2.0 (April 2026)
- **Rollback Support (6.2)**: Every batch update now records a snapshot; one command restores it
  - **Version Snapshots (6.2.1)**: New `src/system_update/snapshots.py` with `SnapshotStore` writing to `~/.system_update/history.db` (tables `snapshots` + `snapshot_packages`). Captures `(name, source, app_id, version_before, version_after, success)` per package. Recorded automatically by `--update-all`, `--update-source`, `--update-package`, and `--interactive`. Skipped during `--dry-run`.
  - **One-Click Rollback (6.2.2)**: `--rollback <id>` (or `--rollback last`) re-installs the captured `version_before` for each package via per-source builders in `executors/commands.py`: winget (`-v --force`), chocolatey (`--allow-downgrade`), npm/pnpm/bun/yarn (`@version`), pip (`==version --force-reinstall --no-deps`). Unsupported sources (PATH, registry, scoop, dotnet, rust, appx, msix) skip with a clear warning. Honours `--dry-run` and `--yes`; confirms before executing otherwise.
  - **Snapshot Listing (6.2.3)**: `--snapshot list` (id, timestamp, package count, success count, label) · `--snapshot show [--snapshot-id ID|last]` (per-package detail with before/after/✓✗) · `--snapshot delete --snapshot-id ID`.
  - New `⏪ Snapshots & Rollback` help panel; new sub-help topics `snapshot` and `rollback` (`--explain snapshot`, `--rollback help`).
- **Vulnerability detail in update flows**: The CVE table renders before the confirm prompt for `--update-package` (with a new "Vulns" column), `--update-all` security batch, and `--interactive` selection — the user sees exactly which CVEs they're about to patch. Selected vulnerable packages get a `🔥` tag in the interactive picker.
- **Cross-interpreter pip safety**: pip scanner records the originating interpreter (`install_path`); update/rollback commands target that exact Python so installs land in the right site-packages. `pip-audit` findings whose `fix_versions` are at or below the installed version are filtered out (no more false positives when `pip-audit` audited a different interpreter than ours).
- **Context-aware pip scope**: Default behaviour now matches `pip list` in your shell — venv-only when in a venv, system-only otherwise. No merging across interpreters by default.
- **VIRTUAL_ENV scrub**: When invoking a global Python under `uv run` (or any active venv), `VIRTUAL_ENV` / `CONDA_PREFIX` / `PYTHONHOME` / `PIP_*` are stripped from the child env so the targeted interpreter's own site-packages are reported, not the parent venv's.
- **Cache pip-context invalidation**: Cache header now records `pip_context` (scope, interpreter, in_venv). On load, if the running process's pip context differs, only the cached pip entries are dropped and rescanned — other sources stay cached. Switching between system Python and venv (or between venvs) is now self-correcting.
- **Cache expiry hint**: `💾 Loaded N items from cache` now shows `(expires HH:MM:SS · in 1h 23m)`. Auto-formats as `Hh Mm` → `Mm Ss` → `Ss` → `expired`.
- **`--no-cache` symmetry**: now skips cache write too (was only skipping read).
- **`--exclude` flag**: previously dead config; now functional — bare token (`pip` excludes every pip package), `source:name`, `source:*` all supported. Combine with `--save-config` to persist.
- **`--save-config` flag**: persist this run's CLI overrides (`--source`, `--exclude`, `--theme`, `--format`, `--icons`) into the active profile's `config.json`.
- **Profile fixes**: `--profile NAME`, `--profile-export`, `--profile-import` were silently no-ops — now activate via `config.reinit()` with cache/history/vuln-history rebound to the profile paths; activation auto-seeds a default config.
- **Banner runtime line**: Shows whether a venv is active (green pill) or system Python (yellow pill), plus the absolute interpreter path.
- **Source override notice**: `--source X` against `sources.X: false` now scans anyway with a clear `ℹ Source(s) disabled in config but requested via --source` message instead of silently doing nothing.
- **`--update-source` no longer auto-enables `--yes`**: now prompts before applying. Add `--yes` explicitly to skip.
- **Vulnerability history corruption recovery**: Corrupted JSON is auto-renamed to `<name>.corrupt-<ts>.bak` and a fresh empty file is started; warning logged.
- **MagicMock leak guard**: Strict `isinstance(str)` checks on persisted CLI overrides so unit-test mocks can't poison real `config.json` again.
- **Tests**: +31 new tests in `tests/test_snapshots.py` covering store CRUD, capture/build helpers, every supported & unsupported rollback source, dry-run / unsupported-source skip paths, snapshot recording during `execute_updates`. Plus pip-audit interpreter / version-aware tests in `tests/test_security.py`.

### v6.1.0 (April 2026)
- **Scheduled Updates (6.1)**: Run scans on a recurring schedule and react automatically
  - **Task Scheduler Integration (6.1.1)**: New `src/system_update/scheduler.py` wraps Windows `schtasks` for create / delete / list / status / run. Non-Windows platforms get a clear "configure cron / systemd / launchd manually" error.
  - **Daily / Weekly / Hourly / Monthly Scans (6.1.2)**: `--schedule create` accepts `--schedule-when daily|weekly|hourly|monthly|onstart|onlogon`, `--schedule-time HH:MM`, `--schedule-days MON,FRI`, `--schedule-args "..."`. Each task launches `python -m system_update <user-args>` with the current interpreter.
  - **Conditional Actions (6.1.3)**: New `src/system_update/conditions.py` with a rule engine. Predicates: `any_updates`, `any_vulnerabilities`, `any_critical_cves`, `security_updates_only`, `n_updates_gte:N`, `n_vulns_gte:N`. Actions: `notify`, `log`, `auto_update`. Configured under `conditional_actions` in config.json; trigger via `--schedule eval`.
  - `--schedule list` table now uses `schtasks /Query /FO CSV /V` and renders `Name`, `Next run`, `Last run`, `Last result`, `Status`. The schtasks "never run" sentinel (`30/11/1999`) renders as dim `Never`; non-zero exit codes turn red.
- **Profile bug fixes**:
  - `--profile NAME` was completely ignored — `SystemUpdateApp` always ran with the default profile. Now activated via `config.reinit()`, with cache/history/vuln-history rebound to the profile's paths.
  - `--profile-export PATH` and `--profile-import PATH` were also non-functional — now wired as meta commands with friendly error rendering.
  - Activating a fresh profile now auto-seeds a default `config.json` so the directory is no longer empty after first use.
- **`--exclude` flag (was dead config)**: `exclude` was declared in config but never read. Now CLI flag `--exclude foo,bar,pip:requests` actually drops matching packages. Token formats: bare name, `source:name`, `source:*` (or bare source name → drops every package from that source).
- **`--save-config` flag**: Persist the run's CLI overrides (`--source`, `--exclude`, `--theme`, `--format`, `--icons`) into the active profile's `config.json` so the next run uses them as defaults.
- **`--no-cache` symmetry**: previously read but still wrote cache. Now skips cache write too, with a clear `💾 --no-cache: skipping cache write` notice.
- **Cache expiry hint**: `💾 Loaded N items from cache (expires HH:MM:SS · in 1h 23m)` — auto-formats as `Hh Mm`, `Mm Ss`, or `Ss` as time runs out.
- **Source override notice**: `--source X` where `sources.X: false` now prints `ℹ Source(s) disabled in config but requested via --source: X (scanning anyway — pass --save-config to make this permanent)` instead of silently scanning nothing.
- **Banner redesign**: Profile pill (`👤 work` cyan, `default profile` white), tree-style file inventory with ✅/❌ existence, size, mtime; profile-aware split into `📁 Profile data` and `🌐 Shared data`; `Profiles available:` chip row with active profile highlighted (`★ work`).
- **Detailed sub-help — universal trigger**:
  - `--explain <flag>` works for any flag including booleans (e.g. `--explain interactive`, `--explain notify`).
  - `--<flag> help` works via pre-Typer argv intercept, so even boolean flags accept it (`--interactive help`, `--update-source help`).
  - `--explain` flag moved to the default `Options` panel next to `--help`; new `schedule` sub-help topic added.
  - Flags with sub-help pages now carry a `📖` marker in `--help`, with a tip line in the epilog.
- **Friendly choice errors** rendered in the standard Click error panel (no traceback) for `--export`, `--report`, `--format`, `--theme`, `--cloud-sync`, `--schedule`.
- **`-h` alias** for `--help`.
- **UTF-8 stdout** moved into `cli.py` so the installed `system-update` script entry-point also renders emoji help on Windows cp1252 consoles.
- **Tests**: +35 new tests (18 scheduler, 17 conditions). Full suite **388 tests**.

### v5.6.0 (April 2026)
- **Data Sharing (5.4)**: Import scans, merge across machines, sync the cache anywhere
  - **Import Scan Data (5.4.1)**: `--import PATH` (repeatable) loads scan data from JSON or CSV (auto-detected by suffix). Imported apps short-circuit live scanning. Accepts a bare list, or an object with a `packages` / `apps` / `items` / `data` key.
  - **Merge Scans (5.4.2)**: Multiple `--import` files are deduplicated by `(source, name, version)` with the latest `scan_time` winning per key. Add `--merge` to also fold in the existing on-disk cache. Merged result is persisted back to the cache.
  - **Cloud Sync (5.4.3)**: `--cloud-sync push|pull|status`. Two backends: `file` (any folder — point at OneDrive/Dropbox/Google Drive/iCloud/network share for free cross-device sync) and `http` (PUT/GET with optional `Authorization` header). Configure under a new `cloud_sync` block in `~/.system_update/config.json`.
- **Detailed sub-help pages**: 13 topics, 2 trigger styles
  - `--explain <topic>` — works for any flag, including booleans (e.g. `--explain interactive`, `--explain notify`)
  - `--<choice-flag> help` — works for choice flags (e.g. `--cloud-sync help`, `--export help`, `--report help`, `--source help`, `--format help`, `--theme help`)
  - `--explain list` lists all available topics
  - Topics: cloud-sync, export, format, history-stale, history-trends, import, interactive, notify, profile, report, source, theme, update-source
  - Each page is a Rich-formatted panel + tables + JSON snippets + worked examples
  - Unknown `--explain` value → friendly Click error panel with the full topic list (no traceback)
- **New `🔄 Data Sharing` help panel**: New flags grouped under their own emoji-labeled section in `--help`
- **UTF-8 stdout in `cli.py`**: Reconfiguration moved out of `__main__.py` so the installed `system-update` script entry-point also renders emoji help on Windows cp1252 consoles
- **New modules**: `src/system_update/data_sharing.py` (import/merge/cloud APIs), `src/system_update/subhelp.py` (page registry)
- **Tests**: +44 new tests (15 data-sharing, 29 sub-help). Full suite now 333 tests, ~92s.

### v5.5.0 (April 2026)
- **History CLI Ported**: `--history`, `--history-package`, `--history-trends`, `--history-stale N` now render Rich tables instead of stub messages
  - `--history` — last 10 scans (timestamp, source, pkgs, updates, vulns, duration)
  - `--history-package <name>` — full version-history rows for a package across all sources
  - `--history-trends` — per-source aggregates over the last 30 days + unique packages tracked
  - `--history-stale <days>` — packages whose latest `version_history` row is older than N days
- **History Reports**: `--report text|json|html` (with optional `--report-output PATH`) generates a self-contained scan/trend/stale/vuln summary; HTML report is fully branded (KPIs + tables) and writes anywhere
- **Interactive Picker**: `--interactive` opens a numbered TUI of update candidates (vulnerable first, tagged `[VULN]`); accepts `all` / `none` / `1,3,5-7` syntax; confirms before applying; honors `--dry-run` and `--yes`; clean Ctrl-C / EOF cancellation
- **Friendly Choice Errors**: Typos like `--export hmlt` or `--report hmtl` raise `typer.BadParameter` rendered in the standard Click error panel with a `Did you mean 'html'?` suggestion — no more tracebacks
- **Branded HTML Source Chips**: `📦 Sources` block in HTML reports now renders as colored pills (one per source) with brand color, emoji icon, count badge, and luminance-aware text color
- **Beautified `--help`**: Typer help output grouped into emoji-labeled panels (🔎 Scanning, ⚙️ Updates, 📤 Export, 🎨 UI, 🧭 Profiles, 📜 History, 🪵 Logging) with per-flag emojis and a worked-example epilog
- **Test Suite Speedup**: Full suite ~180s → ~80s
  - Late-bound `run_command` proxy in `tests/conftest.py` so `@patch('system_update.run_command')` finally reaches per-submodule callers (was silently missing — checker/scanner mocked tests hit real subprocess at 2-12s each)
  - Default-stub fixture prevents non-mocked tests from accidentally running real commands
  - Shared session-scoped `seeded_cache` fixture replaces three duplicate `--no-cache` integration scans (saved ~40s)
- **UTF-8 stdout in `__main__.py`**: Reconfigures stdout/stderr to UTF-8 so emoji-rich help renders on Windows cp1252 consoles

### v5.4.0 (April 2026)
- **Report Templates (5.3)**: HTML export now driven by a placeholder-based template + branding block
  - **Custom HTML Templates (5.3.1)**: `--html-template PATH` (or `report.template_path` in config) loads any `.html` file with `{title}`, `{logo_html}`, `{summary_cards}`, `{packages_rows}`, `{vuln_section}`, `{security_summary_section}`, `{sources_section}`, `{footer_text}`, `{primary_color}`, `{accent_color}` placeholders. Unknown tokens kept verbatim.
  - **Logo Insertion (5.3.2)**: `--html-logo PATH` (PNG/JPG/SVG/…) embeds as `data:` URI in the report header — no external files needed.
  - **Report Branding (5.3.3)**: `--html-title`, `--html-company`, plus `report.branding.{title,subtitle,company_name,primary_color,accent_color,background_color,footer_text}` in config. CLI wins over config, config over defaults.
  - New `src/system_update/report_templates.py` module with `ReportBranding`, `render_html`, `load_template`, `load_logo_data_uri`, `resolve_branding`.
  - Existing `export html` users unaffected — default template matches the previous built-in layout.

### v5.3.1 (April 2026)
- **Cache Partial-Scan + Merge**: `--source X` where `X` is not yet cached now scans only `X`, merges into cached apps, and saves — no more full rescan that discards warm cache
- **Invalid `--source` Handling**: Unknown tokens (e.g. `--source xpto`) warn with the list of available sources; mixed valid+invalid proceed with valid only; cache untouched when nothing valid remains
- **Empty-Cache Incremental**: Valid but empty cache + `--source X` silently routes through the merge path instead of triggering the full-scan banner
- **Unified Summary**: Dropped standalone `📈 Security Summary`; severity / packages-affected / persistent lines fold into the main `📊 Summary` block. Works for both cache-hit and fresh-scan paths
- **Per-CVE Security Table**: `🔥 Security Vulnerabilities Detected` now emits one row per CVE (was grouped per package with a count); added `Fix` column populated from `latest_version`; trailing `Found N known vulnerabilities in M package(s).` line
- **Cross-Source Vuln Dedup**: Findings keyed by `(package, cve)` so PyPI JSON + pip-audit + OSV duplicates collapse into one row, keeping the highest severity, numeric CVSS, and longest description
- **Cache v1.0.2**: Top-level deduplicated `sources` array enables fast missing-source detection; `AppInfo.to_dict()` now round-trips `security_findings`, `error_msg`, `install_path`

### v5.3.0 (April 2026)
- **Modular Refactor**: Split monolithic `system_update.py` (~7100 LOC) into `src/system_update/` package
  - Subpackages: `scanners/`, `checkers/`, `executors/`, `security/`, `ui/` — one module per source
  - `security/` split into per-source checkers: `npm`, `pip`, `pypi`, `osv`, `github`, `local`
  - `SystemUpdateApp` orchestrator lives in `app.py`; data models in `models.py`; config/cache/history/notifications as dedicated modules
  - Typer CLI at `system_update.cli` replaces argparse; entry point via `python -m system_update` (`__main__.py`)
  - Public API preserved: every class from the old flat layout still importable as `from system_update import X`
  - Build: `hatchling` packages `src/system_update` as a wheel (see `pyproject.toml`)
  - Tests: 267 green, migrated to invoke `python -m system_update` via `sys.executable`

### v5.2.0 (April 2026)
- **Export Formats**: Added multiple export format support beyond JSON and CSV
  - HTML Export: Styled HTML report with summary stats, tables, and color-coded status badges
  - XML Export: Enterprise-compatible XML format with full package data
  - Markdown Export: GitHub-compatible markdown tables with emoji status icons
  - Diff Export: Line-by-line version diff showing updates, vulnerabilities, and up-to-date packages
  - New CLI flag `--export` now supports: `json`, `csv`, `html`, `xml`, `markdown`, `diff`

### v5.1.0 (April 2026)
- **Historical Tracking**: SQLite database for scan history and package version tracking
  - Added `HistoryDatabase` class with tables for scans, package_snapshots, and version_history
  - Auto-record scans to SQLite database on each scan execution
  - New CLI flags: `--history`, `--history-package`, `--history-trends`, `--history-stale`
  - New CLI flags: `--report` with text/html/json output formats
  - Trend analysis: `get_update_trends()`, `get_stale_packages()`, `get_source_distribution()`

### v4.2.0 (April 2026)
- **Advanced Environment Variable System**: Comprehensive 12-factor app configuration via environment variables
  - Implemented core shortcuts: `SYSTEM_UPDATE_SOURCES`, `TIMEOUT`, `WORKERS`, `EXCLUDE`, `LOG_LEVEL`
  - Added dynamic double-underscore (`__`) override support for *any* nested configuration key (e.g., `SYSTEM_UPDATE_CACHE__ENABLED=false`)
  - Added smart string-to-boolean/integer type casting for environment variables to ensure safe parsing

### v4.1.0 (April 2026)
- **Configuration System**: Robust persistent configuration via JSON and YAML
  - JSON Config File (`~/.system_update/config.json`) with auto-generation and full parameter support
  - YAML Config Support (`config.yaml`/`config.yml`) with priority loading over JSON
  - Config Validation with safe default fallbacks for invalid user values
  - Config Migration schema built-in (`version: 1`) to auto-upgrade legacy formats
  - Smart Source Filtering: Automatically assumes unlisted sources are `false` if *any* source is explicitly enabled
  - `choco` alias support for the Chocolatey source

### v3.7.0 (April 2026)
- **Advanced Environment Variable System**: Comprehensive 12-factor app configuration via environment variables
  - Implemented core shortcuts: `SYSTEM_UPDATE_SOURCES`, `TIMEOUT`, `WORKERS`, `EXCLUDE`, `LOG_LEVEL`
  - Added dynamic double-underscore (`__`) override support for *any* nested configuration key (e.g., `SYSTEM_UPDATE_CACHE__ENABLED=false`)
  - Added smart string-to-boolean/integer type casting for environment variables to ensure safe parsing

### v3.6.0 (April 2026)
- **Configuration System**: Robust persistent configuration via JSON and YAML
  - JSON Config File (`~/.system_update/config.json`) with auto-generation and full parameter support
  - YAML Config Support (`config.yaml`/`config.yml`) with priority loading over JSON
  - Config Validation with safe default fallbacks for invalid user values
  - Config Migration schema built-in (`version: 1`) to auto-upgrade legacy formats
  - Smart Source Filtering: Automatically assumes unlisted sources are `false` if *any* source is explicitly enabled
  - `choco` alias support for the Chocolatey source

### v3.5.0 (April 2026)
- **UI Improvements**: Enhanced user interface with themes and display options
  - Custom Themes: default, vibrant, minimal, dark, neon color schemes
  - Display Formats: auto, compact, verbose, json modes
  - Source Icons: Custom icons per package manager (📦🍫📚🐍🦀)
  - Status Icons: Custom status indicators (✅⬆️⚠️🔒❓)
  - New `--theme` CLI flag
  - New `--format` CLI flag
  - New `--icons` CLI flag
  - ThemeManager and DisplayFormatter classes

### v3.4.0 (April 2026)
- **Notification System**: New notification features for updates
  - System Notifications: Native Windows toast/balloon tip notifications
  - Email Alerts: SMTP integration for email notifications
  - Webhook Notifications: HTTP POST to custom URLs
  - Custom Script Hooks: Execute user-defined scripts on events
  - New `--notify` CLI flag to force notifications
  - Config options: email_enabled, email_to, smtp_server, smtp_port, smtp_username, smtp_password

### v3.3.0 (April 2026)
- **Better Error Handling**: Enhanced error classification with recovery suggestions
  - ErrorCategory enum for error types: NOT_FOUND, TIMEOUT, PERMISSION_DENIED, NETWORK_ERROR, PARSE_ERROR, COMMAND_FAILED, UNKNOWN
  - CommandError class with structured error info and recovery suggestions
  - Applied to run_command function for better diagnostics
- **AppX/MSIX Fixes**: Fixed Windows Store app scanning
  - Fixed Get-AppxPackage to use without -AllUsers (was causing "Access is denied")
  - AppX now returns Store-signed packages (SignatureKind = 'Store')
  - MSIX returns sideloaded/development apps (SignatureKind != 'Store')
  - Appx/MSIX now show "✅ up-to-date" instead of "❓ unknown"
- **Banner Enhancement**: Shows all config files in data directory
  - Now displays: cache.json, config.json, errors.log, system.log, vulnerability_history.json
- **Logging Improvements**: Enhanced debug logging
  - --debug: Shows all commands, outputs, and errors in console + saves to system.log
  - --log: Saves to system.log without console output
  - Removed --verbose (redundant)
  - Separate errors.log file for warnings/errors only
- **Code Quality**: Ruff lint fixes
  - Removed unused imports
  - Fixed variable naming

### v3.2.0 (April 2026)
- **Progress Enhancements**: Enhanced progress bars with more metrics
  - ETA: Show estimated time remaining using TimeRemainingColumn
  - Speed: Show processing speed using SpeedColumn
  - All progress bars now display elapsed time, remaining time, and speed
  - More detailed source status during scanning

### v3.1.0 (April 2026)
- **Interactive TUI (3.1)**: Launch interactive mode with `--interactive` for package selection
  - Fuzzy Search: Search packages by partial name match
  - Package Multi-Select: Select multiple packages with numbers (e.g., 1,3,5 or 1-5)
  - Keyboard Navigation: Use `input()` for selection
  - Real-time Filtering: Type to fuzzy search packages
  - Preview Changes: Shows preview table before applying updates
- **Source Filter Refactor**: Rename `--include` to `--source` for clarity
  - `--source` filters scan to specific sources (e.g., `--source pip,npm`)
- **New --update-source**: Add new flag to update all packages from a specific source
  - Combines `--source` filtering with `--update-all` and `--yes`
- **Security Enhancements**: Enhanced interactive mode security vulnerability display
  - Show vulnerability count with fire emoji (🔥) in selection table
  - Show full security vulnerability details in preview before confirmation
  - Display CVE, severity, CVSS, and description for each vulnerability
  - Add horizontal lines between vulnerability entries
- **Improved UX**: Show selected packages before confirmation prompt (handles scrolling)

### v2.9.0 (April 2026)
- **Critical Alert Priority**: Critical vulnerabilities now sorted first and highlighted with 🚨 emoji and bold red blink effect
- **Security Update Auto-Priority**: Vulnerable packages are now prioritized and updated separately from regular updates

### v2.8.0 (April 2026)
- **Python-only Repository**: Simplified to only Python implementation (removed Node.js and PowerShell scripts)
- **Repository Cleanup**: Removed all Node.js and PowerShell files, tests, and documentation

### v2.7.0 (April 2026)
- **CVSS Score Display**: Show CVSS scores for vulnerabilities in security tables
- **Security Summary Stats**: Added detailed security summary with colored severity counts and affected package counts
- **Vulnerability History**: Implemented persistent vulnerability tracking over time in `vulnerability_history.json`
- **Enhanced CVE Details**: Added detailed vulnerability metadata including affected versions and published dates

### v2.6.0 (April 2026)
- **GitHub Advisory Database**: Added vulnerability scanning via GitHub Advisory API
- **Local Advisory Import**: Added support for custom vulnerability data from local JSON file (~/.system_update/advisories.json)

### v2.5.0 (April 2026)
- **NPM Audit Full Parse**: Enhanced npm vulnerability scanning to extract detailed advisory info from npm audit JSON output including via array details, advisoryUrl, fixAvailable, isDirect, and effects

### v2.4.0 (April 2026)
- **PyPI Security JSON**: Added vulnerability checking via PyPI JSON API for direct vulnerability data

### v2.3.0 (April 2026)
- **OSV API Integration**: Added Google's OSV vulnerability database support for all supported ecosystems
- **Extended vulnerability scanning**: Now checks npm, PyPI, crates.io, RubyGems, Go, CocoaPods, and Hex packages

### v2.2.0 (April 2026)
- **.NET Global Tools support**: Added .NET CLI tools scanning via `dotnet tool list -g`
- **Scoop support**: Added Scoop package manager support
- **AppX/Packaged Apps support**: Added Windows Store apps scanning via `Get-AppxPackage`
- **MSIX support**: Added MSIX packages scanning
- **New `--show-all` flag**: Show all packages including up-to-date ones (default shows only updates)
- **Improved output format**: "💾 Showing" line now appears after the package table
- **New "🎯 Found" message**: Clear indication of available updates count at the end

### v2.1.0 (April 2026)
- **Cargo crates.io API**: Now queries crates.io API directly instead of requiring cargo-install-update
- **Improved Rust scanning**: Better version comparison for Rust packages

### v2.0.0 (March 2026)
- **Major rewrite**: Reimplemented in Python with Rich UI
- **Parallel scanning**: ThreadPoolExecutor for concurrent package scanning
- **Security features**: OSV, GitHub Advisory, PyPI vulnerability scanning

### v1.0.0 (March 2026)
- Initial release
