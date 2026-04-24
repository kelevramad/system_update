# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## 📝 License

This project is provided as-is for system administration and package management.

---

## 🆕 Latest Changes

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
