# System Update CLI

> 🚀 A powerful system update tool for Windows.

A comprehensive Python-based system package management tool that scans, checks, and updates software from multiple sources.

**Version:** 7.1.0
**Runtime:** Python 3.8+
**Platform:** Windows (primarily), cross-platform support
**Layout:** Modular package at `src/system_update/` (typer CLI)

---

## 🌟 Features

- **Multi-source Package Discovery**: Scan applications installed via Winget, Chocolatey, NPM, PNPM, Bun, Yarn, PIP, Scoop, system PATH executables, and Windows Registry.
- **Security Scanning**: Real-time vulnerability checking for NPM (`npm audit`) and PIP (`pip check`) packages.
- **Smart Caching**: 2-hour cache with per-source freshness, incremental rescans, delta records, a bounded hot-package LRU cache, and optional prefetch.
- **Dry-run & Output Options**: Safely preview updates before applying them and export reports to JSON or CSV formats.
- **Rich Terminal UI**: Beautiful, colorful console output built with the `rich` library, featuring spinners, progress bars, and emoji indicators.
- **Parallel Processing**: ThreadPoolExecutor for optimal performance.
- **Modular Architecture**: Clean separation of concerns with dataclasses.
- **Smart Version Comparison**: Handles preview/stable version detection.
- **Interactive TUI**: Fuzzy search, multi-select, and preview for package selection.
- **Remote Management**: Manage a Windows host inventory and run scans, updates, and consolidated reports over WinRS/WinRM.
- **Plugin Architecture**: Add custom package scanners and notification channels from local Python plugins.

---

## 📋 Requirements

### Python Dependencies
- **rich** - Terminal UI framework (auto-installed on first run)

### System Requirements
- **Python 3.8+** - Required for dataclasses and type hints
- **Windows 10/11** - Primary platform (Winget, Registry support)
- **Package Managers** - Optional, based on sources used:
  - **Winget** - Windows Package Manager
  - **Chocolatey** - Chocolatey package manager
  - **Node.js** - For NPM, PNPM, Bun, Yarn support
  - **Python** - For PIP package support
  - **Rust** - For Cargo package support (`cargo-update` required for updates)
  - **Git** - For Git version detection
  - **PowerShell** - For Registry scanning and PS updates

---

## 🚀 Quick Start

### Installation

```bash
# Clone + enter
cd C:\Git\System_Update

# Install via uv (recommended — reads pyproject.toml)
uv sync --all-extras --dev

# Or plain pip
pip install -e .
```

### Basic Usage

All invocations go through `python -m system_update` (the module's `__main__` entry). The old `python -m system_update` flat-file layout was removed in 5.3.0.

```bash
# Run a full system scan
python -m system_update

# Update all packages automatically
python -m system_update --update-all --yes

# Check for updates without installing
python -m system_update --dry-run

# Export scan results to JSON
python -m system_update --export json --output report.json
```

---

## 📖 Command Reference

### Options

| Option | Description |
|--------|-------------|
| `--update-all` | Update every package with available updates |
| `--update-source <source>` | Update all packages from a specific source |
| `--update-package <name>` | Update a specific package by name |
| `--version <ver>` | Target version (use with `--update-package`) |
| `--source <source>` | Filter by source (winget\|chocolatey\|npm\|pnpm\|bun\|yarn\|pip\|path\|rust\|registry) |
| `--dry-run` | Show planned updates without executing |
| `--no-cache` | Force fresh scan (ignore cache) |
| `--clear-cache` | Remove cache file and exit |
| `--export <json\|csv\|html\|xml\|md\|diff>` | Export scan results to file |
| `--output <file>` | Output path for export |
| `--dependency-graph <dot\|conflicts\|minimal>` | Generate Graphviz DOT, show version conflicts, or suggest minimal direct updates |
| `--graph-output <file>` | Output path for `--dependency-graph dot` |
| `--remote <action>` | Remote action: `list`, `add`, `remove`, `scan`, `update`, `report`, or `help` |
| `--remote-host <name>` | Target one inventory host, or name the host for `--remote add/remove` |
| `--remote-group <name>` | Target every host assigned to a group |
| `--remote-address <addr>` | Hostname or IP address for `--remote add`; defaults to `--remote-host` |
| `--remote-user <user>` | Username used by `winrs` for `--remote add` |
| `--remote-groups <csv>` | Comma-separated groups for `--remote add` |
| `--remote-args "<args>"` | Extra arguments appended to the remote `system-update` command |
| `--remote-output <file>` | Output path for `--remote report` consolidated JSON |
| `--remote-timeout <seconds>` | Per-host remote execution timeout; default is `600` |
| `--remote-verbose` | Show each host's stdout/stderr tail when it completes |
| `--remote-debug` | Print target metadata, timeout, redacted `winrs` command, progress heartbeat, and completion output |
| `--source <csv>` | Limit scan to specific sources (e.g., `winget,npm,pip`) |
| `--yes`, `-y` | Skip confirmation prompts |
| `--help`, `-h` | Show help message |
| `--show-all` | Show all packages (including up-to-date) |
| `--log` | Enable logging to file |
| `--debug` | Show all executed commands |
| `--interactive` | Launch interactive TUI for package selection |

### Examples

```bash
# Full system scan with interactive updates
python -m system_update

# Update all packages without confirmation
python -m system_update --update-all --yes

# Update only Winget packages
python -m system_update --source winget --yes

# Update only Rust packages
python -m system_update --source rust --yes

# Update all packages from a specific source
python -m system_update --update-source rust --yes

# Update all Winget packages
python -m system_update --update-source winget --dry-run

# Update a specific package
python -m system_update --update-package git --source chocolatey

# Dry run to preview updates
python -m system_update --dry-run

# Scan only specific sources
python -m system_update --source winget,npm,pip

# Export results to JSON
python -m system_update --export json --output updates.json

# Export results to CSV
python -m system_update --export csv --output updates.csv

# Export results to HTML
python -m system_update --export html --output updates.html

# Export results to XML
python -m system_update --export xml --output updates.xml

# Export results to Markdown
python -m system_update --export md --output updates.md

# Export results to Diff
python -m system_update --export diff --output updates.diff

# Export dependency graph to Graphviz DOT
python -m system_update --dependency-graph dot --graph-output deps.dot

# Detect package version conflicts
python -m system_update --dependency-graph conflicts --show-all

# Suggest a minimal direct update set
python -m system_update --dependency-graph minimal

# Debug a remote host that appears stuck
python -m system_update --remote scan --remote-host build01 --remote-debug

# Force fresh scan and export
python -m system_update --no-cache --export json

# Show all packages (including up-to-date)
python -m system_update --show-all

# Interactive package selection
python -m system_update --interactive
```

---

## 🌐 Remote Management

Remote management lets one machine run `system-update` on other Windows hosts through `winrs`. The local machine keeps an inventory at `~/.system_update/inventory.json`, then fans out scan/update/report commands to a single host or to a group.

### Requirements

- `winrs` must be available on the local machine.
- WinRM must be enabled on target hosts, usually with `winrm quickconfig`.
- The caller must be allowed to connect to the target host. In simple lab setups, that often means configuring TrustedHosts on the caller:

```powershell
winrm set winrm/config/client '@{TrustedHosts="build01"}'
```

- `system-update` must be installed and available in `PATH` on each remote host.
- Set `SYSTEM_UPDATE_REMOTE_PASS` in the environment to provide the `winrs` password without putting it in the command line.

### Actions

| Action | Description |
|--------|-------------|
| `--remote list` | Show all hosts in the inventory |
| `--remote add` | Add or replace a host; requires `--remote-host` |
| `--remote remove` | Remove a host; requires `--remote-host` |
| `--remote scan` | Run `system-update --no-cache --export json -o -` remotely and summarize results |
| `--remote update` | Run `system-update --update-all --yes` remotely |
| `--remote report` | Run remote scans and write/print a consolidated fleet report |
| `--remote help` | Show detailed in-app remote help |

### Remote Examples

```powershell
# Add a host to the inventory
python -m system_update --remote add --remote-host build01 --remote-address build01.corp --remote-user "DOMAIN\admin" --remote-groups builders,windows

# List configured hosts
python -m system_update --remote list

# Scan one host
python -m system_update --remote scan --remote-host build01

# Scan all hosts in a group
python -m system_update --remote scan --remote-group builders

# Pass extra flags to the command executed on the remote host
python -m system_update --remote scan --remote-group builders --remote-args "--source winget --show-all"

# Update one host, with a shorter timeout
python -m system_update --remote update --remote-host build01 --remote-timeout 300

# Create a consolidated JSON report
python -m system_update --remote report --remote-group builders --remote-output fleet-report.json

# Show stdout/stderr tails when each host finishes
python -m system_update --remote scan --remote-group builders --remote-verbose

# Debug a host that appears stuck
python -m system_update --remote scan --remote-host build01 --remote-debug
```

### Verbose vs Debug

Use `--remote-verbose` when you want completion details: the command still runs normally, and each host prints stdout/stderr tails after it finishes.

Use `--remote-debug` when a host appears frozen. It implies verbose output and additionally prints the remote command, timeout, host metadata, redacted local `winrs` argv, a start message, and a heartbeat every 30 seconds until completion or timeout. Password values are masked as `-p:***`.

---

## 🔧 Configuration

### Default Configuration

The script uses the following default settings stored in `~/.system_update/config.json`:

```json
{
    "cache": {
        "duration_hours": 2,
        "enabled": true,
        "incremental_enabled": true,
        "delta_enabled": true,
        "lru_max_items": 512,
        "prefetch_enabled": false,
        "prefetch_threshold_minutes": 15
    },
    "performance": {
        "parallel_scan": true,
        "max_workers": 6,
        "timeout_seconds": 45
    },
    "sources": {
        "winget": true,
        "chocolatey": true,
        "npm": true,
        "pnpm": true,
        "bun": true,
        "yarn": true,
        "pip": true,
        "path": true,
        "registry": true,
        "rust": true
    },
    "security": {
        "enabled": true,
        "auto_check": true,
        "severity_threshold": "medium"
    },
    "ui": {
        "theme": "default",
        "show_stats": true,
        "compact_view": false,
        "color_scheme": "vibrant"
    },
    "export": {
        "default_format": "json",
        "include_timestamp": true
    }
}
```

### Data Directory

- **Default:** `~/.system_update` (user's home directory)
- **Cache File:** `~/.system_update/cache.json`
- **Log File:** `~/.system_update/system.log`
- **Config File:** `~/.system_update/config.json`
- **Remote Inventory:** `~/.system_update/inventory.json`

---

## 📊 Supported Sources

| Source | Scan | Update Check | Security Scan |
|--------|------|--------------|---------------|
| Winget | ✅ | ✅ | ❌ |
| Chocolatey | ✅ | ✅ | ❌ |
| NPM | ✅ | ✅ | ✅ |
| PNPM | ✅ | ✅ | ❌ |
| Bun | ✅ | ✅ | ❌ |
| Yarn | ✅ | ✅ | ❌ |
| PIP | ✅ | ✅ | ✅ |
| Rust | ✅ | ✅ | ❌ |
| PATH | ✅ | ✅ | ❌ |
| Registry | ✅ | ✅ | ❌ |
| Scoop | ✅ | ✅ | ❌ |
| dotnet | ✅ | ✅ | ❌ |
| AppX | ✅ | ❌ | ❌ |
| MSIX | ✅ | ❌ | ❌ |

---

## 🔒 Security Features

### Vulnerability Scanning

The CLI automatically scans for security vulnerabilities in:

- **NPM packages** - Uses `npm audit --json` to detect known CVEs
- **PIP packages** - Uses `pip check --format=json` to identify security issues

### Severity Thresholds

Vulnerabilities are filtered by severity level:
- **Critical** - Highest priority (CVSS 9.0-10.0)
- **High** - Serious security risk (CVSS 7.0-8.9)
- **Medium** - Moderate risk (CVSS 4.0-6.9) - *default threshold*
- **Low** - Minor issues (CVSS 0.1-3.9)

---

## 📤 Export Formats

### JSON Export

```json
{
  "scan_time": "2026-02-26T10:30:00.000000",
  "summary": {
    "total_apps": 45,
    "up_to_date": 30,
    "update_available": 15,
    "vulnerable": 0,
    "unknown": 0
  },
  "security_summary": {
    "total_vulns": 0,
    "packages_affected": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
  },
  "sources": {
    "Winget": 20,
    "NPM": 10,
    "PIP": 15
  },
  "apps": [
    {
      "name": "git",
      "source": "winget",
      "version": "2.40.1",
      "latestVersion": "2.44.0",
      "status": "update_available"
    }
  ]
}
```

### CSV Export

```csv
Name,Source,Version,Latest,Status
git,Winget,2.40.1,2.44.0,update_available
node,NPM,18.16.0,20.11.0,update_available

Security Summary
Critical,0
High,0
Medium,0
Low,0

Sources
Winget,20
NPM,10
PIP,15
```

### HTML Export

Styled HTML report with:
- Summary stats cards (Total, Up to Date, Updates, Vulnerable)
- Color-coded status badges
- Security Vulnerabilities table (if found)
- Security Summary section (Critical/High/Medium/Low)
- Sources breakdown

### XML Export

Enterprise-compatible XML with:
- Package details with vulnerability data
- Security vulnerabilities section
- Security summary counts
- Source distribution

### Markdown Export

GitHub-compatible markdown with:
- Summary table
- Package table with emoji status icons
- Security Vulnerabilities section (if found)
- Security Summary table
- Sources list

### Diff Export

Line-by-line diff showing:
- Updated packages (old -> new versions)
- Vulnerable packages with CVE details
- Up to date packages
- Security Summary
- Sources breakdown

---

## 🏗️ Architecture

Since 5.3.0 the code lives in a modular package under `src/system_update/`.

### Package Layout

```
src/system_update/
├── __init__.py              # Public re-exports (AppInfo, SystemUpdateApp, ...)
├── __main__.py              # `python -m system_update` entry
├── cli.py                   # Typer app (argparse replaced)
├── app.py                   # SystemUpdateApp orchestrator
├── models.py                # AppInfo, SecurityInfo, UpdateStatus, CommandError
├── config.py                # SystemConfig, setup_logging
├── cache.py                 # CacheManager
├── dependency_graph.py      # Graphviz DOT, conflict detection, minimal update set
├── history.py               # HistoryDatabase, VulnerabilityHistory (SQLite + JSON)
├── notifications.py         # NotificationManager
├── export.py                # JSON/CSV/HTML/XML/MD/diff exporters
├── utils.py                 # run_command, console, SOURCE_ICONS, THEMES
├── scanners/                # One module per source (winget, npm, pip, ...)
├── checkers/                # Per-source update-check logic
├── executors/               # execute_single_update, execute_updates + commands.py
├── security/                # Per-source vuln scanners (npm, pip, pypi, osv, github, local)
└── ui/                      # ThemeManager, DisplayFormatter, UISystem
```

### Core Components

```
SystemUpdateApp          - Orchestrator (scan → check → security → display → export → update)
├── UISystem             - Rich-based UI
├── PackageScanner       - Multi-source package discovery (parallel)
├── UpdateChecker        - Update detection
├── UpdateExecutor       - Update execution
├── SecurityChecker      - Facade over security/* per-source checkers
├── CacheManager         - 2-hour JSON cache
├── DependencyGraph      - Graphviz DOT, conflict detection, minimal update set
├── HistoryDatabase      - SQLite history (scans, package_snapshots, version_history)
├── VulnerabilityHistory - Persistent CVE tracking (JSON)
└── NotificationManager  - Toast/email/webhook/hook dispatch
```

### Backward compatibility

Every name from the old flat `system_update.py` is re-exported from the package root, so existing scripts using `from system_update import AppInfo, SystemUpdateApp, run_command, ...` keep working. The monolithic file itself was removed.

---

## 🛠️ Troubleshooting

### Common Issues

**Rich library not installed:**
The script will prompt to install automatically. Alternatively:
```bash
pip install rich
```

**Cache permission errors:**
Ensure write permissions to `~/.system_update` directory.

**Command timeouts:**
Increase `timeout_seconds` in config or use `--no-cache`.

**Package manager not found:**
Verify the package manager is installed and in PATH.

**Rust updates not working:**
Ensure `cargo-update` is installed: `cargo install cargo-update`

### Logging

All operations are logged to `~/.system_update/system.log`.

---

## 🤝 Contributing

Contributions are welcome! Please ensure:
- Type hints are used throughout
- Rich UI components follow existing patterns
- Tests cover new functionality
- Documentation is updated

---

## 📞 Support

For issues or questions:
1. Check the log file at `~/.system_update/system.log`
2. Run with `--no-cache` to rule out cache issues
3. Verify Python version: `python --version`
4. Ensure package managers are accessible

---

## 🧪 Testing

This project includes a comprehensive test suite using pytest. Tests are located in the `tests/` directory.

### Run Tests

```bash
# Install dependencies
uv sync --all-extras --dev

# Run tests
uv run pytest

# Single file
uv run pytest tests/test_checkers.py -v

# Coverage
uv run task test-cov

# Lint / format
uv run task check
uv run task format
```

---

For complete version history and license, see [CHANGELOG.md](CHANGELOG.md).

Contributions and enhancements are always welcome!
