# System Update CLI

> 🚀 A powerful system update tool for Windows.

A comprehensive Python-based system package management tool that scans, checks, and updates software from multiple sources.

**Version:** 8.14.2
**Runtime:** Python 3.8+
**Platform:** Windows (primarily), cross-platform support
**Layout:** Modular package at `src/system_update/` (typer CLI)

---

## 🌟 Features

- **Multi-source Package Discovery**: Scan applications installed via Winget, Chocolatey, NPM, PNPM, Bun, Yarn, PIP, Scoop, system PATH executables, Windows Registry, AppX/MSIX, drivers, services, PowerShell modules, and VS Code extensions.
- **Security Scanning**: Vulnerability checking through npm audit, pip/pip-audit, OSV, PyPI, GitHub Advisory, and local advisory data.
- **Smart Caching**: 2-hour readable JSON cache with per-source freshness, incremental rescans, delta records, pruning, selective storage, a bounded hot-package LRU cache, optional prefetch, and post-upgrade refresh so updated packages do not reappear as stale updates.
- **Network Optimization**: Batched OSV security lookups, rate-limited/cached JSON API responses, and one shared `winget upgrade` table per update-check run.
- **Deduplicated Internals**: Built-in scanners share one decorator-backed registry, update/rollback command builders share one backend dispatch table, and data-directory lookups use the shared secure helper.
- **Dry-run & Output Options**: Safely preview updates before applying them and export reports to JSON, CSV, HTML, XML, Markdown, or diff formats.
- **Rich Terminal UI**: Beautiful, colorful console output built with the `rich` library, featuring spinners, progress bars, and emoji indicators.
- **Parallel Processing**: Per-source scanner and update-checker worker pools with graceful degradation when one source fails.
- **Modular Architecture**: Thin CLI orchestration with typed CLI option contracts, command modules, dataclasses, and separated rendering helpers.
- **Smart Version Comparison**: Handles preview/stable version detection.
- **Interactive TUI**: Fuzzy search, multi-select, and preview for package selection.
- **Remote Management**: Manage a Windows host inventory and run scans, updates, and consolidated reports over WinRS/WinRM.
- **Plugin Architecture**: Add custom scanners, update checkers, package updaters, **vulnerability checkers**, and notification channels from local Python plugins. Plugin loading is **opt-in** (`plugins.enabled=true`) and can be hardened further with a SHA-256 allowlist; bypass entirely with `--no-plugins`.

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
  - **PowerShell** - For Registry, AppX/MSIX, services, drivers, and PowerShell module scanning

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

All invocations go through `python -m system_update` (the module's `__main__` entry) or the installed `system-update` command. The old `python system_update.py` flat-file layout was removed in 5.3.0.

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
| `--source <source>` | Filter by source (winget\|chocolatey\|npm\|pnpm\|bun\|yarn\|pip\|path\|rust\|registry\|appx\|msix\|drivers\|services\|psmodules\|vsextensions) |
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
| `--list-plugins` | Show loaded plugins (one row per plugin with capability icons + docstring summary) |
| `--list-plugins-detail` | Per-extension-point breakdown of every registered scanner/checker/updater/security/notifier |
| `--no-plugins` | Bypass the plugin loader entirely (security kill switch) |
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

Remote JSON stdout is capped before parsing to protect the orchestrator from
oversized responses. The default is 10 MiB and can be changed with
`remote.max_response_bytes` in the config file or
`SYSTEM_UPDATE_REMOTE__MAX_RESPONSE_BYTES`.

---

## 🔧 Configuration

### Default Configuration

The script uses the following default settings stored in `~/.system_update/config.json`:

Configuration loading prefers `config.json` when it exists. If no JSON config
exists, `config.yaml` or `config.yml` can be used, but PyYAML must be installed;
otherwise startup raises a clear error instead of silently ignoring the YAML
file and running with defaults.

```json
{
    "cache": {
        "duration_hours": 2,
        "enabled": true,
        "incremental_enabled": true,
        "delta_enabled": true,
        "lru_max_items": 512,
        "prefetch_enabled": false,
        "prefetch_threshold_minutes": 15,
        "prune_after_days": 14,
        "storage_fields": [
            "name",
            "source",
            "version",
            "latestVersion",
            "appId",
            "status",
            "scanTime",
            "errorMsg",
            "installPath",
            "securityFindings"
        ],
        "omit_empty_fields": true
    },
    "performance": {
        "parallel_scan": true,
        "max_workers": 6,
        "timeout_seconds": 45
    },
    "network": {
        "enabled": true,
        "cache_enabled": true,
        "cache_ttl_seconds": 3600,
        "rate_limit_seconds": 0.2,
        "timeout_seconds": 10
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
        "rust": true,
        "scoop": true,
        "dotnet": true,
        "appx": true,
        "msix": true,
        "drivers": true,
        "services": true,
        "psmodules": true,
        "vsextensions": true
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
| AppX | ✅ | ✅ | ❌ |
| MSIX | ✅ | ✅ | ❌ |
| Drivers | ✅ | ✅ | ❌ |
| Services | ✅ | ✅ | ❌ |
| PowerShell modules | ✅ | ✅ | ❌ |
| VS Code extensions | ✅ | ✅ | ❌ |
| Plugin sources | ✅ | ✅ | Plugin-defined |

---

## 🔒 Security Features

### Vulnerability Scanning

The CLI automatically scans for security vulnerabilities in:

- **NPM packages** - Uses `npm audit --json` to detect known CVEs
- **PIP packages** - Uses `pip check`, `pip-audit`, PyPI JSON, and OSV data where available
- **OSV-supported ecosystems** - Batched OSV lookups cover supported package ecosystems such as npm, PyPI, and crates.io
- **Local/GitHub advisories** - Advisory imports and GitHub Advisory data enrich package findings

### Severity Thresholds

Vulnerabilities are filtered by severity level:
- **Critical** - Highest priority (CVSS 9.0-10.0)
- **High** - Serious security risk (CVSS 7.0-8.9)
- **Medium** - Moderate risk (CVSS 4.0-6.9) - *default threshold*
- **Low** - Minor issues (CVSS 0.1-3.9)

---

## 🧩 Plugins

Plugins extend `system-update` with custom package sources, update checkers, updaters, vulnerability feeds, and notification channels. Each plugin is a single Python file under `~/.system_update/plugins/` (or any directory listed under `plugins.paths` in `config.json`).

### Opt-in by default (Hardening 1.2)

Since plugins execute arbitrary Python at scan time, the loader is **off by default**. To enable:

```jsonc
// ~/.system_update/config.json
{
  "plugins": {
    "enabled": true,
    "paths": [],
    "require_hash_allowlist": false
  }
}
```

**Hardened mode (recommended for shared machines):** drop a SHA-256 manifest next to your plugins so only known-good files load.

```bash
# Compute the digest of every plugin you want to load:
python -c "import hashlib; print(hashlib.sha256(open(r'~\.system_update\plugins\demo_plugin.py','rb').read()).hexdigest())"
```

```text
# ~/.system_update/plugins/allowed.sha256
5da4642db1db34e1ac5c2030bfa6975591e52fd504df5d027b8b9b6e452072c6  demo_plugin.py
```

Set `plugins.require_hash_allowlist: true` to refuse loading any plugin without a manifest entry. Bypass the loader at any time with `--no-plugins`.

### Extension points

| Hook | Registry call | Receives | Returns |
|------|---------------|----------|---------|
| Scanner | `register_scanner(source, scan, …)` | _no args_ | `Iterable[AppInfo]` (or dicts) |
| Checker | `register_checker(source, check, …)` | `List[AppInfo]` | int (count of updates found) |
| Updater | `register_updater(source, update, …)` | `AppInfo` | `bool` (success) |
| Security | `register_security_checker(source, check, …)` | `List[AppInfo]` | `List[dict]` of vulnerability findings |
| Notifier | `register_notifier(name, notify, …)` | `(event, title, message, payload, config)` | `None` |

Plugin security checkers participate in the `🔒 Checking security vulnerabilities` stage as their own progress row, alongside the built-in OSV / npm / pip / PyPI / GitHub Advisory feeds.

### Reference template

A complete, working reference plugin lives in this repo at
[`examples/plugins/demo_plugin.py`](examples/plugins/demo_plugin.py). It implements every extension point and demonstrates the recommended shape:

- Returning typed `AppInfo` (not dicts).
- Filtering by `app.source` so the plugin never mutates apps owned by other plugins.
- Using the `UpdateStatus` enum.
- Resolving the data dir via `context.data_dir` from `register_plugin(registry, context)`.
- Wrapping I/O in `try/except OSError` and logging via `logging`.

### How to create a plugin (step-by-step)

This walkthrough shows how to ship a working scanner + security checker for a fictional `mytool` source.

**1. Create the file**

```bash
mkdir -p ~/.system_update/plugins
$EDITOR ~/.system_update/plugins/mytool_plugin.py
```

**2. Implement the extension points you need**

```python
"""mytool-plugin — discover and check mytool packages.

The first non-empty line of this docstring becomes the description
shown by ``--list-plugins``.
"""

from __future__ import annotations

import logging
from typing import Iterable, List

from system_update.models import AppInfo, UpdateStatus
from system_update.plugins import PluginContext, PluginRegistry

PLUGIN_NAME = 'mytool-plugin'
SOURCE = 'mytool'

logger = logging.getLogger(f'system_update.plugin.{SOURCE}')


def scan() -> Iterable[AppInfo]:
    """Return everything mytool has installed."""
    return [
        AppInfo(name='mytool-cli', source=SOURCE, version='1.2.3',
                update_status=UpdateStatus.UNKNOWN),
    ]


def check(apps: List[AppInfo]) -> int:
    """Set ``latest_version`` for our packages — the rest of the CLI
    handles the diff and the post-scan display."""
    count = 0
    for app in apps:
        if app.source != SOURCE:
            continue
        # Replace this with a real version lookup against your registry.
        app.latest_version = '1.3.0'
        app.update_status = UpdateStatus.UPDATE_AVAILABLE
        count += 1
    return count


def update(app: AppInfo) -> bool:
    """Apply the update; return True on success."""
    if app.source != SOURCE:
        return False
    # Run your actual installer here and verify the result.
    app.version = app.latest_version or app.version
    app.latest_version = ''
    app.update_status = UpdateStatus.UP_TO_DATE
    return True


def security_check(apps: List[AppInfo]) -> List[dict]:
    """Return a list of vulnerability dicts for our packages.

    The shape mirrors what the built-in checkers produce; see
    ``system_update/security/local.py`` for the canonical fields.
    """
    findings: List[dict] = []
    for app in apps:
        if app.source != SOURCE or app.name != 'mytool-cli':
            continue
        finding = {
            'package': app.name,
            'severity': 'HIGH',
            'cvss_score': 7.5,
            'cve': 'CVE-2026-EXAMPLE',
            'description': 'Replace this with a real advisory description.',
            'source': PLUGIN_NAME,
            'affected_versions': ['<1.3.0'],
            'fix_available': True,
            'fixed_version': '1.3.0',
            'installed_version': app.version,
            'advisory_url': 'https://example.com/advisories/CVE-2026-EXAMPLE',
        }
        app.security_findings.append(finding)
        app.update_status = UpdateStatus.VULNERABLE
        findings.append(finding)
    return findings


def register_plugin(registry: PluginRegistry, context: PluginContext) -> None:
    registry.register_scanner(SOURCE, scan, description='mytool scanner')
    registry.register_checker(SOURCE, check, description='mytool update checker')
    registry.register_updater(SOURCE, update, description='mytool installer')
    registry.register_security_checker(
        SOURCE, security_check, description='mytool advisory feed',
    )
```

You can register only the hooks you need — every `register_*` call is independent.

**3. Opt in via config**

```jsonc
// ~/.system_update/config.json
{
  "plugins": {
    "enabled": true
  }
}
```

**4. (Optional) Pin the file with SHA-256**

```bash
python -c "import hashlib; print(hashlib.sha256(open(r'~/.system_update/plugins/mytool_plugin.py','rb').read()).hexdigest())" \
  > /tmp/digest

cat /tmp/digest mytool_plugin.py > ~/.system_update/plugins/allowed.sha256
```

```text
# allowed.sha256 format (one line per plugin)
<sha256>  mytool_plugin.py
```

Then set `plugins.require_hash_allowlist: true` to refuse loading any plugin not listed.

**5. Verify it loaded**

```bash
system-update --list-plugins
```

```
┌──────────────┬─────────────┬────────────────────────────────────┐
│ Plugin       │ Caps        │ Description                        │
├──────────────┼─────────────┼────────────────────────────────────┤
│ mytool-plugin│ 🧩 🔄 ⬆️ 🔒│ mytool-plugin — discover and check │
│              │             │ mytool packages.                   │
└──────────────┴─────────────┴────────────────────────────────────┘
```

**6. Run a scan and confirm the results**

```bash
system-update --source mytool --no-cache --show-all
```

The plugin's `security_check` runs as its own row in the **🔒 Checking security vulnerabilities** stage, and findings show up in the apps table as `🔥 vulnerable`.

### Plugin contract reference

| Function | When it runs | Receives | Returns |
|----------|--------------|----------|---------|
| `scan()` | During scan phase, when its source is enabled | _no args_ | `Iterable[AppInfo]` (or dicts; auto-coerced) |
| `check(apps)` | During update-check phase | apps owned by this source | `int` — number of updates found |
| `update(app)` | When the user runs `--update-all`, `--update-source`, or `--update-package` | one `AppInfo` | `bool` — success |
| `security_check(apps)` | During the **🔒 Checking security vulnerabilities** stage | apps owned by this source | `List[dict]` of vulnerability findings |
| `notify(event, title, message, payload, config)` | Any time the CLI dispatches a notification | event name + body + payload | `None` |

The vulnerability dict shape (mirrors the built-in checkers):

```python
{
    'package': str,
    'severity': 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW',
    'cvss_score': float | None,
    'cve': str,
    'description': str,
    'source': str,
    'affected_versions': list[str],
    'published_date': str,
    'advisory_url': str,
    'fix_available': bool,
    'fixed_version': str,        # optional but recommended
    'installed_version': str,    # optional but recommended
}
```

Plugins that need a writable directory should use `context.data_dir` (passed to `register_plugin`) instead of hard-coding paths.

### Listing plugins

```bash
# One-line summary with capability icons and docstring description:
system-update --list-plugins

# Full per-extension-point breakdown:
system-update --list-plugins-detail
```

### Plugin-load warning

When a plugin loads, a bold-yellow `PLUGIN LOAD` Rich panel appears above the startup banner:

```
┌─  PLUGIN LOAD  ──────────────────────────────────────────────────────────┐
│ ⚠️  Loading plugin: C:\Users\vchav\.system_update\plugins\demo_plugin.py │
│    Disable with plugins.enabled=false in ~/.system_update/config.json    │
│    or run with --no-plugins.                                             │
└──────────────────────────────────────────────────────────────────────────┘
```

The warning fires once per process per plugin file; the same line is also written to `system.log` at DEBUG level when `--debug` is used.

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
├── network.py               # Shared JSON HTTP cache/rate-limit helper
├── remote.py                # WinRS/WinRM remote management
├── plugins.py               # Plugin API and loader
├── snapshots.py             # Update snapshots and rollback
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
├── UpdateChecker        - Parallel update detection; Winget-backed sources share one winget upgrade table per run
├── UpdateExecutor       - Update execution
├── SecurityChecker      - Facade over security/* per-source checkers
├── CacheManager         - 2-hour JSON cache
├── DependencyGraph      - Graphviz DOT, conflict detection, minimal update set
├── HistoryDatabase      - SQLite history (scans, package_snapshots, version_history)
├── VulnerabilityHistory - Persistent CVE tracking (JSON)
├── PluginRegistry       - Custom scanner/checker/updater/security/notifier registration (opt-in)
├── RemoteManagement     - Inventory, remote scan/update/report fan-out
└── NotificationManager  - Toast/email/webhook/hook/plugin dispatch
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
