# Product Requirements Document (PRD)
## System Update CLI

**Document Version:** 8.4.0
**Last Updated:** May 9, 2026
**Author:** Kelevra Mad
**Based On:** `src/system_update/` package (v8.4.0)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Product Overview](#2-product-overview)
3. [Goals and Objectives](#3-goals-and-objectives)
4. [Target Users](#4-target-users)
5. [Features and Requirements](#5-features-and-requirements)
6. [Technical Architecture](#6-technical-architecture)
7. [User Interface](#7-user-interface)
8. [Data Model](#8-data-model)
9. [Security Considerations](#9-security-considerations)
10. [Performance Requirements](#10-performance-requirements)
11. [Configuration](#11-configuration)
12. [Command-Line Interface](#12-command-line-interface)
13. [Use Cases](#13-use-cases)
14. [Error Handling](#14-error-handling)
15. [Logging and Monitoring](#15-logging-and-monitoring)
16. [Future Enhancements](#16-future-enhancements)

---

## 1. Executive Summary

**System Update Python CLI** is a comprehensive command-line tool designed to scan, discover, and update software packages across multiple package managers and system sources on Windows. It provides a unified interface for managing updates from Winget, Chocolatey, NPM, PNPM, Bun, Yarn, PIP, Rust, Scoop, dotnet global tools, system PATH tools, Windows Registry installations, AppX/MSIX packages, drivers, services, PowerShell modules, VS Code extensions, and plugin-defined sources.

The tool features parallel scanning, security vulnerability detection, intelligent caching, flexible export options, detailed logging, debug mode, and a polished terminal UI with real-time progress indicators.

---

## 2. Product Overview

### 2.1 Problem Statement

Developers and system administrators often need to manage software updates across multiple package managers:
- Windows: Winget, Chocolatey, Scoop, Registry, AppX/MSIX, drivers, services, PowerShell modules, VS Code extensions
- JavaScript: NPM, PNPM, Bun, Yarn
- Python: PIP
- System tools: PATH-based installations
- Windows applications: Registry-installed software

Manually checking each source is time-consuming and error-prone. There is no unified solution that provides:
- Cross-platform package discovery
- Security vulnerability scanning
- Batch update capabilities
- Exportable reports

### 2.2 Solution

A single CLI tool that:
1. Scans all configured package sources in parallel
2. Identifies available updates
3. Checks for security vulnerabilities
4. Executes updates with user confirmation
5. Exports results for reporting

### 2.3 Key Differentiators

- **Multi-source support**: 18+ built-in package/system sources plus plugin-defined sources
- **Python package implementation**: Modular `src/system_update/` package with `python -m system_update` and `system-update` entry points
- **Security-first**: Built-in vulnerability scanning through npm audit, pip/pip-audit, PyPI JSON, OSV, GitHub Advisory, and local advisories
- **Performance**: Parallel scanning with configurable timeouts
- **Developer experience**: Rich terminal UI with colors, emojis, and progress bars
- **Flexibility**: Extensive CLI options for targeted operations
- **Observability**: Optional logging with `--log` and debug mode with `--debug`

### 2.4 Implementation

The tool ships as a modular Python package (since v5.3.0):

| Implementation | Entry | Requirements | Dependencies |
|--------------|-------|-------------|--------------|
| Python | `python -m system_update` (package at `src/system_update/`) | Python 3.8+ | `rich`, `typer` |

All features and CLI options are implemented in the Python version. The legacy monolithic `system_update.py` was removed in v5.3.0; public API names remain importable from `system_update`.

---

## 3. Goals and Objectives

### 3.1 Primary Goals

| Goal | Description | Success Metric |
|------|-------------|----------------|
| Unified Discovery | Scan all package sources in a single command | Support 9+ sources |
| Accurate Detection | Correctly identify outdated packages | >95% accuracy |
| Security Awareness | Surface vulnerabilities proactively | CVE integration |
| Performance | Complete scans in under 60 seconds | Configurable timeout |
| Usability | Intuitive CLI with helpful output | Minimal learning curve |

### 3.2 Non-Goals

- GUI interface (CLI-only)
- Automatic background updates (requires user confirmation)
- Cross-platform package installation (update-only tool)
- Package manager replacement (orchestration layer)

---

## 4. Target Users

### 4.1 Primary Users

| Persona | Description | Use Case |
|---------|-------------|----------|
| **Developer** | Software engineers managing dev tools | Keep toolchain current |
| **DevOps Engineer** | CI/CD pipeline maintainers | Ensure build environments are updated |
| **System Administrator** | IT operations staff | Batch update multiple machines |
| **Security-Conscious User** | Privacy/security focused | Monitor vulnerabilities |

### 4.2 User Environment

- **Platforms**: Windows (primary), macOS, Linux
- **Runtime**: Python 3.8+
- **Terminal**: TTY-capable (full UI) or pipe-friendly (CI/CD)

---

## 5. Features and Requirements

### 5.1 Package Discovery

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| F-01 | Scan Winget packages | P0 | Implemented |
| F-02 | Scan Chocolatey packages | P0 | Implemented |
| F-03 | Scan NPM global packages | P0 | Implemented |
| F-04 | Scan PNPM global packages | P0 | Implemented |
| F-05 | Scan Bun global packages | P1 | Implemented |
| F-06 | Scan Yarn global packages | P1 | Implemented |
| F-07 | Scan PIP packages | P0 | Implemented |
| F-08 | Scan PATH tools (node, python, git, etc.) | P1 | Implemented |
| F-09 | Scan Windows Registry applications | P1 | Implemented |
| F-10 | Deduplicate results across sources | P0 | Implemented |
| F-11 | Scan Rust packages (cargo install) | P1 | Implemented |
| F-11a | Scan .NET Global Tools (dotnet tool list -g) | P1 | Implemented |
| F-11b | Scan Scoop packages | P1 | Implemented |
| F-11c | Scan AppX/Windows Store apps | P1 | Implemented |
| F-11d | Scan MSIX packages | P1 | Implemented |
| F-11e | Scan Windows drivers | P2 | Implemented |
| F-11f | Scan Windows services and executable versions | P2 | Implemented |
| F-11g | Scan PowerShell modules | P2 | Implemented |
| F-11h | Scan VS Code extensions | P2 | Implemented |
| F-11i | Scan plugin-defined package sources | P3 | Implemented |

### 5.2 Update Detection

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| F-12 | Check Winget for available upgrades | P0 | Implemented |
| F-13 | Check Chocolatey for outdated packages | P0 | Implemented |
| F-14 | Check NPM for outdated packages | P0 | Implemented |
| F-15 | Check PNPM for outdated packages | P0 | Implemented |
| F-16 | Check Bun for latest versions | P1 | Implemented |
| F-17 | Check Yarn for latest versions | P1 | Implemented |
| F-18 | Check PIP for outdated packages | P0 | Implemented |
| F-19 | Check PATH tools via GitHub API / commands | P1 | Implemented |
| F-20 | Cross-reference Registry with Winget | P1 | Implemented |
| F-21 | Check Rust for updates (cargo install-update) | P1 | Implemented |
| F-21a | Check .NET Global Tools for updates (dotnet tool list -g --outdated) | P1 | Implemented |
| F-21b | Check AppX/MSIX updates through Winget Store/upgrade data | P1 | Implemented |
| F-21c | Reconcile driver and service inventory status | P2 | Implemented |
| F-21d | Check PowerShell module updates | P2 | Implemented |
| F-21e | Check VS Code extension updates through the shared network client | P2 | Implemented |
| F-21f | Check plugin-defined package sources | P3 | Implemented |
| F-21g | Reuse one parsed `winget upgrade` table per update-check run | P3 | Implemented |

### 5.3 Security Features

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| F-22 | Scan NPM packages for vulnerabilities | P0 | Implemented |
| F-23 | Scan PIP packages for vulnerabilities | P1 | Implemented |
| F-24 | Filter by severity threshold | P1 | Implemented |
| F-25 | Display CVE identifiers | P1 | Implemented |
| F-26 | Mark vulnerable packages in UI | P0 | Implemented |
| F-26a | OSV API vulnerability scanning (npm, PyPI, crates.io, etc.) | P1 | Implemented |
| F-26b | PyPI JSON API vulnerability data | P1 | Implemented |

### 5.4 Update Execution

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| F-27 | Update all packages | P0 | Implemented |
| F-28 | Update single package by name | P0 | Implemented |
| F-29 | Update by source filter | P1 | Implemented |
| F-30 | Specify target version | P1 | Implemented |
| F-31 | Dry-run mode | P0 | Implemented |
| F-32 | Confirmation prompts | P0 | Implemented |
| F-33 | Skip prompts with --yes flag | P1 | Implemented |
| F-34 | Update Rust packages (cargo install-update) | P1 | Implemented |
| F-34a | Update .NET Global Tools (dotnet tool update -g) | P1 | Implemented |
| F-34b | Update PowerShell modules | P2 | Implemented |
| F-34c | Update VS Code extensions | P2 | Implemented |
| F-34d | Execute plugin-defined package updaters | P3 | Implemented |

### 5.5 Caching System

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| F-35 | Cache scan results | P1 | Implemented |
| F-36 | Configurable cache duration | P1 | Implemented |
| F-37 | Load from cache on subsequent runs | P1 | Implemented |
| F-38 | Clear cache manually | P1 | Implemented |
| F-39 | Bypass cache with --no-cache | P1 | Implemented |

### 5.6 Export Features

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| F-40 | Export to JSON format | P1 | Implemented |
| F-41 | Export to CSV format | P1 | Implemented |
| F-42 | Custom output path | P1 | Implemented |
| F-43 | Include scan metadata | P2 | Implemented |

### 5.7 User Interface

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| F-44 | Color-coded terminal output | P0 | Implemented |
| F-45 | Emoji indicators | P2 | Implemented |
| F-46 | Progress bars for scanning | P1 | Implemented |
| F-47 | Status badges per package | P1 | Implemented |
| F-48 | Source badges with colors | P2 | Implemented |
| F-49 | Summary statistics | P0 | Implemented |
| F-50 | Security vulnerability table | P0 | Implemented |
| F-51 | Graceful degradation for non-TTY | P1 | Implemented |

### 5.8 Logging and Debugging

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| F-52 | Optional logging to file with --log | P1 | Implemented |
| F-53 | Debug mode to show executed commands | P2 | Implemented |
| F-54 | Log file with timestamps | P1 | Implemented |
| F-55 | Debug output includes full command details | P2 | Implemented |

---

## 6. Technical Architecture

### 6.1 System Components

```
┌─────────────────────────────────────────────────────────────┐
│                     CLI Entry Point                         │
│        (python -m system_update / system-update)            │
├─────────────────────────────────────────────────────────────┤
│  Typer CLI  │ Config Manager │ Cache/Network │ Plugins     │
├─────────────────────────────────────────────────────────────┤
│        SystemUpdateApp Orchestrator + Rich UI               │
│  ┌─────────┬─────────┬─────────┬─────────┬─────────────┐   │
│  │ Winget  │ Choco   │  NPM    │  PNPM   │  Bun/Yarn   │   │
│  ├─────────┼─────────┼─────────┼─────────┼─────────────┤   │
│  │  PIP    │  PATH   │Registry │  Rust   │   Scoop     │   │
│  ├─────────┼─────────┼─────────┼─────────┼─────────────┤   │
│  │ dotnet  │ AppX    │ MSIX    │Drivers  │ Services    │   │
│  ├─────────┼─────────┼─────────┼─────────┼─────────────┤   │
│  │ PSMods  │ VS Ext  │ Plugins │  OSV    │  Security   │   │
│  └─────────┴─────────┴─────────┴─────────┴─────────────┘   │
├─────────────────────────────────────────────────────────────┤
│ Update Checkers │ Executors │ Remote │ Snapshots/Rollback  │
├─────────────────────────────────────────────────────────────┤
│                    Output Layer                             │
│         (UI rendering, logging, debug mode, file export)    │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 Module Dependencies

| Module | Purpose |
|--------|---------|
| `pathlib`, `json`, `sqlite3` | File I/O for cache, config, history, snapshots, and exports |
| `subprocess` | Execute package manager, PowerShell, Winget, and WinRS commands |
| `urllib.request` | Shared JSON API calls through `network.py` |
| `concurrent.futures` | Parallel scanner, checker, and remote fan-out workers |
| `rich`, `typer` | Terminal UI and CLI parsing |

### 6.3 Data Flow

1. **Initialization**: Parse args → Load config → Ensure data directory → Initialize logging
2. **Cache Check**: Load cached results if valid
3. **Scan Phase**: Parallel source scanning → Deduplication
4. **Update Check**: Query each source for available updates; Winget-backed sources reuse one parsed `winget upgrade` table per run
5. **Security Check**: Run vulnerability scans (npm audit, pip/pip-audit, OSV, PyPI, GitHub, local advisories)
6. **Display**: Render tables, summaries, security alerts
7. **Execution**: Apply updates (if requested) with confirmation
8. **Export**: Write results to file (if requested)
9. **Cache**: Save results for next run
10. **Logging**: All operations logged to file (if --log enabled)

---

## 7. User Interface

### 7.1 Visual Design

**Color Scheme:**
- Green (`#00ff00`): Success, up-to-date
- Yellow (`#ffff00`): Updates available, warnings
- Red (`#ff0000`): Errors, vulnerabilities
- Cyan (`#00ffff`): Headers, borders
- Magenta (`#ff00ff`): Security updates, Rust, PNPM sources
- Blue (`#0000ff`): Winget, Yarn sources
- Orange (`#ffa500`): Bun source
- White (`#ffffff`): Yarn source
- Gray: Dimmed text, unknown status, Registry source

**Typography:**
- Bold: Package names, counts, important info
- Dim: Secondary information
- Monospace: Commands, paths

### 7.2 Screen Layouts

#### 7.2.1 Header Card
```
┌──────────────────────────────────────────────────────────────┐
│ 🚀 System Update Node CLI v1.0.1                             │
│ ⚙️ Data dir: C:\Users\user\.system_update                    │
└──────────────────────────────────────────────────────────────┘
```

#### 7.2.2 Package Table
```
Package                       Source        Current             Latest              Status
────────────────────────────────────────────────────────────────────────────────────────────────────
git                           chocolatey    2.39.0              2.44.0              ⬆️ update
node                          path          v20.11.0            v22.0.0             ⬆️ update
lodash                        npm           4.17.21             -                   ✅ up-to-date
requests                      pip           2.31.0              -                   🔒 security
```

#### 7.2.3 Progress Indicator
```
🔎 Scanning ████████████████████░░░░░░ 72% (5/7) ⏱️ 12.3s
```

#### 7.2.4 Security Alert
```
┌─────────────────────────────────────────────────────────────┐
│ 🔥 Security Vulnerabilities Detected                        │
├─────────────────────────────────────────────────────────────┤
│ Package             Severity    CVE                 Description │
├─────────────────────────────────────────────────────────────┤
│ requests            HIGH        CVE-2024-XXXX       Security vuln │
└─────────────────────────────────────────────────────────────┘
```

#### 7.2.5 Summary and Output
```
📊 Summary
📦 total apps     456
⬆️ updates        78
⏱️ scan duration  34.81s
⚙️ sources        chocolatey:21, npm:16, path:12, pip:58, registry:104, rust:1, winget:243, yarn:1

[Package table...]

💾 Showing: updates only

🎯 Found 78 available updates
```

With `--show-all`:
```
💾 Showing: all packages
```

### 7.4 Source Badges

Each source is displayed with a unique color badge:

| Source | Color |
|--------|-------|
| Winget | Blue |
| Chocolatey | Yellow |
| NPM | Red |
| PNPM | Magenta |
| Bun | Orange |
| Yarn | White |
| PIP | Cyan |
| Rust | Magenta |
| PATH | Green |
| Registry | Gray |
| Scoop | Gold |
| dotnet | Gold |

### 7.5 Accessibility

- **Non-TTY mode**: Falls back to plain text output
- **NO_COLOR support**: Respects `NO_COLOR=1` environment variable
- **Screen readers**: Structured output with clear labels

---

## 8. Data Model

### 8.1 Package Object

```javascript
{
  name: string,           // Package/display name
  source: string,         // Source identifier (winget, npm, etc.)
  version: string,        // Currently installed version
  latestVersion: string,  // Latest available version (empty if unknown)
  appId: string|null,     // Source-specific identifier
  status: string,         // Status enum value
  scanTime: string        // ISO 8601 timestamp
}
```

### 8.2 Status Enum

| Value | Description | Display |
|-------|-------------|---------|
| `up_to_date` | Package is current | ✅ up-to-date (green) |
| `update_available` | Newer version exists | ⬆️ update (yellow) |
| `security_update_available` | Security patch available | 🔒 security update (magenta) |
| `vulnerable` | Known vulnerability | 🔥 vulnerable (red) |
| `unknown` | Status could not be determined | ❔ unknown (gray) |
| `error` | Scan/update failed | ❌ error (red) |

### 8.3 Cache Structure

```json
{
  "timestamp": "2026-03-09T10:30:00.000Z",
  "version": "1.0.1",
  "totalApps": 42,
  "apps": [ /* Package objects */ ]
}
```

### 8.4 Vulnerability Object

```javascript
{
  packageName: string,   // Affected package
  severity: string,      // critical|high|medium|low
  cve: string,           // CVE identifier or N/A
  description: string,   // Vulnerability description
  appInfo: object        // Reference to Package object
}
```

### 8.5 Configuration Schema

```javascript
{
  cache: {
    enabled: boolean,
    durationHours: number
  },
  performance: {
    timeoutSeconds: number,
    maxWorkers: number
  },
  sources: {
    winget: boolean,
    chocolatey: boolean,
    npm: boolean,
    pnpm: boolean,
    bun: boolean,
    yarn: boolean,
    pip: boolean,
    path: boolean,
    registry: boolean,
    rust: boolean,
    scoop: boolean,
    dotnet: boolean,
    appx: boolean,
    msix: boolean,
    drivers: boolean,
    services: boolean,
    psmodules: boolean,
    vsextensions: boolean
  },
  security: {
    enabled: boolean,
    autoCheck: boolean,
    severityThreshold: string
  },
  ui: {
    compact: boolean
  }
}
```

---

## 9. Security Considerations

### 9.1 Vulnerability Scanning

| Source | Method | Data Source |
|--------|--------|-------------|
| NPM | `npm audit --json` | NPM Registry |
| PIP | `pip-audit` | PyPI Advisory DB |
| PyPI JSON | `https://pypi.org/pypi/{name}/{version}/json` | PyPI Vulnerability Field |
| OSV | `https://api.osv.dev/v1/query` | Google OSV Database |

### 9.2 Security Thresholds

Users can configure minimum severity to report:
- `low`: Report all vulnerabilities
- `medium`: Report medium, high, critical (default)
- `high`: Report high, critical only
- `critical`: Report critical only

### 9.3 Safe Operations

- **No automatic updates**: User confirmation required
- **Dry-run support**: Preview changes before execution
- **Command validation**: Whitelist of allowed commands
- **Timeout protection**: Prevents hanging processes

### 9.4 Data Privacy

- No telemetry or analytics
- Cache stored locally in user directory
- No external API calls except for version checks
- Logs contain only operational data

### 9.5 Attack Surface

| Vector | Mitigation |
|--------|------------|
| Command injection | Whitelist commands, no shell interpolation |
| Timeout DoS | Configurable per-command timeouts |
| Malicious packages | User confirmation before install |
| Cache poisoning | Version validation on load |

---

## 10. Performance Requirements

### 10.1 Timing Targets

| Operation | Target | Configurable |
|-----------|--------|--------------|
| Full scan (9 sources) | <45 seconds | Yes (timeoutSeconds) |
| Individual source scan | <10 seconds | Inherited |
| Update check | <30 seconds | Inherited |
| Security scan | <15 seconds | Inherited |
| Cache load | <100ms | N/A |
| Cache save | <500ms | N/A |

### 10.2 Parallelization

- All source scanners run in parallel via `Promise.all()`
- Update checks run in parallel per source
- Security checks run sequentially (NPM, then PIP)

### 10.3 Resource Usage

| Metric | Limit |
|--------|-------|
| Memory footprint | <100MB typical |
| Concurrent processes | 9 (one per source) |
| Network requests | As needed per package |
| Disk usage (cache) | <10MB typical |

### 10.4 Optimization Strategies

1. **Caching**: Skip scan if cache is valid (default 2 hours)
2. **Timeouts**: Kill long-running commands
3. **Early exit**: Skip disabled sources
4. **Filtering**: `--source` limits sources scanned

---

## 11. Configuration

### 11.1 Default Configuration

```javascript
const DEFAULT_CONFIG = {
  cache: {
    enabled: true,
    durationHours: 2,
  },
  performance: {
    timeoutSeconds: 45,
    maxWorkers: 6,
  },
  sources: {
    winget: true,
    chocolatey: true,
    npm: true,
    pnpm: true,
    bun: true,
    yarn: true,
    pip: true,
    path: true,
    registry: true,
    rust: true,
    scoop: true,
    dotnet: true,
  },
  security: {
    enabled: true,
    autoCheck: true,
    severityThreshold: 'medium',
  },
  ui: {
    compact: false,
  },
};
```

### 11.2 Configuration Storage

| Platform | Path |
|----------|------|
| Windows | `%USERPROFILE%\.system_update\config.json` |
| macOS/Linux | `~/.system_update/config.json` |
| Fallback | `./.system_update/` (project local) |

### 11.3 Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `SYSTEM_UPDATE_HOME` | Override data directory | `~/.system_update` |
| `NO_COLOR` | Disable colors | `false` |

---

## 12. Command-Line Interface

### 12.1 Command Syntax

```bash
python -m system_update [options]
```

> Prior to v5.3.0 the entry point was `python -m system_update [options]` (flat-file layout). The CLI flags are unchanged; only the invocation differs.

### 12.2 Options Reference

| Option | Alias | Type | Description |
|--------|-------|------|-------------|
| `--update-all` | - | Flag | Update every package with updates |
| `--update-source <source>` | - | String | Update all packages from one source |
| `--update-package <name>` | - | String | Update one package by name |
| `--version <ver>` | - | String | Target version (with --update-package) |
| `--source <source>` | - | String | Filter sources (comma-separated for multiple) |
| `--dry-run` | - | Flag | Print planned updates without executing |
| `--no-cache` | - | Flag | Force fresh scan (skip cache) |
| `--clear-cache` | - | Flag | Remove cache file and exit |
| `--export <format>` | - | String | Export scan results (json|csv) |
| `--output <file>` | - | String | Output path for export |
| `--log` | - | Flag | Enable logging to file |
| `--debug` | - | Flag | Show all executed commands on screen and in log |
| `--yes` | `-y` | Flag | Skip confirmation prompts |
| `--help` | `-h` | Flag | Show help message |
| `--show-all` | - | Flag | Show all packages (including up-to-date) |

### 12.3 Valid Source Values

- `winget`
- `chocolatey`
- `npm`
- `pnpm`
- `bun`
- `yarn`
- `pip`
- `path`
- `registry`
- `rust`
- `scoop`
- `dotnet`
- `appx`
- `msix`
- `drivers`
- `services`
- `psmodules`
- `vsextensions`

### 12.4 Example Commands

```bash
# Basic scan
python -m system_update

# Update everything (with confirmation)
python -m system_update --update-all

# Update everything (no prompts)
python -m system_update --update-all --yes

# Update all from specific source
python -m system_update --update-source rust --yes

# Update all Winget packages (dry-run)
python -m system_update --update-source winget --dry-run

# Update specific package
python -m system_update --update-package git --source chocolatey

# Update all Rust packages only
python -m system_update --source rust --yes

# Update all Winget packages only
python -m system_update --source winget --dry-run

# Export results
python -m system_update --export json --output report.json
python -m system_update --export csv --output updates.csv

# Scan specific sources only
python -m system_update --source winget,npm,pip

# Force fresh scan
python -m system_update --no-cache

# Clear cache
python -m system_update --clear-cache

# Enable logging for debugging
python -m system_update --log

# Show all executed commands
python -m system_update --debug

# Show all packages (including up-to-date)
python -m system_update --show-all
```

---

## 13. Use Cases

### 13.1 Daily Developer Workflow

**Actor:** Software Developer  
**Goal:** Keep development tools updated

**Steps:**
1. Run `python -m system_update` (uses cache if valid)
2. Review displayed package table
3. Note packages with ⚠️ update badge
4. Run `python -m system_update --update-all --yes`
5. Verify completion message

**Expected Output:** Summary of updated packages

### 13.2 Security Audit

**Actor:** Security Engineer  
**Goal:** Identify vulnerable packages

**Steps:**
1. Run `python -m system_update --no-cache`
2. Review security vulnerability table
3. Note CVEs and severity levels
4. Export report: `--export json --output security-report.json`
5. Prioritize remediation

**Expected Output:** List of vulnerabilities with CVEs

### 13.3 Targeted Update

**Actor:** Developer  
**Goal:** Update specific package to specific version

**Steps:**
1. Run `python -m system_update --update-package node --source path --version 22.0.0`
2. Confirm update when prompted
3. Verify success message

**Expected Output:** Confirmation of successful update

### 13.4 CI/CD Integration

**Actor:** DevOps Engineer  
**Goal:** Check for updates in pipeline

**Steps:**
1. Run `python -m system_update --export json --output $BUILD_DIR/updates.json`
2. Parse JSON in subsequent pipeline step
3. Fail build if critical vulnerabilities found

**Expected Output:** Machine-readable report

### 13.5 Source-Specific Scan

**Actor:** Administrator  
**Goal:** Check only Winget-managed software

**Steps:**
1. Run `python -m system_update --source winget`
2. Review Winget-specific results

**Expected Output:** Filtered package list

---

## 14. Error Handling

### 14.1 Error Categories

| Category | Examples | Handling |
|----------|----------|----------|
| **Command Not Found** | winget, choco, npm not installed | Skip source, log warning |
| **Timeout** | Command exceeds timeout | Kill process, mark as error |
| **Parse Error** | Invalid JSON from tool | Log error, skip affected packages |
| **Network Error** | GitHub API unavailable | Graceful degradation |
| **Permission Error** | Cannot write to data dir | Fallback to local directory |
| **Invalid Arguments** | Unknown flag | Show help, exit code 1 |

### 14.2 Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (no updates or updates applied) |
| 1 | Fatal error |
| 2 | Package not found / ambiguous selection |

### 14.3 Error Messages

Errors are displayed with appropriate styling:
- ❌ prefix for errors
- Red color for visibility
- Clear description of what went wrong
- Suggested remediation when applicable

---

## 15. Logging and Monitoring

### 15.1 Log File

**Location:** `<data_dir>/system.log`

**Format:** ISO 8601 timestamp + message

**Example:**
```
2026-03-09T10:30:00.000Z parse npm list failed: SyntaxError: Unexpected token
2026-03-09T10:30:05.000Z update failed: git (chocolatey) stderr=error message
2026-03-09T10:30:10.000Z [DEBUG] Executing: winget upgrade --id Git.Git
```

### 15.2 Logging Modes

| Mode | Flag | Description |
|------|------|-------------|
| Disabled | (default) | No logging to file |
| Enabled | `--log` | All operations logged to file |
| Debug | `--debug` | All executed commands shown on screen AND logged |

### 15.3 Logged Events

- Configuration load failures
- Command parse errors
- Update failures (command + stderr)
- Fatal errors (with stack trace)
- All executed commands (in debug mode)
- Session start/end with duration

### 15.4 Resilience

- Logging failures do not interrupt execution
- Errors are caught and logged, not thrown
- CLI remains functional even if logging fails

---

## 16. Future Enhancements

### 16.1 Remaining Planned Features

| ID | Feature | Priority | Description |
|----|---------|----------|-------------|
| E-06 | Homebrew support | P2 | macOS package manager |
| E-07 | APT/YUM support | P2 | Linux package managers |
| E-08 | Update groups | P3 | Named package collections |
| E-09 | Pre/post update hooks | P3 | Custom scripts around package update execution |
| E-10 | Scan checkpoint persistence | P3 | Resume interrupted scans across process restarts |

Configuration files, scheduled tasks, rollback, interactive selection, remote management, plugin architecture, smart caching, network optimization, and Windows-specific source coverage are implemented.

### 16.2 Known Limitations

1. **Windows-centric**: Registry, AppX/MSIX, driver, service, PowerShell module, VS Code extension, and WinRS remote features are Windows-focused.
2. **Global packages only**: Does not scan project-local dependency trees as package sources.
3. **No dependency resolver**: Updates are orchestrated per package/source; dependency graph output is advisory.
4. **Authentication is source-specific**: Private registries/remotes depend on the underlying package manager, WinRS, or user-provided environment/config.

### 16.3 Technical Debt

- Broaden non-Windows package source support.
- Add stronger end-to-end tests for real remote hosts and package managers where CI environments permit it.
- Expand plugin examples and compatibility guidance for third-party extensions.

---

## Appendix A: Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | - | Initial release |
| 1.0.1 | March 2026 | Added Rust source support, --log and --debug flags, enhanced PATH version detection, Registry updates via winget, updated source badge colors, **--show-all flag** (show all packages including up-to-date), improved output format with "💾 Showing" line after table and "🎯 Found" message |
| 2.1.0 | April 2026 | Added .NET Global Tools support (dotnet tool list -g), dotnet update checking (dotnet tool list -g --outdated), 12 sources now supported |
| 2.2.0 | April 2026 | Added Scoop package manager support, AppX scanning (Windows Store apps), MSIX scanning |
| 2.3.0 | April 2026 | Added OSV API integration (Google's vulnerability database for npm, PyPI, crates.io, RubyGems, Go, CocoaPods, Hex) |
| 2.4.0 | April 2026 | Added PyPI JSON API vulnerability checking, now 3 implementations (Node.js, Python, PowerShell) |
| 2.5.0 | April 2026 | Enhanced npm vulnerability scanning (full audit JSON parse), added advisory URLs and fix availability info |
| 2.6.0 | April 2026 | Added GitHub Advisory Database API integration, local advisory import support (~/.system_update/advisories.json) |
| 2.7.0 | April 2026 | Implemented **Security Reporting Features**: CVSS Score Display, persistent Vulnerability History tracking, Security Summary Stats with severity counts, and enhanced CVE details |
| 2.8.0 | April 2026 | Simplified to **Python-only** implementation - removed Node.js and PowerShell scripts |
| 3.1.0 | April 2026 | Interactive TUI, fuzzy search, multi-select, --source filter rename |
| 3.2.0 | April 2026 | Progress enhancements (ETA, speed), detailed scanning status |
| 3.3.0 | April 2026 | Better Error Handling (classification, suggestions), AppX/MSIX fixes |
| 3.4.0 | April 2026 | Notification System (Toast, Email, Webhook, Custom scripts) |
| 3.5.0 | April 2026 | UI Improvements (Themes, Formats, Icons), Column layout adjustments |
| 4.1.0 | April 2026 | Configuration System (JSON/YAML configs, validation, migration, smart filtering) |
| 4.2.0 | April 2026 | Advanced Environment Variable System (Dynamic double-underscore nested overrides, auto type-casting, explicit excludes) |
| 5.1.0 | April 2026 | Historical Tracking (SQLite scan history, trends, stale-package detection, report generation) |
| 5.2.0 | April 2026 | Export Formats (HTML, XML, Markdown, diff in addition to JSON/CSV) |
| 5.3.0 | April 2026 | Modular refactor: `src/system_update/` package, Typer CLI, `python -m system_update` entry; monolithic `system_update.py` removed |
| 5.3.1 | April 2026 | Cache partial-scan + merge, unified summary block, per-CVE security table with cross-source dedup, invalid `--source` handling. Cache partial-scan + merge for missing sources; unified Summary (security stats folded in); per-CVE security table with Fix column and cross-source dedupe by `package|cve`; invalid-source validation|
| 5.4.0 | April 2026 | Report Templates (5.3): custom HTML templates, logo embedding, full report branding (`--html-template`, `--html-logo`, `--html-title`, `--html-company`) |
| 5.5.0 | April 2026 | History/report/interactive ported (`--history`, `--history-package`, `--history-trends`, `--history-stale`, `--report text\|json\|html`, interactive picker); friendly choice errors; beautified `--help` with emoji panels |
| 5.6.0 | April 2026 | Data Sharing (5.4): `--import`, `--merge`, `--cloud-sync` (file + http backends); detailed sub-help system (`--explain <topic>`, `--<flag> help`) with 13 topics. Report Templates (5.3): custom HTML template path, base64-embedded logo, branding block (title, subtitle, company, colors, footer); new CLI flags `--html-template`, `--html-logo`, `--html-title`, `--html-company`; `report_templates` module |
| 6.1.0 | April 2026 | Scheduled Updates (6.1): `--schedule create\|delete\|list\|status\|run\|eval` wraps Windows Task Scheduler; daily/weekly/hourly/monthly/onstart/onlogon recurrences; conditional actions engine (`any_critical_cves`, `n_updates_gte:N`, `security_updates_only` → `notify`/`log`/`auto_update`); `--schedule list` table now shows Last Run + Last Result columns |
| 6.2.0 | April 2026 | Rollback Support (6.2): version snapshots auto-recorded for every batch update (`snapshots.py`, SQLite); `--rollback <id>\|last` re-installs `version_before` per package; `--snapshot list\|show\|delete`. Cross-interpreter pip safety: scanner records originating interpreter, update/rollback target it; `pip-audit` filtered against installed version. Context-aware pip default (venv-only / system-only); cache pip-context invalidation on env switch; `VIRTUAL_ENV` scrub for global Python under `uv run`. CVE table surfaced before update prompts; `--update-source` no longer auto-`--yes`. New `--exclude`, `--save-config`, profile import/export wired through |
| 6.2.1 | May 2026 | Structured `errors.log` format (timestamp, level, logger, file:line, function, pid/tid, traceback). `--format compact` redesigned as a 3-column dense view with status markers (✓ up-to-date / ↑ update / 🔥 vulnerable / ✗ error) and ellipsis truncation — no more mid-line wrap. `--format verbose` Source column widened so `🍫 chocolatey` and `🖥️ registry` fit on one line |
| 6.2.2 | May 2026 | Unified Rich progress helper with per-task durations for scan/check/security phases; grouped banner and summary panels with aligned file inventory, profile chips, source chips, and security breakdowns; failed subprocess stdout/stderr captured in `system.log` while CLI output and `errors.log` remain concise; banner version display updated to current release |
| 6.3.0 | May 2026 | Dependency Graph (6.3): `--dependency-graph dot\|conflicts\|minimal\|help`; Graphviz DOT export via `--graph-output`; best-effort npm/pnpm/pip dependency edges; conflict detection for multiple installed versions; minimal direct update set suggestions that preserve vulnerable packages |
| 6.4.0 | May 2026 | Remote Management (6.4): WinRM execution via Windows-native `winrs` (6.4.1), `~/.system_update/inventory.json` host inventory with groups (6.4.2), consolidated multi-host JSON reports with cross-host version-drift detection (6.4.3), parallel mass update fan-out (6.4.4); new `--remote list\|add\|remove\|scan\|update\|report\|help` plus `--remote-host\|-group\|-address\|-user\|-groups\|-args\|-output\|-timeout\|-verbose\|-debug` flags; new `🌐 Remote Management` help panel and `remote` sub-help topic |
| 6.5.0 | May 2026 | Plugin Architecture (6.5): local Python plugins loaded from `~/.system_update/plugins` or configured `plugins.paths`; custom package scanners can add new `--source` providers (6.5.1); custom notifiers receive update and scan-complete events (6.5.2); public plugin API exports `PluginRegistry`, `PluginContext`, `PluginScanner`, `PluginChecker`, `PluginUpdater`, `PluginNotifier`, and `load_plugins` (6.5.3); new `--list-plugins` command lists loaded scanners/checkers/updaters/notifiers and load errors |
| 7.1.0 | May 2026 | Smart Caching (7.1): per-source freshness metadata enables incremental rescans for stale/missing sources while fresh sources remain cached (7.1.1); cache writes include delta metadata for added/updated/removed packages (7.1.2); bounded hot-package LRU cache tracks recently loaded packages (7.1.3); optional prefetch can refresh near-expiry caches in the background (7.1.4). Source emoji chips now render by default in summaries, package tables, scan/update progress, and partial-cache messages; `--icons` was removed because icons are always shown |
| 7.2.0 | May 2026 | Parallel Processing (7.2): per-source scanner and update-checker work now use bounded worker pools (7.2.1); package deduplication uses a shared helper across scan paths (7.2.2); update-check failures are isolated per source so healthy sources continue and report results (7.2.3) |
| 7.3.0 | May 2026 | Network Optimization (7.3): OSV vulnerability checks use batched API requests (7.3.1); shared JSON API calls honor configurable per-host rate limits (7.3.2); API responses are cached in `api_cache.json` with configurable TTL (7.3.3). Summary panel source rows wrap safely inside borders on emoji-rich terminals |
| 7.4.0 | May 2026 | Size Reduction (7.4): old source metadata, stale source package rows, and expired deltas are pruned automatically (7.4.2); cache field storage is configurable and empty optional fields are omitted by default (7.4.3). Cache files remain readable plain JSON because they are small |
| 8.1.0 | May 2026 | Windows-Specific Enhancements (8.1): AppX Store packages can be checked for `msstore` updates through winget (8.1.1-8.1.2); Windows drivers are inventoried via `pnputil` (8.1.3); service executable versions are discovered via CIM (8.1.4); PowerShell modules and VS Code extensions now scan and check available versions (8.1.5-8.1.6). Cache files are readable plain JSON |
| 8.1.1 | May 2026 | Cache readability patch: removed cache compression code and the `compression_enabled` setting; `cache.json` is always written as plain, indented JSON |
| 8.1.2 | May 2026 | Security hardening patch: custom notification script hooks execute without `shell=True`; PowerShell hooks are invoked explicitly with `powershell -File` on Windows |
| 8.1.3 | May 2026 | Windows source polish patch: MSIX packages now have a real update checker; driver/service/PowerShell module versions are normalized before display; VS Code extensions use a distinct `🔌` source icon |
| 8.1.4 | May 2026 | Plugin lifecycle and network-consistency patch: plugin sources can register checkers and updaters so scan/check/update flows are fully pluggable; VS Code extension checks now use the shared network client |
| 8.1.5 | May 2026 | Windows parsing patch: service executable paths without quotes preserve spaces and arguments correctly; PowerShell JSON scanners tolerate warning text and `null` output |
| 8.1.6 | May 2026 | Winget optimization patch: Winget, Registry, AppX, and MSIX update checkers share one parsed `winget upgrade` table per update-check run |
| 8.2.0 | May 2026 | Hardening 1.1 — credentials kept off process argv: new optional `pywinrm` HTTPS transport (avoids `winrs -p:` argv leak) and webhook bearer token now sent via `urllib.request` headers instead of `curl` argv. CLI gains a unified `System Update` panel rendered both at runtime and on `--help`, showing version, runtime, profile, data-dir inventory, cache TTL, sources, security feeds, and repo URL |
| 8.4.0 | May 2026 | Hardening 1.3 — SSRF and URL validation: `network.fetch_json` now refuses non-HTTP(S) schemes (`file://`, `ftp://`, `data:`, `gopher://`) via a strict allowlist plus a custom `OpenerDirector` that registers only `HTTPHandler`/`HTTPSHandler` (defense-in-depth: even a 30x to `file://` cannot escape). Webhook delivery rejects URLs whose host (literal IP or DNS-resolved A/AAAA) falls in loopback / link-local / RFC1918 / multicast / reserved / unspecified ranges by default — including the cloud metadata endpoint `169.254.169.254`. New setting `notifications.allow_private_hosts=false` is the single opt-in for self-hosted ChatOps endpoints. Tooling: added Pyright (Pylance's CLI engine) with `pyrightconfig.json` and two taskipy tasks (`uv run task typecheck` / `uv run task typecheck-stats`) so contributors can scan the repo for type errors from the terminal |
| 8.3.0 | May 2026 | Hardening 1.2 — untrusted code execution: plugin loader is **opt-in by default** (was auto-load), refuses world-writable plugin dirs, supports an optional SHA-256 allowlist (`allowed.sha256`) plus `plugins.require_hash_allowlist`, adds `--no-plugins` kill switch, and renders a bold `PLUGIN LOAD` warning panel when a plugin loads. Replaces `iex (irm aka.ms/install-powershell.ps1)` with `winget install --id Microsoft.PowerShell` (hash-verified). Adds `_safe_argv_token` validator on cache-sourced strings (winget/chocolatey/appx + rollback) to prevent flag injection. Plugin API gains a fifth extension point — `register_security_checker` — which participates in the `🔒 Checking security vulnerabilities` stage as its own progress row. Plugin-load standardization: `_register_module` captures `PluginMetadata` with first-line docstring and capability set; `--list-plugins` redesigned as one row per plugin with capability icons and the docstring summary, with the per-extension breakdown moved behind `--list-plugins-detail`. Banner header now carries the version inline (`🚀 System Update · v8.3.0`) instead of a redundant first row |

## Appendix B: Glossary

| Term | Definition |
|------|------------|
| **Winget** | Windows Package Manager by Microsoft |
| **Chocolatey** | Package manager for Windows |
| **NPM** | Node Package Manager |
| **PNPM** | Performant NPM - disk-efficient package manager |
| **Bun** | JavaScript runtime and package manager |
| **Yarn** | Alternative JavaScript package manager |
| **PIP** | Python package installer |
| **Rust/Cargo** | Rust programming language package manager |
| **CVE** | Common Vulnerabilities and Exposures identifier |
| **TTY** | Teletypewriter - interactive terminal |

## Appendix C: References

- [Winget Documentation](https://docs.microsoft.com/windows/package-manager/)
- [Chocolatey Documentation](https://chocolatey.org/docs)
- [NPM Audit](https://docs.npmjs.com/auditing-package-dependencies-for-security-vulnerabilities)
- [PIP Vulnerability Checking](https://pip.pypa.io/en/stable/cli/pip_check/)
- [GitHub Releases API](https://docs.github.com/rest/releases/releases)
- [Cargo Documentation](https://doc.rust-lang.org/cargo/)
- [Cargo Update](https://github.com/nabijaczleweli/cargo-update)

---

*End of Document*
