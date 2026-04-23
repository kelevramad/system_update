# Product Requirements Document (PRD)
## System Update CLI

**Document Version:** 5.3.0
**Last Updated:** April 23, 2026
**Author:** Qwen Code
**Based On:** `src/system_update/` package (v5.3.0)

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

**System Update Python CLI** is a comprehensive command-line tool designed to scan, discover, and update software packages across multiple package managers and system sources on Windows. It provides a unified interface for managing updates from Winget, Chocolatey, NPM, PNPM, Bun, Yarn, PIP, Rust, system PATH tools, and Windows Registry installations.

The tool features parallel scanning, security vulnerability detection, intelligent caching, flexible export options, detailed logging, debug mode, and a polished terminal UI with real-time progress indicators.

---

## 2. Product Overview

### 2.1 Problem Statement

Developers and system administrators often need to manage software updates across multiple package managers:
- Windows: Winget, Chocolatey
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

- **Multi-source support**: 14+ different package sources including .NET and Windows Store apps
- **Multi-implementation**: Available in Node.js, Python, and PowerShell (zero-dependency)
- **Security-first**: Built-in vulnerability scanning for NPM, PIP, PyPI JSON, and OSV API
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
- **Runtime**: Node.js 16+
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
│                        (main.js)                            │
├─────────────────────────────────────────────────────────────┤
│  Argument Parser  │  Config Manager  │  Cache Manager      │
├─────────────────────────────────────────────────────────────┤
│                    Scanner Orchestrator                     │
│  ┌─────────┬─────────┬─────────┬─────────┬─────────────┐   │
│  │ Winget  │ Choco   │  NPM    │  PNPM   │  Bun/Yarn   │   │
│  ├─────────┼─────────┼─────────┼─────────┼─────────────┤   │
│  │  PIP    │  PATH   │Registry │  Rust   │   Scoop     │   │
│  ├─────────┼─────────┼─────────┼─────────┼─────────────┤   │
│  │  dotnet │ AppX   │ MSIX    │  OSV    │   Security  │   │
│  └─────────┴─────────┴─────────┴─────────┴─────────────┘   │
├─────────────────────────────────────────────────────────────┤
│                  Command Execution Layer                    │
│              (spawn, timeout handling, parsing)             │
├─────────────────────────────────────────────────────────────┤
│                    Output Layer                             │
│         (UI rendering, logging, debug mode, file export)    │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 Module Dependencies

| Module | Purpose | Node.js API |
|--------|---------|-------------|
| `fs/promises` | File I/O for cache, config, export | Async filesystem |
| `child_process` | Execute package manager commands | spawn |
| `https` | Fetch latest versions, vulnerability data | HTTPS client |
| `readline` | Interactive prompts | Terminal input |
| `path`, `os` | Cross-platform path handling | System utilities |

### 6.3 Data Flow

1. **Initialization**: Parse args → Load config → Ensure data directory → Initialize logging
2. **Cache Check**: Load cached results if valid
3. **Scan Phase**: Parallel source scanning → Deduplication
4. **Update Check**: Query each source for available updates
5. **Security Check**: Run vulnerability scans (NPM audit, PIP check)
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
    rust: boolean
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
| `--package <name>` | - | String | Update one package by name |
| `--version <ver>` | - | String | Target version (with --package) |
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
python -m system_update --package git --source chocolatey

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
1. Run `python -m system_update --package node --source path --version 22.0.0`
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

### 16.1 Planned Features

| ID | Feature | Priority | Description |
|----|---------|----------|-------------|
| E-01 | Configuration file support | P1 | Persistent user configuration |
| E-02 | Auto-update mode | P2 | Scheduled background updates |
| E-03 | Rollback support | P2 | Revert to previous versions |
| E-04 | Interactive selection | P2 | TUI for choosing updates |
| E-05 | Plugin architecture | P3 | Custom source providers |
| E-06 | Homebrew support | P2 | macOS package manager |
| E-07 | APT/YUM support | P2 | Linux package managers |
| E-08 | Update groups | P3 | Named package collections |
| E-09 | Pre/post hooks | P3 | Custom scripts around updates |
| E-10 | Progress persistence | P3 | Resume interrupted scans |

### 16.2 Known Limitations

1. **Windows-centric**: Registry scanning only works on Windows
2. **Global packages only**: Does not scan project-local dependencies
3. **No dependency resolution**: Updates packages independently
4. **Limited vulnerability sources**: Only NPM and PIP supported
5. **No authentication**: Cannot access private registries

### 16.3 Technical Debt

- Hardcoded source list (not extensible without code changes)
- No unit tests
- Limited integration tests
- No TypeScript types
- Sequential security checks (could be parallel)

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
