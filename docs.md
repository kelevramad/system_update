# System Update CLI - Node.js Implementation

## Overview

`system_update.js` is a cross-platform command-line tool that scans and updates packages from multiple package managers on your system. It provides a unified interface to manage updates across different package sources including Winget, Chocolatey, NPM, PNPM, Yarn, Bun, PIP, Rust, PATH-based installs, and Windows Registry.

**Version:** 1.0.1
**Language:** Node.js (ES6+)
**Platform:** Windows, Linux, macOS (partial support)

---

## Features

### Core Capabilities

- **Multi-Source Scanning**: Discover installed packages from 10 different package managers
- **Update Detection**: Check for available updates across all sources
- **Security Scanning**: Vulnerability detection for NPM and PIP packages
- **Caching**: Intelligent caching to speed up repeated scans (2-hour default)
- **Parallel Operations**: Concurrent scanning and checking for better performance
- **Export Support**: Export results to JSON or CSV formats
- **Dry Run Mode**: Preview updates before applying them
- **Selective Updates**: Update all, by source, or specific packages
- **Logging**: Optional file logging with `--log` flag
- **Debug Mode**: Show all executed commands with `--debug` flag

### Supported Sources

| Source | Scan | Auto-Update | Security Scan |
|--------|------|-------------|---------------|
| Winget | ✅ | ✅ | ❌ |
| Chocolatey | ✅ | ✅ | ❌ |
| NPM | ✅ | ✅ | ✅ |
| PNPM | ✅ | ✅ | ❌ |
| Bun | ✅ | ✅ | ❌ |
| Yarn | ✅ | ✅ | ❌ |
| PIP | ✅ | ✅ | ✅ |
| PATH | ✅ | ✅ | ❌ |
| Registry | ✅ | ✅ | ❌ |
| Rust | ✅ | ✅ | ❌ |

---

## Installation & Setup

### Prerequisites

- Node.js 18+ (recommended)
- Target package managers installed (winget, choco, npm, etc.)

### Running the CLI

```bash
# Basic usage (scan all sources)
node system_update.js

# With all options
node system_update.js --update-all --dry-run --no-cache

# Specific package update
node system_update.js --package <name> --source winget

# Export results
node system_update.js --export json --output updates.json
```

As an npm package:
```bash
npm start
npm run help
```

---

## Command-Line Options

### General Options

| Option | Description |
|--------|-------------|
| `--update-all` | Update every package with available updates |
| `--update-source <source>` | Update all packages from one source (e.g., `winget`, `chocolatey`, `npm`, `pnpm`, `pip`, `bun`, `yarn`, `path`, `rust`, `registry`) |
| `--package <name>` | Update a specific package by name |
| `--version <ver>` | Target version (used with `--package`) |
| `--source <source>` | Source filter for `--package` (disambiguates packages with same name) |
| `--dry-run` | Print planned updates without executing them |
| `--no-cache` | Force fresh scan, bypassing the cache |
| `--clear-cache` | Remove cache file and exit |
| `--export <json\|csv>` | Export scan results to JSON or CSV format |
| `--output <file>` | Output path for export (default: stdout for JSON, file for CSV) |
| `--include <csv>` | Limit scan sources (comma-separated, e.g., `winget,npm,pip`) |
| `--log` | Enable logging to file |
| `--debug` | Show all executed commands on screen and in log |
| `--yes, -y` | Skip confirmation prompts (auto-approve) |
| `--help, -h` | Show help message |

### Configuration

The script uses a default configuration that can be customized:

```javascript
const DEFAULT_CONFIG = {
  cache: {
    enabled: true,
    durationHours: 2,          // Cache valid for 2 hours
  },
  performance: {
    timeoutSeconds: 45,       // Command timeout (seconds)
    maxWorkers: 6,            // Parallel scan workers
  },
  sources: {
    winget: true,
    chocolatey: true,
    npm: true,
    pnpm: true,
    pip: true,
    bun: true,
    yarn: true,
    path: true,
    registry: true,
    rust: true,
  },
  security: {
    enabled: true,            // Security scanning on/off
    autoCheck: true,          // Check security automatically
    severityThreshold: 'medium', // Min severity: critical, high, medium, low
  },
  ui: {
    compact: false,           // Compact output mode
  },
};
```

---

## Output & Display

### Status Indicators

| Status | Emoji | Color | Meaning |
|--------|-------|-------|---------|
| `up_to_date` | ✅ | green | Package is current |
| `update_available` | ⬆️ | yellow (bold) | Update available |
| `error` | ❌ | red | Scan/update failed |
| `vulnerable` | 🔥 | red (bold) | Security vulnerability found |
| `security_update_available` | 🔒 | magenta (bold) | Security update available |
| `unknown` | ❔ | gray | Status could not be determined |

### Source Badges

Each source is displayed with a unique color:

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

### Main Table Columns

- **Package**: Package name
- **Source**: Package manager source (winget, npm, pip, etc.)
- **Current**: Currently installed version
- **Latest**: Latest available version (shows `-` when up-to-date)
- **Status**: Update/vulnerability status

### Summary Section

After scanning, the CLI displays:
- Total number of discovered packages
- Count of packages with updates
- Scan duration
- Breakdown by source (e.g., `npm:45, winget:12`)

---

## Caching System

### Cache Location

The script stores cache in the following locations (in order of preference):

1. **Custom directory**: `$SYSTEM_UPDATE_HOME` environment variable
2. **Default home**: `~/.system_update/` (Unix) or `%USERPROFILE%\.system_update\` (Windows)
3. **Fallback**: Current working directory `./.system_update/` (if above locations are inaccessible)

### Cache Files

- `cache.json` - Main cache storing discovered packages and metadata
- `system.log` - Log file for errors and operations

### Cache Behavior

- Cache valid for **2 hours** by default
- Cache stores: package name, source, current version, latest version, status, scan timestamp
- `--no-cache` forces a fresh scan, ignoring existing cache
- `--clear-cache` removes the cache file

---

## Error Handling & Logging

### Logging Modes

| Mode | Flag | Description |
|------|------|-------------|
| Disabled | (default) | No logging to file |
| Enabled | `--log` | All operations logged to file |
| Debug | `--debug` | All executed commands shown on screen AND logged |

### Error Handling Strategy

- Commands use **timeouts** (45s default) to prevent hangs
- Optional commands (like `winget list`) use `allowFailure: true`
- Errors are logged to `system.log` but don't crash the CLI
- Non-critical failures continue processing other sources
- Debug mode shows all executed commands with `[DEBUG]` prefix

### Log File Format

```
2026-03-11T12:34:56.789Z Command timed out: winget list
2026-03-11T12:35:01.234Z update failed: nodejs (npm) stderr=...
2026-03-11T12:35:05.000Z [DEBUG] Executing: winget upgrade --id Git.Git
```

Log location: `{data-directory}/system.log`

### Debug Output

When `--debug` is enabled, all executed commands are displayed:

```
[DEBUG] Executing: winget upgrade --id Git.Git --accept-source-agreements
[DEBUG] Executing: npm outdated -g --json
```

---

## Security Scanning

### NPM Vulnerabilities

- Uses `npm audit --json --silent` to check for known CVEs
- Parses `vulnerabilities` object from audit output
- Reports package name, severity, CVE, description

### PIP Vulnerabilities

- Uses `pip check --format=json` (PIP 22.3+)
- Parses output for vulnerability information
- Reports package name, severity, CVE, description

### Severity Threshold

Configure with `config.security.severityThreshold`:
- `critical` - Only show critical vulnerabilities
- `high` - Show high and critical
- `medium` - Show medium, high, and critical (default)
- `low` - Show all vulnerabilities

Vulnerable packages receive `VULNERABLE` status and are highlighted in red.

---

## Implementation Details

### Architecture

1. **Parser** (`parseArgs`) - Parses CLI arguments into options object
2. **Scanner** (`scanSystem`) - Discovers packages from all enabled sources
3. **Cache Manager** (`loadCache`, `saveCache`) - Handles persistence
4. **Update Checker** (`checkUpdates`) - Queries each source for available updates
5. **Security Checker** (`checkSecurityVulnerabilities`) - Runs vulnerability scans
6. **Executor** (`executeUpdates`) - Applies updates sequentially
7. **UI Renderer** (`printAppsTable`, `printSecurityTable`) - Displays results
8. **Logger** (`writeLog`) - Optional file logging with `--log` flag
9. **Debug Mode** (`DEBUG_ENABLED`) - Shows all executed commands

### Source Scanners

Each source has a dedicated scanner function:

- `scanWinget()` - Windows only, uses `winget list --accept-source-agreements`
- `scanChocolatey()` - Windows only, uses `choco list --limit-output`
- `scanNpm()` - Uses `npm list -g --depth=0 --json --silent`
- `scanPnpm()` - Uses `pnpm list -g --depth=0 --json`
- `scanYarn()` - Uses `yarn global list`
- `scanBun()` - Uses `bun pm ls -g`
- `scanPip()` - Uses `pip list --format=json` (with fallbacks: py, python, python3)
- `scanPath()` - Scans PATH for known executables (node, npm, pnpm, yarn, python, git, go, bun, deno, rustc, cargo, dotnet, java, pwsh)
- `scanRegistry()` - Windows only, scans installed programs from registry (HKLM/HKCU)
- `scanRust()` - Uses `cargo install --list`

### Update Checkers

Each source has an update checker:

- `checkWingetUpdates()` - Uses `winget upgrade --accept-source-agreements`
- `checkChocolateyUpdates()` - Uses `choco outdated --limit-output`
- `checkNpmUpdates()` - Uses `npm outdated -g --json --silent`
- `checkPnpmUpdates()` - Uses `pnpm outdated -g --json`
- `checkBunUpdates()` - Uses `npm info <package> version`
- `checkYarnUpdates()` - Uses `npm info <package> version`
- `checkPipUpdates()` - Uses `pip list --outdated --format=json`
- `checkPathUpdates()` - Uses GitHub API, winget, or source-specific commands
- `checkRegistryUpdates()` - Cross-references with winget upgrade output
- `checkRustUpdates()` - Uses `cargo install-update -l` (requires cargo-update)

### Command Execution

The `runCommand()` function provides robust command execution:

- Cross-platform command normalization (Windows: adds `.cmd`, `.bat`, `.exe` extensions)
- Timeout handling (default 45s, configurable)
- UTF-8 encoding with error ignore
- `allowFailure` flag for non-critical commands
- Detailed error logging
- Returns `{ ok, stdout, stderr, code }` object

Example:
```javascript
const result = await runCommand('npm', ['list', '-g', '--json'], {
  timeoutMs: 45000,
  allowFailure: true
});
```

---

## Code Style & Conventions

The codebase follows JavaScript best practices:

- `'use strict'` mode
- ES6+ features (async/await, arrow functions, template literals)
- Proper error handling with try/catch
- No external dependencies (pure Node.js)
- Consistent naming (camelCase for variables/functions, UPPER_SNAKE for constants)
- Well-commented complex logic
- ANSI color codes for terminal UI

### Key Patterns

```javascript
// Command execution with timeout
async function runCommand(cmd, args = [], options = {}) {
  const {
    timeoutMs = 45000,
    encoding = 'utf-8',
    allowFailure = false
  } = options;
  // Implementation...
}

// Progress tracking
const progress = createProgress(total, label);
progress.tick(message);  // Update current
progress.done(message);  // Complete
```

---

## Known Limitations

1. **Platform Support**: Some sources are Windows-only (Winget, Chocolatey, Registry scanning)
2. **Security Scanning**: Only NPM and PIP have vulnerability detection
3. **Rust Updates**: Requires `cargo-update` to be installed (`cargo install cargo-update`)
4. **Yarn/Bun Updates**: Relies on `npm info` for version checking
5. **Registry**: Windows registry scanning may miss some applications
6. **PATH**: Limited to known executables; not all PATH-installed tools are detected
7. **Logging**: Disabled by default; must use `--log` flag to enable

---

## Troubleshooting

### Common Issues

**Permission Denied** (cache or log)
- The script will fallback to local `.system_update/` directory
- Ensure write permissions to home directory

**Command Not Found** (package manager)
- Install the missing package manager
- Disable the source in config if unavailable

**Timeout Errors**
- Increase `performance.timeoutSeconds` in config
- Check network connectivity for online sources

**No Updates Detected (but updates exist)**
- Use `--no-cache` to force fresh scan
- Verify package manager CLI is in PATH
- Check if source is enabled in config

**Rust Updates Not Working**
- Ensure `cargo-update` is installed: `cargo install cargo-update`
- Verify cargo is in PATH

**Logging Not Working**
- Ensure `--log` flag is used to enable logging
- Check write permissions to data directory

### Using Debug Mode

For detailed troubleshooting, use `--debug` to see all executed commands:

```bash
node system_update.js --debug
```

This will show each command as it's executed:
```
[DEBUG] Executing: winget list --accept-source-agreements
[DEBUG] Executing: npm list -g --depth=0 --json --silent
```

---

## Development & Testing

### Manual Testing

```bash
# Run basic scan
node system_update.js

# Dry-run update
node system_update.js --dry-run --update-all

# Test single package
node system_update.js --package <name> --source npm

# Test Rust packages
node system_update.js --update-source rust

# Test caching
node system_update.js --no-cache

# Export to JSON
node system_update.js --export json

# Export to CSV
node system_update.js --export csv --output updates.csv

# Enable logging
node system_update.js --log

# Debug mode (show all commands)
node system_update.js --debug
```

### Code Quality

- No external dependencies
- ESLint patterns (if configured)
- Consistent with project-wide conventions

---

## License & Credits

Part of the **System Update** multi-platform CLI project.

**Version:** 1.0.1

For Python and PowerShell implementations, see:
- `system_update.py` - Python version with Rich UI
- `system_update.ps1` - PowerShell native version

---

## Support

For issues, feature requests, or contributions:
1. Check the log file at `~/.system_update/system.log`
2. Run with `--no-cache` to rule out cache issues
3. Use `--debug` to see all executed commands
4. Verify package managers are installed and accessible