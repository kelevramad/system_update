# System Update CLI - Node.js Implementation

## Overview

`system_update.js` is a cross-platform command-line tool that scans and updates packages from multiple package managers on your system. It provides a unified interface to manage updates across different package sources including Winget, Chocolatey, NPM, PNPM, Yarn, Bun, PIP, PATH-based installs, and Windows Registry.

**Version:** 1.0.1  
**Language:** Node.js (ES6+)  
**Platform:** Windows, Linux, macOS (partial support)

---

## Features

### Core Capabilities

- **Multi-Source Scanning**: Discover installed packages from multiple package managers
- **Update Detection**: Check for available updates across all sources
- **Security Scanning**: Vulnerability detection for NPM and PIP packages
- **Caching**: Intelligent caching to speed up repeated scans (2-hour default)
- **Parallel Operations**: Concurrent scanning and checking for better performance
- **Export Support**: Export results to JSON or CSV formats
- **Dry Run Mode**: Preview updates before applying them
- **Selective Updates**: Update all, by source, or specific packages

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
| `--update-source <source>` | Update all packages from one source (e.g., `winget`, `chocolatey`, `npm`, `pnpm`, `pip`, `path`) |
| `--package <name>` | Update a specific package by name |
| `--version <ver>` | Target version (used with `--package`) |
| `--source <source>` | Source filter for `--package` (disambiguates packages with same name) |
| `--dry-run` | Print planned updates without executing them |
| `--no-cache` | Force fresh scan, bypassing the cache |
| `--clear-cache` | Remove cache file and exit |
| `--export <json\|csv>` | Export scan results to JSON or CSV format |
| `--output <file>` | Output path for export (default: stdout for JSON, file for CSV) |
| `--include <csv>` | Limit scan sources (comma-separated, e.g., `winget,npm,pip`) |
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
| `update_available` | ⬆️ | yellow | Update available |
| `error` | ❌ | red | Scan/update failed |
| `vulnerable` | 🔥 | red (bold) | Security vulnerability found |
| `security_update_available` | 🔒 | magenta (bold) | Security update available |
| `unknown` | ❔ | gray | Status could not be determined |

### Main Table Columns

- **Package**: Package name
- **Source**: Package manager source (winget, npm, pip, etc.)
- **Current**: Currently installed version
- **Latest**: Latest available version
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

### Error Handling Strategy

- Commands use **timeouts** (45s default) to prevent hangs
- Optional commands (like `winget list`) use `allowFailure: true`
- Errors are logged to `system.log` but don't crash the CLI
- Non-critical failures continue processing other sources

### Log File Format

```
2026-03-11T12:34:56.789Z Command timed out: winget list
2026-03-11T12:35:01.234Z update failed: nodejs (npm) stderr=...
```

Log location: `{data-directory}/system.log`

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

### Source Scanners

Each source has a dedicated scanner function:

- `scanWinget()` - Windows only, uses `winget list --accept-source-agreements`
- `scanChocolatey()` - Windows only, uses `choco list --local-only --limit-output`
- `scanNpm()` - Uses `npm list -g --depth=0 --json --silent`
- `scanPnpm()` - Uses `pnpm list -g --depth=0 --json`
- `scanYarn()` - Uses `yarn global list --json`
- `scanBun()` - Uses `bun pm ls -g`
- `scanPip()` - Uses `pip list --format=json` (with fallback to `pip freeze`)
- `scanPath()` - Scans `PATH` for known executables (bun, deno, git, pwsh, yarn, etc.)
- `scanRegistry()` - Windows only, scans installed programs from registry (HKLM/HKCU)

### Update Checkers

Each source has an update checker:

- `checkWingetUpdates()` - Uses `winget upgrade`
- `checkChocolateyUpdates()` - Uses `choco outdated`
- `checkNpmUpdates()` - Uses `npm outdated -g --json`
- `checkPnpmUpdates()` - Uses `pnpm outdated -g --json`
- `checkBunUpdates()` - Uses `bpm update --global --json` or `bun update --global`
- `checkYarnUpdates()` - Parses `yarn outdated` (no JSON support)
- `checkPipUpdates()` - Uses `pip list --outdated --format=json`
- `checkPathUpdates()` - Connects to source-specific upgrade endpoints
- `checkRegistryUpdates()` - Queries Windows registry for update detection

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
3. **Yarn Updates**: Relies on text parsing `yarn outdated` (no JSON output)
4. **Bun Updates**: Depends on `bpm` (Bun Package Manager) availability
5. **Registry**: Windows registry scanning may miss some applications
6. **PATH**: Limited to known executables; not all PATH-installed tools are detected

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

# Test caching
node system_update.js --no-cache

# Export to JSON
node system_update.js --export json

# Export to CSV
node system_update.js --export csv --output updates.csv
```

### Code Quality

- No external dependencies
- ESLint patterns (if configured)
- Consistent with project-wide conventions

---

## License & Credits

Part of the **System Update** multi-platform CLI project.

For Python and PowerShell implementations, see:
- `system_update.py` - Python version with Rich UI
- `system_update.ps1` - PowerShell native version

---

## Support

For issues, feature requests, or contributions, refer to the project repository.