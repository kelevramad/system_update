# System Update Node.js CLI

> 🚀 A powerful multi-source system update tool for Windows

**Version:** 2.0.0
**Runtime:** Node.js
**Platform:** Windows (primarily), cross-platform support

> **Note:** This repository also includes Python (`system_update.py`) and PowerShell (`system_update.ps1`) implementations. See [README_py.md](README_py.md) and [README_ps.md](README_ps.md).

---

## 📋 Overview

System Update Node.js CLI is a comprehensive package management tool that scans, checks, and updates software from multiple sources including Winget, Chocolatey, NPM, PNPM, Bun, Yarn, PIP, Rust, and system PATH executables.

### ✨ Key Features

- **Multi-source package discovery** - Scan Winget, Chocolatey, NPM, PNPM, Bun, Yarn, PIP, Rust, PATH, and Windows Registry
- **Security vulnerability scanning** - Real-time security checks for NPM and PIP packages
- **Parallel scanning** - Optimized performance with concurrent source scanning
- **Smart caching** - 2-hour cache duration for faster subsequent runs
- **Flexible export** - Export results to JSON or CSV formats
- **Dry-run support** - Preview updates before applying them
- **Beautiful CLI output** - Colorful, emoji-rich terminal interface with progress bars
- **Detailed logging** - Optional logging with `--log` flag for debugging
- **Debug mode** - Show all executed commands with `--debug` flag

---

## 🚀 Quick Start

### Prerequisites

- **Node.js** 16.x or higher
- **Windows 10/11** (primary platform)
- Optional package managers: Winget, Chocolatey, NPM, PNPM, Bun, Yarn, PIP

### Installation

No installation required. Clone or download the script:

```bash
# Navigate to the script directory
cd C:\Git\System_Update
```

### Basic Usage

```bash
# Run a full system scan
node system_update.js

# Update all packages automatically
node system_update.js --update-all --yes

# Check for updates without installing
node system_update.js --dry-run

# Export scan results to JSON
node system_update.js --export json --output report.json
```

---

## 📖 Command Reference

### Options

| Option | Description |
|--------|-------------|
| `--update-all` | Update every package with available updates |
| `--update-source <source>` | Update all packages from a specific source (winget\|chocolatey\|npm\|pnpm\|pip\|bun\|yarn\|path\|rust\|registry) |
| `--package <name>` | Update a specific package by name |
| `--version <ver>` | Target version (use with `--package`) |
| `--source <source>` | Filter by source (winget\|chocolatey\|npm\|pnpm\|bun\|yarn\|pip\|path\|rust\|registry) |
| `--dry-run` | Show planned updates without executing |
| `--no-cache` | Force fresh scan (ignore cache) |
| `--clear-cache` | Remove cache file and exit |
| `--export <json\|csv>` | Export scan results to file |
| `--output <file>` | Output path for export |
| `--include <csv>` | Limit scan to specific sources (e.g., `winget,npm,pip`) |
| `--log` | Enable logging to file |
| `--debug` | Show all executed commands on screen and in log |
| `--yes`, `-y` | Skip confirmation prompts |
| `--help`, `-h` | Show help message |
| `--show-all` | Show all packages (including up-to-date) |

### Examples

```bash
# Full system scan with interactive updates
node system_update.js

# Update all packages without confirmation
node system_update.js --update-all --yes

# Update only Winget packages
node system_update.js --update-source winget --yes

# Update only Rust packages
node system_update.js --update-source rust --yes

# Update a specific package
node system_update.js --package git --source chocolatey

# Dry run to preview updates
node system_update.js --dry-run

# Scan only specific sources
node system_update.js --include winget,npm,pip

# Export results to JSON
node system_update.js --export json --output updates.json

# Export results to CSV
node system_update.js --export csv --output updates.csv

# Force fresh scan and export
node system_update.js --no-cache --export json

# Enable logging for debugging
node system_update.js --log

# Show all executed commands
node system_update.js --debug

# Show all packages (including up-to-date)
node system_update.js --show-all
```

---

## 🔧 Configuration

### Default Configuration

The script uses the following default settings:

```javascript
{
  cache: {
    enabled: true,
    durationHours: 2
  },
  performance: {
    timeoutSeconds: 45,
    maxWorkers: 6
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
    rust: true
  },
  security: {
    enabled: true,
    autoCheck: true,
    severityThreshold: 'medium'
  },
  ui: {
    compact: false
  }
}
```

### Data Directory

- **Default:** `~/.system_update` (user's home directory)
- **Fallback:** `./.system_update` (current directory)
- **Custom:** Set `SYSTEM_UPDATE_HOME` environment variable

### Cache File

- **Location:** `<DATA_DIR>/cache.json`
- **Duration:** 2 hours (configurable)
- **Log File:** `<DATA_DIR>/system.log`

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

---

## 🔒 Security Features

### Vulnerability Scanning

The CLI automatically scans for security vulnerabilities in:

- **NPM packages** - Uses `npm audit` to detect known vulnerabilities
- **PIP packages** - Uses `pip check` to identify security issues

### Severity Thresholds

Vulnerabilities are filtered by severity:
- **Critical** - Highest priority
- **High** - Serious security risk
- **Medium** - Moderate risk (default threshold)
- **Low** - Minor issues

---

## 📤 Export Formats

### JSON Export

```json
{
  "scanTime": "2026-02-26T10:30:00.000Z",
  "totalApps": 45,
  "apps": [
    {
      "name": "git",
      "source": "winget",
      "version": "2.40.1",
      "latestVersion": "2.44.0",
      "status": "update_available",
      "appId": "Git.Git"
    }
  ]
}
```

### CSV Export

```csv
name,source,version,latestVersion,status,appId
git,winget,2.40.1,2.44.0,update_available,Git.Git
node,npm,18.16.0,20.11.0,update_available,node
```

---

## 🎨 Output Format

### Status Indicators

| Status | Badge | Description |
|--------|-------|-------------|
| `up_to_date` | ✅ up-to-date | Package is current |
| `update_available` | ⬆️ update | New version available |
| `vulnerable` | 🔥 vulnerable | Security vulnerability detected |
| `security_update` | 🔒 security update | Security patch available |
| `error` | ❌ error | Scan/update failed |
| `unknown` | ❔ unknown | Status could not be determined |

### Source Badges

Each source has a unique color:
- **Winget** - Blue
- **Chocolatey** - Yellow
- **NPM** - Red
- **PNPM** - Magenta
- **Bun** - Orange
- **Yarn** - White
- **PIP** - Cyan
- **Rust** - Magenta
- **PATH** - Green
- **Registry** - Gray

### Output Example

```
📊 Summary
📦 total apps     456
⬆️ updates        78
⏱️ scan duration  34.81s
⚙️ sources        chocolatey:21, npm:16, path:12, pip:58, registry:104, rust:1, winget:243, yarn:1

Package                       Source        Current             Latest              Status
────────────────────────────────────────────────────────────────────────────────────────────────────
git                           chocolatey    2.39.0              2.44.0              ⬆️ update
node                          path          v20.11.0            v22.0.0             ⬆️ update

💾 Showing: updates only

🎯 Found 78 available updates
```

With `--show-all`:
```
💾 Showing: all packages
```

---

## 🛠️ Troubleshooting

### Common Issues

**Cache permission errors:**
The script automatically falls back to a local `.system_update` directory if the home directory is not writable.

**Command timeouts:**
Increase the timeout in the configuration or use `--no-cache` for fresh scans.

**Package not found:**
Ensure the package manager is installed and available in PATH.

**Rust updates not working:**
Ensure `cargo-edit` and `cargo-update` are installed: `cargo install cargo-update`

### Logging

All operations are logged to `<DATA_DIR>/system.log` with timestamps for debugging. Enable logging with `--log` flag:

```bash
node system_update.js --log
```

### Debug Mode

Show all executed commands on screen and in logs with `--debug`:

```bash
node system_update.js --debug
```

---

## 🧪 Testing

This project includes a comprehensive test suite using Node.js native test runner. Tests are located in the `tests/` directory.

### Run Tests

```bash
# Install dependencies
npm install

# Run tests
npm run test

# Run with coverage
npm run coverage
npm run test:all        # Runs tests + coverage
```

### Test Files

```
tests/
└── system_update_cli.test.js    # Node.js tests (native --test runner)
```

---

## 📝 License

This project is provided as-is for system administration and package management tasks.

---

## 🆕 Latest Changes (v1.0.1)

- **New `--show-all` flag**: Show all packages including up-to-date ones (default shows only updates)
- **Improved output format**: "💾 Showing" line now appears after the package table
- **New "🎯 Found" message**: Clear indication of available updates count at the end
- **Target emoji (🎯) added**: Better visual distinction for update notifications
- **Scoop support**: Added Scoop package manager support

Contributions and enhancements are always welcome!

---

## 🤝 Contributing

Contributions are welcome! Please ensure your changes:
- Follow existing code style
- Include appropriate error handling
- Test with multiple package managers
- Update documentation as needed

---

## 📞 Support

For issues or questions, please check:
1. The log file at `~/.system_update/system.log`
2. Run with `--no-cache` to rule out cache issues
3. Verify package managers are installed and accessible
