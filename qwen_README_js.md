# System Update Node.js CLI

> 🚀 A powerful multi-source system update tool for Windows

**Version:** 1.0.1  
**Runtime:** Node.js  
**Platform:** Windows (primarily), cross-platform support

---

## 📋 Overview

System Update Node.js CLI is a comprehensive package management tool that scans, checks, and updates software from multiple sources including Winget, Chocolatey, NPM, PNPM, Bun, Yarn, PIP, and system PATH executables.

### ✨ Key Features

- **Multi-source package discovery** - Scan Winget, Chocolatey, NPM, PNPM, Bun, Yarn, PIP, PATH, and Windows Registry
- **Security vulnerability scanning** - Real-time security checks for NPM and PIP packages
- **Parallel scanning** - Optimized performance with concurrent source scanning
- **Smart caching** - 2-hour cache duration for faster subsequent runs
- **Flexible export** - Export results to JSON or CSV formats
- **Dry-run support** - Preview updates before applying them
- **Beautiful CLI output** - Colorful, emoji-rich terminal interface with progress bars

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
| `--update-source <source>` | Update all packages from a specific source (winget\|chocolatey\|npm\|pnpm\|pip\|path) |
| `--package <name>` | Update a specific package by name |
| `--version <ver>` | Target version (use with `--package`) |
| `--source <source>` | Filter by source (winget\|chocolatey\|npm\|pnpm\|bun\|yarn\|pip\|path\|registry) |
| `--dry-run` | Show planned updates without executing |
| `--no-cache` | Force fresh scan (ignore cache) |
| `--clear-cache` | Remove cache file and exit |
| `--export <json\|csv>` | Export scan results to file |
| `--output <file>` | Output path for export |
| `--include <csv>` | Limit scan to specific sources (e.g., `winget,npm,pip`) |
| `--yes`, `-y` | Skip confirmation prompts |
| `--help`, `-h` | Show help message |

### Examples

```bash
# Full system scan with interactive updates
node system_update.js

# Update all packages without confirmation
node system_update.js --update-all --yes

# Update only Winget packages
node system_update.js --update-source winget --yes

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
    registry: true
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
| PATH | ✅ | ✅ | ❌ |
| Registry | ✅ | ✅ | ❌ |

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
- **Bun** - Magenta
- **Yarn** - Blue
- **PIP** - Cyan
- **PATH** - Green
- **Registry** - Gray

---

## 🛠️ Troubleshooting

### Common Issues

**Cache permission errors:**
The script automatically falls back to a local `.system_update` directory if the home directory is not writable.

**Command timeouts:**
Increase the timeout in the configuration or use `--no-cache` for fresh scans.

**Package not found:**
Ensure the package manager is installed and available in PATH.

### Logging

All operations are logged to `<DATA_DIR>/system.log` with timestamps for debugging.

---

## 📝 License

This project is provided as-is for system administration and package management tasks.

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
