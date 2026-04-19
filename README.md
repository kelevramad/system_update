# System Update CLI

> 🚀 A powerful system update tool for Windows.

A comprehensive Python-based system package management tool that scans, checks, and updates software from multiple sources.

**Version:** 4.2.0
**Runtime:** Python 3.8+
**Platform:** Windows (primarily), cross-platform support

---

## 🌟 Features

- **Multi-source Package Discovery**: Scan applications installed via Winget, Chocolatey, NPM, PNPM, Bun, Yarn, PIP, Scoop, system PATH executables, and Windows Registry.
- **Security Scanning**: Real-time vulnerability checking for NPM (`npm audit`) and PIP (`pip check`) packages.
- **Intelligent Caching**: 2-hour caching mechanism to drastically speed up repetitive runs.
- **Dry-run & Output Options**: Safely preview updates before applying them and export reports to JSON or CSV formats.
- **Rich Terminal UI**: Beautiful, colorful console output built with the `rich` library, featuring spinners, progress bars, and emoji indicators.
- **Parallel Processing**: ThreadPoolExecutor for optimal performance.
- **Modular Architecture**: Clean separation of concerns with dataclasses.
- **Smart Version Comparison**: Handles preview/stable version detection.
- **Interactive TUI**: Fuzzy search, multi-select, and preview for package selection.

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
# Navigate to the script directory
cd C:\Git\System_Update

# Optional: Install dependencies manually
pip install rich
```

The script will automatically prompt to install the `rich` library if missing.

### Basic Usage

```bash
# Run a full system scan
python system_update.py

# Update all packages automatically
python system_update.py --update-all --yes

# Check for updates without installing
python system_update.py --dry-run

# Export scan results to JSON
python system_update.py --export json --output report.json
```

---

## 📖 Command Reference

### Options

| Option | Description |
|--------|-------------|
| `--update-all` | Update every package with available updates |
| `--update-source <source>` | Update all packages from a specific source |
| `--package <name>` | Update a specific package by name |
| `--version <ver>` | Target version (use with `--package`) |
| `--source <source>` | Filter by source (winget\|chocolatey\|npm\|pnpm\|bun\|yarn\|pip\|path\|rust\|registry) |
| `--dry-run` | Show planned updates without executing |
| `--no-cache` | Force fresh scan (ignore cache) |
| `--clear-cache` | Remove cache file and exit |
| `--export <json\|csv>` | Export scan results to file |
| `--output <file>` | Output path for export |
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
python system_update.py

# Update all packages without confirmation
python system_update.py --update-all --yes

# Update only Winget packages
python system_update.py --source winget --yes

# Update only Rust packages
python system_update.py --source rust --yes

# Update all packages from a specific source
python system_update.py --update-source rust --yes

# Update all Winget packages
python system_update.py --update-source winget --dry-run

# Update a specific package
python system_update.py --package git --source chocolatey

# Dry run to preview updates
python system_update.py --dry-run

# Scan only specific sources
python system_update.py --source winget,npm,pip

# Export results to JSON
python system_update.py --export json --output updates.json

# Export results to CSV
python system_update.py --export csv --output updates.csv

# Force fresh scan and export
python system_update.py --no-cache --export json

# Show all packages (including up-to-date)
python system_update.py --show-all

# Interactive package selection
python system_update.py --interactive
```

---

## 🔧 Configuration

### Default Configuration

The script uses the following default settings stored in `~/.system_update/config.json`:

```json
{
    "cache": {
        "duration_hours": 2,
        "enabled": true
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
  "total_apps": 45,
  "apps": [
    {
      "name": "git",
      "source": "Winget",
      "version": "2.40.1",
      "latest_version": "2.44.0",
      "update_status": "⬆️",
      "app_id": "Git.Git",
      "has_update": true,
      "scan_time": "2026-02-26T10:30:00.000000"
    }
  ]
}
```

### CSV Export

```csv
name,source,version,latest_version,update_status,app_id,scan_time
git,Winget,2.40.1,2.44.0,⬆️,Git.Git,2026-02-26T10:30:00.000000
node,NPM,18.16.0,20.11.0,⬆️,node,2026-02-26T10:30:00.000000
```

---

## 🏗️ Architecture

### Core Components

```
SystemUpdateApp          - Main application controller
├── UISystem             - User interface (Rich-based)
├── PackageScanner       - Multi-source package discovery
├── UpdateChecker        - Update detection system
├── UpdateExecutor       - Update execution engine
└── CacheManager         - Intelligent caching

Data Models:
├── AppInfo              - Package metadata (dataclass)
├── SecurityInfo         - Vulnerability data (dataclass)
└── UpdateStatus         - Status enumeration
```

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

# Run with coverage
uv run pytest --cov=system_update --cov-report=term-missing
```

---

For complete version history and license, see [CHANGELOG.md](CHANGELOG.md).

Contributions and enhancements are always welcome!
