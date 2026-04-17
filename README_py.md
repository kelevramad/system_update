# System Update Python CLI

> 🚀 A sophisticated system update tool with enhanced UI and modular design

 **Version:** 2.7.0
**Runtime:** Python 3.8+
**Platform:** Windows (primarily), cross-platform support

> **Note:** This repository also includes Node.js (`system_update.js`) and PowerShell (`system_update.ps1`) implementations. See [README_js.md](README_js.md) and [README_ps.md](README_ps.md).

---

## 📋 Overview

System Update Python CLI is an advanced package management tool featuring a beautiful Rich-based terminal interface. It scans, checks, and updates software from multiple sources including Winget, Chocolatey, NPM, PNPM, Bun, Yarn, PIP, Rust, and system PATH executables.

### ✨ Key Features

- **Multi-source package discovery** - Scan Winget, Chocolatey, NPM, PNPM, Bun, Yarn, PIP, Rust, PATH, and Windows Registry
- **Real-time security vulnerability scanning** - CVE detection for NPM and PIP packages
- **Parallel processing** - ThreadPoolExecutor for optimal performance
- **Beautiful Rich UI** - Modern terminal interface with panels, tables, and progress bars
- **Flexible export options** - JSON and CSV export with timestamps
- **Intelligent caching** - 2-hour cache with validation
- **Dry-run support** - Preview updates before applying
- **Modular architecture** - Clean separation of concerns with dataclasses
- **Smart version comparison** - Handles preview/stable version detection

---

## 🚀 Quick Start

### Prerequisites

- **Python** 3.8 or higher
- **Windows 10/11** (primary platform)
- **Rich library** (auto-installed on first run)

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
| `--include <csv>` | Limit scan to specific sources (e.g., `winget,npm,pip`) |
| `--yes`, `-y` | Skip confirmation prompts |
| `--help`, `-h` | Show help message |
| `--show-all` | Show all packages (including up-to-date) |

### Examples

```bash
# Full system scan with interactive updates
python system_update.py

# Update all packages without confirmation
python system_update.py --update-all --yes

# Update only Winget packages
python system_update.py --update-source winget --yes

# Update only Rust packages
python system_update.py --update-source rust --yes

# Update a specific package
python system_update.py --package git --source chocolatey

# Dry run to preview updates
python system_update.py --dry-run

# Scan only specific sources
python system_update.py --include winget,npm,pip

# Export results to JSON
python system_update.py --export json --output updates.json

# Export results to CSV
python system_update.py --export csv --output updates.csv

# Force fresh scan and export
python system_update.py --no-cache --export json

# Show all packages (including up-to-date)
python system_update.py --show-all
```

---

## 🔧 Configuration

### Default Configuration

The script uses the following default settings stored in `~/.system_update/config.json`:

```python
{
    "cache": {
        "duration_hours": 2,
        "enabled": True
    },
    "performance": {
        "parallel_scan": True,
        "max_workers": 6,
        "timeout_seconds": 45
    },
    "sources": {
        "winget": True,
        "chocolatey": True,
        "npm": True,
        "pnpm": True,
        "bun": True,
        "yarn": True,
        "pip": True,
        "path": True,
        "registry": True,
        "rust": True
    },
    "security": {
        "enabled": True,
        "auto_check": True,
        "severity_threshold": "medium"
    },
    "ui": {
        "theme": "default",
        "show_stats": True,
        "compact_view": False,
        "color_scheme": "vibrant"
    },
    "export": {
        "default_format": "json",
        "include_timestamp": True
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

## 🎨 UI Components

### Rich-Based Interface

The Python version features an enhanced UI with:

- **Banner Display** - Beautiful header with system information
- **Summary Panels** - Colorful statistics with emoji indicators
- **Data Tables** - Formatted tables with proper alignment and styling
- **Progress Bars** - Real-time progress with spinners and elapsed time
- **Security Alerts** - Highlighted vulnerability warnings

### Source Badges

Each source has a unique color:
- **Winget** - Blue
- **Chocolatey** - Yellow
- **NPM** - Red
- **PNPM** - Magenta
- **Bun** - Yellow
- **Yarn** - White
- **PIP** - Cyan
- **Rust** - Magenta
- **PATH** - Green
- **Registry** - Dim White

### Status Indicators

| Status | Emoji | Description |
|--------|-------|-------------|
| `UP_TO_DATE` | ✅ | Package is current |
| `UPDATE_AVAILABLE` | ⬆️ | New version available |
| `VULNERABLE` | 🔥 | Security vulnerability detected |
| `SECURITY_UPDATE_AVAILABLE` | 🔒 | Security patch available |
| `ERROR` | ❌ | Scan/update failed |
| `UNKNOWN` | ❓ | Status could not be determined |

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

### Key Classes

- **`SystemConfig`** - Configuration management with validation
- **`CacheManager`** - Cache validation and persistence
- **`PackageScanner`** - Parallel package scanning
- **`UpdateChecker`** - Batch update detection
- **`UpdateExecutor`** - Safe update execution
- **`UISystem`** - Rich terminal interface

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

All operations are logged to `~/.system_update/system.log`:
```python
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
```

---

## 🔧 Advanced Usage

### Custom Configuration

Edit `~/.system_update/config.json` to customize:

```json
{
  "performance": {
    "max_workers": 8,
    "timeout_seconds": 60
  },
  "cache": {
    "duration_hours": 4
  },
  "security": {
    "severity_threshold": "high"
  }
}
```

### Programmatic Usage

```python
from system_update import SystemUpdateApp, SystemConfig

# Initialize
config = SystemConfig()
app = SystemUpdateApp()

# Scan system
apps = app.scan_system(progress, source_filter=None)

# Check updates
updates = UpdateChecker.check_all_updates(apps, progress, task_id)

# Execute updates
UpdateExecutor.execute_updates(apps, dry_run=False)

# Export results
app.export_results(apps, "json", "report.json")
```

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

### Test Files

```
tests/
└── test_system_update.py    # Python tests (pytest)
```

---

## 📝 Requirements

### Python Dependencies

- **rich** - Terminal UI framework (auto-installed)

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

## 📄 License

This project is provided as-is for system administration and package management tasks.

---

## 🆕 Latest Changes (v2.7.0)
- **CVSS Score Display**: Show CVSS scores for vulnerabilities in security tables
- **Security Summary Stats**: Added detailed security summary with colored severity counts and affected package counts
- **Vulnerability History**: Implemented persistent vulnerability tracking over time in `vulnerability_history.json`
- **Enhanced CVE Details**: Added detailed vulnerability metadata including affected versions and published dates

---

## 🆕 Latest Changes (v2.6.0)
- **GitHub Advisory Database**: Added vulnerability scanning via GitHub Advisory API
- **Local Advisory Import**: Added support for custom vulnerability data from local JSON file (~/.system_update/advisories.json)

---

## 🆕 Latest Changes (v2.5.0)
- **NPM Audit Full Parse**: Enhanced npm vulnerability scanning to extract detailed advisory info from npm audit JSON output including via array details, advisoryUrl, fixAvailable, isDirect, and effects

---

## 🆕 Latest Changes (v2.4.0)
- **PyPI Security JSON**: Added vulnerability checking via PyPI JSON API for direct vulnerability data

---

## 🆕 Latest Changes (v2.3.0)
- **OSV API Integration**: Added Google's OSV vulnerability database support for all supported ecosystems
- **Extended vulnerability scanning**: Now checks npm, PyPI, crates.io, RubyGems, Go, CocoaPods, and Hex packages

---

## 🆕 Latest Changes (v2.2.0)
- **.NET Global Tools support**: Added .NET CLI tools scanning via `dotnet tool list -g`
- **Scoop support**: Added Scoop package manager support
- **AppX/Packaged Apps support**: Added Windows Store apps scanning via `Get-AppxPackage`
- **MSIX support**: Added MSIX packages scanning
- **New `--show-all` flag**: Show all packages including up-to-date ones (default shows only updates)

---

## 🆕 Latest Changes (v2.1.0)
- **Cargo crates.io API**: Now queries crates.io API directly instead of requiring cargo-install-update
- **Improved Rust scanning**: Better version comparison for Rust packages

Contributions and enhancements are always welcome!
