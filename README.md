# System Update CLI

> 🚀 A powerful system update tool for Windows.

A comprehensive Python-based system package management tool that scans, checks, and updates software from multiple sources.

## 🌟 Features

- **Multi-source Package Discovery**: Scan applications installed via Winget, Chocolatey, NPM, PNPM, Bun, Yarn, PIP, Scoop, system PATH executables, and Windows Registry.
- **Security Scanning**: Real-time vulnerability checking for NPM (`npm audit`) and PIP (`pip check`) packages.
- **Intelligent Caching**: 2-hour caching mechanism to drastically speed up repetitive runs.
- **Dry-run & Output Options**: Safely preview updates before applying them and export reports to JSON or CSV formats.
- **Rich Terminal UI**: Beautiful, colorful console output built with the `rich` library, featuring spinners, progress bars, and emoji indicators.

---

## 📋 Requirements

- **Python** 3.8 or higher
- **Rich library** (auto-installed on first run)
- **Windows 10/11** (primary platform)

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
| `--include <csv>` | Limit scan to specific sources (e.g., `winget,npm,pip`) |
| `--yes`, `-y` | Skip confirmation prompts |
| `--help`, `-h` | Show help message |
| `--show-all` | Show all packages (including up-to-date) |
| `--log` | Enable logging to file |
| `--debug` | Show all executed commands |

---

## 📊 Supported Sources

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
| Scoop | ✅ | ✅ | ❌ |

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

## 📝 License

This tool is provided as-is for system administration and package management.

---

## 🆕 Latest Changes (v2.8.0)
- **Python-only Repository**: Simplified to only Python implementation (removed Node.js and PowerShell scripts)
- **Repository Cleanup**: Removed all Node.js and PowerShell files, tests, and documentation

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
- **Improved output format**: "💾 Showing" line now appears after the package table
- **New "🎯 Found" message**: Clear indication of available updates count at the end

---

## 🆕 Latest Changes (v2.1.0)
- **Cargo crates.io API**: Now queries crates.io API directly instead of requiring cargo-install-update
- **Improved Rust scanning**: Better version comparison for Rust packages

Contributions and enhancements are always welcome!