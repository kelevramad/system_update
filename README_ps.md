# System Update PowerShell CLI

> 🚀 A powerful PowerShell-based system update tool (requires PowerShell 7+)

**Version:** 2.6.0
**Runtime:** PowerShell 7+
**Platform:** Windows

> **Note:** This repository also includes Node.js (`system_update.js`) and Python (`system_update.py`) implementations. See [README_js.md](README_js.md) and [README_py.md](README_py.md).

---

## 📋 Overview

System Update PowerShell CLI is a comprehensive package management tool built entirely in PowerShell. It scans, checks, and updates software from multiple sources including Winget, Chocolatey, NPM, PNPM, Bun, Yarn, PIP, Rust, and system PATH executables.

### ✨ Key Features

- **Multi-source package discovery** - Scan Winget, Chocolatey, NPM, PNPM, Bun, Yarn, PIP, Rust, PATH, and Windows Registry
- **Security vulnerability scanning** - Real-time security checks for NPM and PIP packages
- **Native PowerShell implementation** - No external dependencies required
- **Advanced command handling** - Proper handling of .ps1, .cmd, .bat, and .exe executables
- **Smart caching** - 2-hour cache duration for faster subsequent runs
- **Flexible export** - Export results to JSON or CSV formats
- **Dry-run support** - Preview updates before applying them
- **Beautiful CLI output** - Colorful, emoji-rich terminal interface with progress bars

---

## 🚀 Quick Start

### Prerequisites

- **PowerShell 7.0** or higher (PowerShell Core)
- **Windows 10/11**
- Optional package managers: Winget, Chocolatey, NPM, PNPM, Bun, Yarn, PIP

### Check PowerShell Version

```powershell
# Verify PowerShell version
$PSVersionTable.PSVersion

# Must be 7.0 or higher
```

### Installation

No installation required. The script is self-contained:

```powershell
# Navigate to the script directory
cd C:\Git\System_Update

# Set execution policy if needed (run as Administrator)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Basic Usage

```powershell
# Run a full system scan
.\system_update.ps1

# Update all packages automatically
.\system_update.ps1 -UpdateAll -Yes

# Check for updates without installing
.\system_update.ps1 -DryRun

# Export scan results to JSON
.\system_update.ps1 -Export json -Output report.json
```

---

## 📖 Command Reference

### Parameters

| Parameter | Description |
|-----------|-------------|
| `-UpdateAll` | Update every package with available updates |
| `-UpdateSource <source>` | Update all packages from a specific source |
| `-Package <name>` | Update a specific package by name |
| `-Version <ver>` | Target version (use with `-Package`) |
| `-Source <source>` | Filter by source (winget\|chocolatey\|npm\|pnpm\|bun\|yarn\|pip\|path\|rust\|registry) |
| `-DryRun` | Show planned updates without executing |
| `-NoCache` | Force fresh scan (ignore cache) |
| `-ClearCache` | Remove cache file and exit |
| `-Export <json\|csv>` | Export scan results to file |
| `-Output <file>` | Output path for export |
| `-Include <csv>` | Limit scan to specific sources (e.g., `winget,npm`) |
| `-Yes` | Skip confirmation prompts |
| `-Help` | Show help message |
| `-ShowAll` | Show all packages (including up-to-date) |

### Examples

```powershell
# Full system scan with interactive updates
.\system_update.ps1

# Update all packages without confirmation
.\system_update.ps1 -UpdateAll -Yes

# Update only Winget packages
.\system_update.ps1 -UpdateSource winget -Yes

# Update only Rust packages
.\system_update.ps1 -UpdateSource rust -Yes

# Update a specific package
.\system_update.ps1 -Package git -Source chocolatey

# Dry run to preview updates
.\system_update.ps1 -DryRun

# Scan only specific sources
.\system_update.ps1 -Include winget,npm,pip

# Export results to JSON
.\system_update.ps1 -Export json -Output updates.json

# Export results to CSV
.\system_update.ps1 -Export csv -Output updates.csv

# Force fresh scan and export
.\system_update.ps1 -NoCache -Export json

# Show all packages (including up-to-date)
.\system_update.ps1 -ShowAll
```

---

## 🔧 Configuration

### Default Settings

The script uses the following built-in defaults:

```powershell
$CFG_CACHE_HOURS = 2          # Cache duration in hours
$CFG_TIMEOUT = 45             # Command timeout in seconds
$CFG_SECURITY = $true         # Enable security scanning
$CFG_SEVERITY = 'medium'      # Vulnerability severity threshold
```

### Data Directory

- **Default:** `~/.system_update` (user's home directory)
- **Custom:** Set `SYSTEM_UPDATE_HOME` environment variable

### Files

- **Cache File:** `<DATA_DIR>/cache.json`
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

Vulnerabilities are filtered by severity:
- **Critical** - Highest priority
- **High** - Serious security risk
- **Medium** - Moderate risk (default threshold)
- **Low** - Minor issues

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
- **Bun** - Yellow
- **Yarn** - White
- **PIP** - Cyan
- **Rust** - Magenta
- **PATH** - Green
- **Registry** - Gray

---

## 📤 Export Formats

### JSON Export

```json
{
  "scanTime": "2026-02-26T10:30:00+00:00",
  "totalApps": 45,
  "apps": [
    {
      "Name": "git",
      "Source": "winget",
      "Version": "2.40.1",
      "LatestVersion": "2.44.0",
      "Status": "update_available",
      "AppId": "Git.Git"
    }
  ]
}
```

### CSV Export

```csv
Name,Source,Version,LatestVersion,Status,AppId
git,winget,2.40.1,2.44.0,update_available,Git.Git
node,npm,18.16.0,20.11.0,update_available,node
```

---

## 🏗️ Advanced Features

### Command Execution Engine

The PowerShell version includes a sophisticated command execution system that properly handles different executable types:

- **ExternalScript (.ps1)** - Routes through `pwsh -NonInteractive -File`
- **Batch scripts (.cmd/.bat)** - Routes through `cmd.exe /d /c`
- **Native executables (.exe)** - Direct ProcessStartInfo execution
- **AppX aliases** - Resolves and executes properly

### Invoke-Cmd

The main command execution function handles all Windows executable types with proper encoding:

```powershell
function Invoke-Cmd {
    param([string]$Cmd, [string[]]$CmdArgs = @(), [int]$TimeoutSec = $CFG_TIMEOUT, [switch]$AllowFail, [switch]$Stderr)
    # Handles .ps1, .cmd, .bat, .exe with proper routing
}
```

### Invoke-NativeCmd

For encoding-sensitive commands (like Winget), the script uses background jobs with proper UTF-8 encoding:

```powershell
function Invoke-NativeCmd {
    param(
        [string]$Cmd,
        [string[]]$CmdArgs = @(),
        [int]$TimeoutSec = $CFG_TIMEOUT,
        [switch]$AllowFail,
        [switch]$Stderr
    )
    # Executes via PowerShell job with UTF-8 encoding
}
```

### Unicode Emoji Support

Uses `ConvertFromUtf32` for proper emoji rendering across all PowerShell versions:

```powershell
function E([string]$n) {
    switch ($n) {
        'rocket' { [char]::ConvertFromUtf32(0x1F680) }
        'package' { [char]::ConvertFromUtf32(0x1F4E6) }
        # ... more emojis
    }
}
```

---

## 🛠️ Troubleshooting

### Common Issues

**Execution Policy Error:**
```powershell
# Set execution policy for current user
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**PowerShell Version Too Low:**
```powershell
# Check version
$PSVersionTable.PSVersion

# PowerShell 7+ required - download from:
# https://aka.ms/powershell
```

**Cache Permission Errors:**
The script automatically handles permission issues and falls back gracefully.

**Command Timeouts:**
Increase `$CFG_TIMEOUT` at the top of the script for slower systems.

**Rust Updates Not Working:**
Ensure `cargo-update` is installed: `cargo install cargo-update`

### Logging

All operations are logged to `<DATA_DIR>/system.log`:
```powershell
function Write-Log([string]$Msg) {
    "$(Get-Date -f 'o') $Msg" | Add-Content $LOG_FILE -Encoding UTF8
}
```

---

## 🔧 Advanced Usage

### Custom Configuration

Edit the script's configuration section:

```powershell
$CFG_CACHE_HOURS = 4          # Extended cache duration
$CFG_TIMEOUT = 60             # Longer timeout
$CFG_SECURITY = $true         # Keep security enabled
$CFG_SEVERITY = 'high'        # Only high/critical vulnerabilities
```

### Pipeline Integration

The script supports PowerShell pipeline operations:

```powershell
# Export and process results
.\system_update.ps1 -Export json | ConvertFrom-Json | 
    Where-Object { $_.Status -eq 'update_available' } |
    Export-Csv updates.csv -NoTypeInformation
```

### Scheduled Tasks

Create a scheduled task for regular scans:

```powershell
$action = New-ScheduledTaskAction -Execute "pwsh" `
    -Argument "-File C:\Git\System_Update\system_update.ps1 -Export json"
$trigger = New-ScheduledTaskTrigger -Daily -At 9am
Register-ScheduledTask -TaskName "SystemUpdate" `
    -Action $action -Trigger $trigger -RunLevel Highest
```

---

## 🧪 Testing

This project includes a comprehensive test suite using Pester. Tests are located in the `tests/` directory.

### Run Tests

```powershell
# Run Pester tests
pwsh -File ./tests/test_system_update.ps1

# Or if Pester is installed
Invoke-Pester ./tests/*.ps1
```

### Test Files

```
tests/
└── test_system_update.ps1    # PowerShell tests (Pester)
```

---

## 📝 Requirements

### System Requirements

- **PowerShell 7.0+** - Required (PowerShell Core)
- **Windows 10/11** - Primary platform
- **.NET 6.0+** - Required for PowerShell 7+
- **Package Managers** - Optional, based on sources used

### Optional Package Managers

| Package Manager | Install Command |
|-----------------|-----------------|
| Winget | Built into Windows 10/11 |
| Chocolatey | `iwr https://chocolatey.org/install.ps1 -UseBasicParsing \| iex` |
| NPM | Included with Node.js |
| PNPM | `npm install -g pnpm` |
| Bun | `powershell -c "iwr https://bun.sh/install.ps1 -useb \| iex"` |
| Yarn | `npm install -g yarn` |
| PIP | Included with Python |
| Rust | `winget install Rustlang.Rust.MSVC` (then `cargo install cargo-update`) |

---

## 🤝 Contributing

Contributions are welcome! Please ensure:
- PowerShell 7+ compatibility is maintained
- StrictMode and ErrorActionPreference are respected
- Unicode emoji rendering works on all terminals
- Documentation is updated

---

## 📞 Support

For issues or questions:
1. Check the log file at `~/.system_update/system.log`
2. Run with `-NoCache` to rule out cache issues
3. Verify PowerShell version: `$PSVersionTable.PSVersion`
4. Ensure package managers are accessible

---

## 📄 License

This project is provided as-is for system administration and package management tasks.

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
- **New `-ShowAll` flag**: Show all packages including up-to-date ones (default shows only updates)

---

## 🆕 Latest Changes (v2.1.0)
- **Cargo crates.io API**: Now queries crates.io API directly instead of requiring cargo-install-update
- **Improved Rust scanning**: Better version comparison for Rust packages

Contributions and enhancements are always welcome!
