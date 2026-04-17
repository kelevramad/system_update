# System Update CLI

> 🚀 A powerful multi-language system update tool for Windows and beyond.

This repository contains a collection of system package management tools implemented in three different languages: **Node.js**, **Python**, and **PowerShell**. All three scripts provide a unified, comprehensive way to scan, check, and update software from multiple sources.

## 🌟 Common Features

Regardless of which script you choose, you get access to a rich set of shared features:

- **Multi-source Package Discovery**: Scan applications installed via Winget, Chocolatey, NPM, PNPM, Bun, Yarn, PIP, Scoop, system PATH executables, and Windows Registry.
- **Security Scanning**: Real-time vulnerability checking for NPM (`npm audit`) and PIP (`pip check`) packages.
- **Intelligent Caching**: 2-hour caching mechanism to drastically speed up repetitive runs.
- **Dry-run & Output Options**: Safely preview updates before applying them and export reports to JSON or CSV formats.
- **Rich Terminal UI**: Beautiful, colorful console output with spinners, progress bars, and emoji indicators.

---

## 💻 The Scripts

Choose the implementation that best fits your environment and preferences:

### 1. 🟢 Node.js (`system_update.js`)
A highly optimized JavaScript implementation natively leveraging the Node.js asynchronous architecture for parallel scanning.
- **Requirements**: Node.js 16.x+
- **Usage**: `node system_update.js`
- **Documentation**: [README_js.md](README_js.md)

### 2. 🐍 Python (`system_update.py`)
A modular and sophisticated Python script featuring an advanced UI built with the `rich` library. It uses ThreadPoolExecutor for highly concurrent processing.
- **Requirements**: Python 3.8+, `rich` library
- **Usage**: `python system_update.py`
- **Documentation**: [README_py.md](README_py.md)

### 3. 🖥️ PowerShell (`system_update.ps1`)
A native Windows implementation requiring ZERO external dependencies. Built for PowerShell 7+, it includes robust handling of command execution and native APIs.
- **Requirements**: PowerShell 7.0+
- **Usage**: `.\system_update.ps1`
- **Documentation**: [README_ps.md](README_ps.md)

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

This project follows the same testing conventions as crypt_tools and includes a comprehensive test suite for validating all three implementations. Tests are located in the `tests/` directory.

### Run All Tests

```bash
# Node.js tests with coverage
npm run test
npm run coverage
npm run test:all        # Runs tests + coverage

# Python tests with coverage (using uv)
uv sync --all-extras --dev  # Install dependencies
uv run pytest           # Run tests
uv run pytest --cov=system_update --cov-report=term-missing  # With coverage

# PowerShell tests (Pester framework)
pwsh -File ./tests/test_system_update.ps1   # Run Pester tests directly
Invoke-Pester ./tests/*.ps1            # If Pester installed and v5+
```

### Test Coverage

| Feature | Node.js | Python | PowerShell |
|---------|---------|--------|------------|
| Help display | ✅ | ✅ | ✅ |
| Scanner functions | ✅ | ✅ | ✅ |
| Export (JSON/CSV) | ✅ | ✅ | ✅ |
| Dry-run mode | ✅ | ✅ | ✅ |
| Cache system | ✅ | ✅ | ✅ |
| --show-all flag | ✅ | ✅ | ✅ |
| --clear-cache | ✅ | ✅ | ✅ |
| --log/--debug flags | ✅ | ✅ | ✅ |

### Test Files

```
tests/
├── test_system_update.py         # Python tests (pytest)
├── system_update_cli.test.js    # Node.js tests (native --test runner)
└── test_system_update.ps1        # PowerShell tests (Pester)
```

---

## 📝 License

These tools are provided as-is for system administration and package management.

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
