# System Update CLI

> 🚀 A powerful multi-language system update tool for Windows and beyond.

This repository contains a collection of system package management tools implemented in three different languages: **Node.js**, **Python**, and **PowerShell**. All three scripts provide a unified, comprehensive way to scan, check, and update software from multiple sources.

## 🌟 Common Features

Regardless of which script you choose, you get access to a rich set of shared features:

- **Multi-source Package Discovery**: Scan applications installed via Winget, Chocolatey, NPM, PNPM, Bun, Yarn, PIP, system PATH executables, and Windows Registry.
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

---

## 🚀 Quick Usage Examples

Regardless of the selected language, the core arguments remain highly consistent across the board:

```bash
# Run a full interactive scan
node system_update.js
python system_update.py
.\system_update.ps1

# Update everything without asking for confirmation
node system_update.js --update-all --yes

# Check for updates only (Dry Run)
python system_update.py --dry-run

# Export results to JSON
.\system_update.ps1 -Export json -Output report.json
```

## 📝 License

These tools are provided as-is for system administration and package management. Contributions and enhancements are always welcome!
