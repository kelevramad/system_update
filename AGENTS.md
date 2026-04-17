# AGENTS.md - System Update CLI

## Project Overview

Three implementations of the same tool (cross-platform package manager scanner/updater):

| File | Language | Version | Requirements |
|------|----------|---------|---------------|
| `system_update.js` | Node.js | v2.7.0 | Node 16+ |
| `system_update.py` | Python | v2.7.0 | Python 3.8+, `rich` library |
| `system_update.ps1` | PowerShell | v2.7.0 | PowerShell 7+ (zero dep) |

## Project Structure

This repository contains three top-level CLI implementations and shared tests:

```
system_update.js      # Node.js implementation
system_update.py      # Python implementation
system_update.ps1     # PowerShell implementation
tests/                # Consolidated test directory
├── test_system_update.py         # Python tests (pytest)
├── system_update_cli.test.js    # Node.js tests (native --test runner)
└── test_system_update.ps1        # PowerShell tests (Pester)
pyproject.toml        # Python project config (pytest, ruff, taskipy)
package.json          # Node.js project config (c8, test scripts)
```

## Running the Tool

```bash
# Node.js
node system_update.js

# Python
python system_update.py

# PowerShell
.\system_update.ps1
```

## Key CLI Options

All implementations share similar flags:

- `--update-all --yes` - Update everything without prompts
- `--dry-run` - Preview updates without executing
- `--no-cache` - Force fresh scan (bypass 2-hour cache)
- `--clear-cache` - Remove cache and exit
- `--include winget,npm,pip` - Scan specific sources only
- `--export json --output file.json` - Export results
- `--show-all` - Show all packages (not just updates)
- `--log` - Enable logging to file
- `--debug` - Show executed commands

## Important Details

- **Default cache duration**: 2 hours
- **Data directory**: `~/.system_update/` (configurable via `SYSTEM_UPDATE_HOME`)
- **Security scanning**: Runs `npm audit`, `pip-audit`, OSV, GitHub Advisory, PyPI, and Local advisories automatically. Displays CVSS scores and tracks history in `vulnerability_history.json`.
- **Supported sources**: Winget, Chocolatey, NPM, PNPM, Bun, Yarn, PIP, Rust, PATH, Registry, Scoop

---

## Build, Test, and Development Commands

Use the toolchain that matches the implementation you are changing.

### Python

```bash
uv sync --all-extras --dev  # Install dependencies from pyproject.toml
uv run pytest               # Run Python test suite
uv run pytest --cov=system_update --cov-report=term-missing  # With coverage
uv run ruff check .         # Lint Python files
uv run ruff format .        # Format Python files
uv run task test            # Run tests via taskipy
```

### Node.js

```bash
npm install                 # Install dependencies from package.json
npm run test               # Run Node test suite (node --test)
npm run coverage           # Collect coverage via c8
npm run test:all           # Run tests + coverage
```

### PowerShell

```bash
pwsh -File ./tests/test_system_update.ps1   # Run Pester tests
Invoke-Pester ./tests/*.ps1                  # If Pester v5+ installed
```

---

## Coding Style & Naming Conventions

### Python
- Follow Ruff settings in `pyproject.toml`: 100-character line length, single quotes
- Tests and functions use `snake_case`; classes use `PascalCase`
- Use `dataclasses` for data models

### JavaScript
- Use `const` and 2-space indentation
- Match existing file style in `system_update.js`
- Tests use semicolons

### PowerShell
- Use PascalCase for functions and variables
- Follow PowerShell best practices
- Use strict mode: `Set-StrictMode -Version Latest`

### Test Naming
Name tests after the behavior they validate, for example:
- `test_include_winget_scans_winget_source`
- `test_export_json_creates_file`
- `--clear-cache removes cache`

---

## Testing Guidelines

Add or update tests for every user-visible CLI change:

1. **Scanner tests** - Test each source (winget, npm, pip, etc.)
2. **Export tests** - Test JSON and CSV export
3. **Flag tests** - Test dry-run, show-all, cache flags
4. **Error handling** - Test unknown sources, invalid arguments

**Before merging:**
- Run Python tests: `uv run pytest`
- Run Node tests: `npm run test`
- Run PowerShell tests: `pwsh -File ./tests/test_system_update.ps1`

**Coverage:**
- Python: `pytest --cov=system_update` (configured in pyproject.toml)
- Node.js: `npm run coverage` (uses c8)

---

## Important Notes

### No Build Required
This is a standalone CLI tool - no build or lint commands. Just run the scripts directly.

### Cache Behavior
- Cache is stored in `~/.system_update/cache.json`
- Duration: 2 hours (configurable)
- Use `--no-cache` to force fresh scan
- Use `--clear-cache` to remove cache file

### Security Scanning
- NPM: Runs `npm audit` automatically
- PIP: Runs `pip check` automatically
- Can be disabled via config

---

## Commit & Pull Request Guidelines

Follow Conventional Commit prefixes:

- `feat:` - New feature (e.g., `feat: add scoop support`)
- `fix:` - Bug fix (e.g., `fix: resolve winget parsing error`)
- `test:` - Test changes (e.g., `test: add npm export tests`)
- `docs:` - Documentation (e.g., `docs: update README`)
- `chore:` - Maintenance (e.g., `chore: update dependencies`)

Keep subjects specific, for example:
- `feat: add hidden volume support` (not `feat: add more features`)
- `fix: resolve json export encoding` (not `fix: fix bugs`)

Pull requests should explain:
- The user-facing change
- Test commands you ran
- Any format or compatibility impact

Note: If the user says "pull", they usually mean to create a Pull Request, not execute `git pull`. 

---

## Version Updates

When updating version numbers, update ALL of these locations to match:

1. **Node.js**: Update `VERSION` constant in `system_update.js` (line ~36)
2. **Python**: Update `Version:` in docstring header of `system_update.py` (line 6)
3. **PowerShell**: Update `$VER` in `system_update.ps1` (line ~150)
4. **pyproject.toml**: Update `version` in `[project]` section (line 3)
5. **README files**: Update version in headers AND "Latest Changes" sections in ALL README*.md files
6. **ENHANCEMENT_PLAN.md**: Update version in Feature Checklist footer
7. **PRD.md**: Update document version in header AND "Latest Changes" sections
8. **AGENTS.md**: Update version in Project Overview table if needed

### Version History in READMEs

When updating the "Latest Changes" section in README files, preserve the complete version history by:
- Moving the previous version's content to a new section below (e.g., `## 🆕 Latest Changes (v2.1.0)`)
- Adding the new version content to the top `## 🆕 Latest Changes (vX.X.X)` section
- Include a brief description of what changed in each version

Example format:
```markdown
## 🆕 Latest Changes (v2.2.0)
- **Feature A**: Description of new feature
- **Feature B**: Description of another new feature

---

## 🆕 Latest Changes (v2.1.0)
- **Feature X**: Description of previous feature
- **Bug Fix**: Description of fix
```

---

## Release Automation Guidelines

When creating GitHub releases, always follow this structure:

### 1. Title:
- Format: `v<version> - <short summary>`

### 2. Overview:
- 1–2 sentences explaining the purpose of this release.

### 3. 🚀 Features
- List new features with concise bullet points.

### 4. 🛠 Improvements
- Enhancements or optimizations.

### 5. 🐛 Bug Fixes
- Clearly describe fixes.

### 6. 🔐 Security
- Mention any security updates.

### 7. ⚠️ Breaking Changes (if any)
- Clearly warn users.

### 8. 📦 CLI Usage (if relevant)
- Show updated commands or examples.

### 9. 📊 Full Changelog
- Format: `<previous_version>...<current_version>`

### 10. 👥 Contributors (optional)

**Rules:**
- Keep it concise but professional.
- Use emojis for sections.
- Use markdown formatting.
- Always maintain the same structure.
- Never omit sections (write "None" if empty).

Use `gh release create v<version> --title "v<version> - <summary>" --notes "<markdown>"` to create releases.