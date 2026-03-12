# AGENTS.md - Development Guidelines for Agents

This document provides guidelines for agents working on the System Update CLI project.

## Project Overview

The project provides multi-source package management tools in three implementations:
- **Node.js** (`system_update.js`) - JavaScript/Node.js CLI
- **Python** (`system_update.py`) - Python CLI with Rich UI
- **PowerShell** (`system_update.ps1`) - Native Windows PowerShell CLI

All three implementations share the same features: multi-source package scanning, security vulnerability checking, caching, and export capabilities.

## Supported Sources

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

## Build/Lint/Test Commands

### Node.js (`system_update.js`)

```bash
# Run the CLI
node system_update.js

# Run with npm
npm start

# Show help
npm run help
```

**Linting**: The project uses ESLint patterns. Run manually if installed:
```bash
npx eslint system_update.js
```

### Python (`system_update.py`)

```bash
# Run the CLI
python system_update.py

# With venv activated
.venv\Scripts\python.exe system_update.py

# Install dependencies manually
pip install rich

# Run ruff linter (if available)
ruff check system_update.py
```

**Testing Single Test**: No formal test suite exists. Test manually by running:
```bash
python -c "import system_update; print('Module loads OK')"
```

### PowerShell (`system_update.ps1`)

```bash
# Run the CLI
.\system_update.ps1

# With explicit pwsh
pwsh -File system_update.ps1
```

### Common Options (shared across all implementations)

- `--update-all` - Update all packages with available updates
- `--update-source <source>` - Update packages from specific source
- `--package <name>` - Update specific package
- `--dry-run` - Preview without executing
- `--no-cache` - Force fresh scan (bypass cache)
- `--clear-cache` - Remove cache file
- `--export <json|csv>` - Export results
- `--output <file>` - Output path for export
- `--include <csv>` - Limit scan sources
- `--yes, -y` - Skip confirmation prompts
- `--help, -h` - Show help

---

## Code Style Guidelines

### JavaScript (`system_update.js`)

**General**
- Use `'use strict'` at the top of files
- Use ES6+ features: const/let, arrow functions, async/await, template literals
- Use named exports/const for modules
- File naming: lowercase with underscores `system_update.js`

**Imports**
- Use node: prefix for built-in modules: `const fs = require('node:fs/promises');`
- Group imports: built-ins first, then external

**Formatting**
- Indentation: 2 spaces
- Line length: Soft limit ~100 characters
- Use semicolons for statement termination
- Use `===` for comparisons (no ==)
- Trailing commas in multi-line objects/arrays

**Naming Conventions**
- Variables/functions: camelCase `const runCommand = ...`
- Constants: UPPER_SNAKE_CASE `const VERSION = '1.0.0'`
- Objects/enums: PascalCase `const Status = Object.freeze({...})`

**Types**
- Use JSDoc comments for complex functions
- Primitive wrappers (String, Number) are avoided; use literal forms

**Error Handling**
- Use try/catch with async/await
- Log errors but don't break CLI flow
- Never throw unhandled errors to top level
- Use `allowFailure: true` option for optional commands

**Example Pattern**:
```javascript
async function fetchJson(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': 'SystemUpdateCLI' } }, (res) => {
      if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode}`));
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch (err) { reject(err); }
      });
    }).on('error', reject);
  });
}
```

---

### Python (`system_update.py`)

**General**
- Use Python 3.8+ syntax
- Use `dataclasses` for structured data models
- Use `Enum` for status enumerations
- Use type hints where beneficial

**Imports**
- Standard library first, then third-party
- Group by: stdlib, third-party, local
- Use explicit imports

**Formatting**
- Indentation: 4 spaces (PEP 8)
- Line length: 100 characters max (Black-compatible)
- Use Black formatting if available

**Naming Conventions**
- Variables/functions: snake_case `def run_command(...)`
- Classes: PascalCase `class UpdateChecker:`
- Constants: UPPER_SNAKE_CASE `VERSION = "5.0.0"`
- Private methods: prefix with underscore `_private_method()`

**Types**
- Use type hints: `def func(arg: str) -> List[AppInfo]:`
- Use Optional for nullable types: `Optional[str]`
- Use Union where needed: `Union[str, None]`

**Error Handling**
- Use try/except with specific exceptions
- Log warnings for non-critical failures
- Never let exceptions crash CLI unexpectedly

**Example Pattern**:
```python
def run_command(cmd: List[str], timeout: int = 45, allow_failure: bool = False) -> Optional[str]:
    """Execute command with enhanced error handling and timeout."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            encoding="utf-8",
            errors="ignore",
            timeout=timeout,
        )
        if result.returncode != 0 and not allow_failure:
            logger.debug(f"Command exited {result.returncode}: {' '.join(cmd)}")
            return None
        return result.stdout.strip() or None
    except subprocess.TimeoutExpired:
        logger.warning(f"Command timed out: {' '.join(cmd)}")
        return None
```

---

### PowerShell (`system_update.ps1`)

**General**
- Use PowerShell 7+ features
- Prefer script-scoped variables over global
- Use strict mode: `Set-StrictMode -Version Latest`

**Formatting**
- Indentation: 4 spaces
- Cmdlets: Verb-Noun format
- Line length: ~100 characters

**Naming**
- Variables: $camelCase
- Functions: Verb-Noun (Get- packages, Update-App)
- Constants: $script:CONSTANT or uppercase

---

## Common Patterns Across All Implementations

### Command Execution
- Always use timeouts (default 45 seconds)
- Handle missing commands gracefully
- Normalize paths for Windows compatibility
- Use `allowFailure` for optional commands

### Caching
- Default cache duration: 2 hours
- Store in `~/.system_update/cache.json`
- Fallback to local `.system_update/` directory on permission errors
- Validate cache timestamp before use

### Status Tracking
- Use consistent status enums: UP_TO_DATE, UPDATE_AVAILABLE, UNKNOWN, ERROR, VULNERABLE
- Set appropriate status after each operation

### UI/Output
- Use colors sparingly for emphasis
- Show progress bars for long operations
- Provide summary statistics at end
- Support JSON/CSV export

---

## Key Files

| File | Description |
|------|-------------|
| `system_update.js` | Node.js implementation |
| `system_update.py` | Python implementation |
| `system_update.ps1` | PowerShell implementation |
| `README.md` | Main documentation |
| `README_js.md` | Node.js-specific docs |
| `README_py.md` | Python-specific docs |
| `README_ps.md` | PowerShell-specific docs |
| `prd.md` | Product requirements |
| `PRD_qwen.md` | Alternative requirements |

---

## Development Notes

- This project has **no formal test suite** - test manually
- The three implementations should remain **feature-equivalent**
- When adding features, update all three implementations
- Use consistent naming for package sources (lowercase in JS, PascalCase in Python)
- Consider cross-referencing JavaScript logic when implementing Python features
