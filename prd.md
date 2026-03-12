# Product Requirements Document: System Update CLI (`system-update`)

## 1. Product Overview
**System Update CLI** is a unified, cross-platform (optimized for Windows) command-line utility designed to aggregate, scan, and manage software updates across multiple package managers and system environments. It provides a "single pane of glass" for developers and system administrators to monitor the health, versioning, and security status of their installed applications and libraries.

## 2. Goals & Objectives
*   **Centralization:** Eliminate the need to manually run `npm outdated`, `pip list --outdated`, `winget upgrade`, etc., individually.
*   **Visibility:** Provide a clear, color-coded summary of what is installed and what needs updating.
*   **Security:** Proactively identify known vulnerabilities in package ecosystems (NPM, PIP) before they become issues.
*   **Efficiency:** Use parallel processing and caching to minimize the time required for system-wide scans.
*   **Automation-Friendly:** Support dry-runs, JSON/CSV exports, and non-interactive modes for CI/CD or scheduled tasks.

## 3. Target Audience
*   **Developers:** Managing global CLI tools (NPM, PNPM, Bun, Yarn).
*   **DevOps/SysAdmins:** Auditing workstation software versions and security patches.
*   **Power Users:** Keeping Windows applications (Winget, Chocolatey) and system binaries up to date via a single command.

## 4. Functional Requirements

### 4.1 Multi-Source Discovery
The system MUST support scanning the following sources:
*   **Native OS:** Windows Registry (Uninstall entries), Windows PATH (System binaries like git, node, rustc).
*   **OS Package Managers:** Winget, Chocolatey.
*   **Language Runtimes:** Node.js (NPM, PNPM, Yarn, Bun), Python (PIP).

### 4.2 Update Management
*   **Version Comparison:** The tool MUST compare installed versions against the latest available versions from upstream sources.
*   **Selective Updates:** Users MUST be able to update a single package, all packages from a specific source, or the entire system.
*   **Dry Run:** Users MUST be able to preview update commands without executing them.

### 4.3 Security Auditing
*   **Vulnerability Scanning:** The tool MUST integrate with `npm audit` and `pip check` to identify security risks.
*   **Severity Thresholds:** Users SHOULD be able to filter security alerts based on severity (Low, Medium, High, Critical).

### 4.4 Data Persistence & Performance
*   **Caching:** Scan results MUST be cached locally (default: 2 hours) to allow for near-instant subsequent lookups.
*   **Parallelism:** Scans across different sources MUST run in parallel to maximize CPU and network utilization.

### 4.5 Reporting & Export
*   **CLI Table:** A formatted, human-readable table showing Package, Source, Current Version, Latest Version, and Status.
*   **Export Formats:** Support for exporting full system snapshots to `JSON` and `CSV`.

## 5. Non-Functional Requirements
*   **Portability:** Written in Node.js to ensure easy installation via NPM or as a standalone script.
*   **Resilience:** The tool MUST NOT crash if a specific package manager (e.g., Chocolatey) is not installed; it should gracefully skip the source.
*   **UI/UX:** Use ANSI colors and Emojis to provide high-signal feedback in TTY environments, while falling back to plain text in non-TTY environments.
*   **Performance:** Total system scan (excluding updates) should ideally complete in under 60 seconds on average broadband.

## 6. Technical Specifications

### 6.1 Command Line Interface
| Option | Description |
| :--- | :--- |
| `--update-all` | Updates all outdated packages across all sources. |
| `--package <name>` | Target a specific package for update. |
| `--source <name>` | Filter scan/update to a specific manager (e.g., `npm`). |
| `--dry-run` | Log intended commands without running them. |
| `--export <format>` | Export data to `json` or `csv`. |
| `--yes / -y` | Skip confirmation prompts for automated workflows. |

### 6.2 Data Directory
By default, the application stores logs and cache in:
*   `$SYSTEM_UPDATE_HOME` (if set)
*   `~/.system_update` (Home directory)
*   `./.system_update` (Local fallback if home is unwritable)

## 7. Security Requirements
*   **No Elevated Defaults:** The script should run with user-level permissions and only request elevation via the underlying package manager (e.g., Winget UAC) when an update is triggered.
*   **Input Validation:** Package names and versions passed via CLI must be normalized to prevent command injection.

## 8. Roadmap & Future Enhancements
*   **GUI Wrapper:** A lightweight Electron or Tauri-based dashboard for non-CLI users.
*   **Auto-Fix Security:** Command to automatically apply "safe" security patches (semver minor/patch).
*   **Linux/macOS Optimization:** Expanded support for `brew`, `apt`, and `pacman`.
*   **Notification Integration:** Support for Desktop notifications or Webhooks when updates are found.
