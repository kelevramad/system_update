# System Update CLI - Enhancement Plan

Windows-only improvement roadmap for `system_update.py` (Python implementation).

---

## Index

1. [Package Manager Expansion (Windows)](#1-package-manager-expansion)
2. [Security Enhancements](#2-security-enhancements)
3. [User Experience Improvements](#3-user-experience-improvements)
4. [Configuration System](#4-configuration-system)
5. [Data and Export Enhancements](#5-data-and-export-enhancements)
6. [Advanced Features](#6-advanced-features)
7. [Performance Optimizations](#7-performance-optimizations)
8. [Windows-Specific Enhancements](#8-windows-specific-enhancements)
9. [Implementation Roadmap](#9-implementation-roadmap)

---

## 1. Package Manager Expansion (Windows)

### 1.1 Additional Windows Package Sources

| # | Source | Command | Description | Implementation File |
|---|--------|---------|-------------|-------------------|
| 1.1.1 | Scoop | `scoop list` + `scoop status` | Scan Scoop packages | Python | ✅ |
| 1.1.2 | .NET Global Tools | `dotnet tool list -g` | Scan .NET CLI tools | Python | ✅ |
| 1.1.3 | Cargo crates.io | Query crates.io API | Check Rust crate updates | Python | ✅ |

### 1.2 Windows Store Apps

| # | Feature | Command | Description | Implementation File |
|---|---------|----------|-------------|---------------------|
| 1.2.1 | AppX/Packaged Apps | `Get-AppxPackage` | Scan Windows Store apps | Python | ✅ |
| 1.2.2 | MSIX Scanning | Query MSIX packages | Scan MSIX installations | Python | ✅ |

---

## 2. Security Enhancements

### 2.1 Extended Vulnerability Scanning

| # | Feature | Description | Implementation File | Status |
|---|---------|-------------|---------------------|--------|
| 2.1.1 | OSV (Open Source Vulnerabilities) API | Query Google's OSV for all ecosystems | Python | ✅ |
| 2.1.2 | PyPI Security JSON | Use PyPI JSON API for vulnerability data | Python | ✅ |
| 2.1.3 | NPM Audit Full Parse | Parse full audit JSON, not just summary | Python | ✅ |
| 2.1.4 | GitHub Advisory Database | Query GitHub advisories via API | Python | ✅ |
| 2.1.5 | Local Advisory Import | Support custom vulnerability data | Python | ✅ |

### 2.2 Security Reporting

| # | Feature | Description | Implementation File | Status |
|---|---------|-------------|---------------------|--------|
| 2.2.1 | CVSS Score Display | Show severity scores | Python | ✅ |
| 2.2.2 | CVE Details Table | Full CVE information display | Python | ✅ |
| 2.2.3 | Vulnerability History | Track vulnerabilities over time | Python | ✅ |
| 2.2.4 | Security Summary Stats | Critical/High/Medium/Low counts | Python | ✅ |

### 2.3 Security Notifications

| # | Feature | Description | Implementation File |
|---|---------|-------------|---------------------|
| 2.3.1 | Critical Alert Priority | Highlight critical vulnerabilities | Python |
| 2.3.2 | Security Update Auto-Priority | Auto-update vulnerable packages first | Python |

---

## 3. User Experience Improvements

### 3.1 Interactive TUI

| # | Feature | Description | Implementation File |
|---|---------|-------------|---------------------|
| 3.1.1 | Fuzzy Search | Search packages by partial name match | Python |
| 3.1.2 | Package Multi-Select | Select multiple packages for batch update | Python |
| 3.1.3 | Keyboard Navigation | Arrow keys to navigate packages | Python |
| 3.1.4 | Real-time Filtering | Filter as you type | Python |
| 3.1.5 | Preview Changes | Show what will happen before applying | Python |

### 3.2 Progress Enhancements

| # | Feature | Description | Implementation File |
|---|---------|-------------|---------------------|
| 3.2.1 | Scan Checkpointing | Save progress every N packages | Python |
| 3.2.2 | Resume Interrupted Scan | Continue from last checkpoint | Python |
| 3.2.3 | ETA Display | Show estimated time remaining | Python |
| 3.2.4 | Per-Source Progress | Progress for each source independently | Python |

### 3.3 Better Error Handling

| # | Feature | Description | Implementation File |
|---|---------|-------------|---------------------|
| 3.3.1 | Error Classification | Categorize errors (not_found, timeout, etc.) | Python |
| 3.3.2 | Recovery Suggestions | Show how to fix each error type | Python |
| 3.3.3 | Verbose Mode | `--verbose` for detailed debugging | Python |
| 3.3.4 | Error Log File | Separate log file for errors | Python |

### 3.4 Notification System

| # | Feature | Description | Implementation File |
|---|---------|-------------|---------------------|
| 3.4.1 | System Notifications | Native Windows toast notifications | Python |
| 3.4.2 | Email Alerts | SMTP integration for email | Python |
| 3.4.3 | Webhook Notifications | HTTP POST to URL | Python |
| 3.4.4 | Custom Script Hooks | Execute user-defined scripts | Python |

### 3.5 UI Improvements

| # | Feature | Description | Implementation File |
|---|---------|-------------|---------------------|
| 3.5.1 | Custom Theme | User-defined color schemes | Python only |
| 3.5.2 | More Display Formats | Compact/verbose/JSON modes | All three |
| 3.5.3 | Source Icons | Custom icons per package manager | All three |
| 3.5.4 | Status Icons | Custom status indicators | All three |

---

## 4. Configuration System

### 4.1 Config File

| # | Feature | Description | Implementation File |
|---|---------|-------------|---------------------|
| 4.1.1 | JSON Config File | Persistent configuration | All three |
| 4.1.2 | YAML Config Support | Alternative to JSON | Python only |
| 4.1.3 | Config Validation | Validate config on load | All three |
| 4.1.4 | Config Migration | Auto-upgrade old configs | All three |

### 4.2 Environment Variables

| # | Variable | Description | Default |
|---|----------|-------------|---------|
| 4.2.1 | `SYSTEM_UPDATE_SOURCES` | Comma-separated enabled sources | All |
| 4.2.2 | `SYSTEM_UPDATE_TIMEOUT` | Override default timeout | 45s |
| 4.2.3 | `SYSTEM_UPDATE_WORKERS` | Parallel worker count | 6 |
| 4.2.4 | `SYSTEM_UPDATE_EXCLUDE` | Excluded packages (glob) | None |
| 4.2.5 | `SYSTEM_UPDATE_LOG_LEVEL` | Debug/Info/Warning/Error | Warning |

### 4.3 Profile System

| # | Feature | Description | Implementation File |
|---|---------|-------------|---------------------|
| 4.3.1 | Named Profiles | Multiple config profiles | All three |
| 4.3.2 | Profile Switching | `--profile dev` flag | All three |
| 4.3.3 | Profile Export/Import | Share configs between machines | All three |

---

## 5. Data and Export Enhancements

### 5.1 Historical Tracking

| # | Feature | Description | Implementation File |
|---|---------|-------------|---------------------|
| 5.1.1 | SQLite Database | Store scan history | All three |
| 5.1.2 | Version History | Track package versions over time | All three |
| 5.1.3 | Trend Analysis | Show update trends | All three |
| 5.1.4 | Report Generation | Periodic summary reports | All three |

### 5.2 Export Formats

| # | Format | Use Case | Implementation File |
|---|--------|---------|----------------|
| 5.2.1 | HTML Report | Email/sharing with styling | All three |
| 5.2.2 | XML | Enterprise integration | All three |
| 5.2.3 | Markdown | GitHub-compatible | All three |
| 5.2.4 | Diff | Version-to-version | All three |
| 5.2.5 | PDF | Printable reports | Python |

### 5.3 Report Templates

| # | Feature | Description | Implementation File |
|---|---------|-------------|---------------------|
| 5.3.1 | Custom HTML Templates | User-defined report style | Python |
| 5.3.2 | Logo Insertion | Add company/logo to reports | All three |
| 5.3.3 | Report Branding | Custom colors/header | All three |

### 5.4 Data Sharing

| # | Feature | Description | Implementation File |
|---|---------|-------------|---------------------|
| 5.4.1 | Import Scan Data | Load from JSON/CSV | All three |
| 5.4.2 | Merge Scans | Combine multiple scans | All three |
| 5.4.3 | Cloud Sync | Sync cache across devices | All three |

---

## 6. Advanced Features

### 6.1 Scheduled Updates

| # | Feature | Description | Implementation File |
|---|---------|-------------|---------------------|
| 6.1.1 | Task Scheduler Integration | Windows Task Scheduler integration | All three |
| 6.1.2 | Daily/Weekly Scans | Automatic periodic scans | All three |
| 6.1.3 | Conditional Actions | Actions based on criteria | All three |

### 6.2 Rollback Support

| # | Feature | Description | Implementation File |
|---|---------|-------------|---------------------|
| 6.2.1 | Version Snapshots | Save pre-update state | All three |
| 6.2.2 | One-Click Rollback | Revert failed updates | All three |
| 6.2.3 | Snapshot Listing | View available snapshots | All three |

### 6.3 Dependency Graph

| # | Feature | Description | Implementation File |
|---|---------|-------------|---------------------|
| 6.3.1 | Graphviz DOT Export | Generate dependency graphs | All three |
| 6.3.2 | Conflict Detection | Find version conflicts | All three |
| 6.3.3 | Minimal Update Set | Suggest minimal updates | All three |

### 6.4 Remote Management

| # | Feature | Description | Implementation File |
|---|---------|-------------|---------------------|
| 6.4.1 | WinRM Remote Execution | Execute on remote Windows machines | All three |
| 6.4.2 | Inventory Management | Define machine groups | All three |
| 6.4.3 | Consolidated Reports | Aggregate multiple machines | All three |
| 6.4.4 | Mass Update | Update all machines at once | All three |

### 6.5 Plugin Architecture

| # | Feature | Description | Implementation File |
|---|---------|-------------|---------------------|
| 6.5.1 | Custom Scanners | Add custom package sources | All three |
| 6.5.2 | Custom Notifiers | Add notification channels | All three |
| 6.5.3 | Plugin API | Public API for extensions | All three |

---

## 7. Performance Optimizations

### 7.1 Smart Caching

| # | Feature | Description | Implementation File |
|---|---------|-------------|---------------------|
| 7.1.1 | Incremental Scan | Only scan changed sources | All three |
| 7.1.2 | Delta Cache | Store diffs instead of full | All three |
| 7.1.3 | LRU Memory Cache | Cache hot packages | All three |
| 7.1.4 | Pre-fetch | Background version checks | All three |

### 7.2 Parallel Processing

| # | Feature | Description | Implementation File |
|---|---------|-------------|---------------------|
| 7.2.1 | Worker Pool | Per-source worker pools | All three |
| 7.2.2 | Shared Deduplication | Cross-source cache | All three |
| 7.2.3 | Graceful Degradation | Handle partial failures | All three |

### 7.3 Network Optimization

| # | Feature | Description | Implementation File |
|---|---------|-------------|---------------------|
| 7.3.1 | Batch API Requests | Single request for multiple packages | All three |
| 7.3.2 | Rate Limiting | Respect API limits | All three |
| 7.3.3 | Response Caching | Cache API responses | All three |

### 7.4 Size Reduction

| # | Feature | Description | Implementation File |
|---|---------|-------------|---------------------|
| 7.4.1 | Compressed Cache | Gzip cached data | All three |
| 7.4.2 | Data Pruning | Remove old data automatically | All three |
| 7.4.3 | Selective Storage | Store only requested fields | All three |

---

## 8. Windows-Specific Enhancements

| # | Feature | Command | Description | Implementation File |
|---|---------|----------|-------------|---------------------|
| 8.1.1 | AppX Scanning | `Get-AppxPackage` | Scan Windows Store apps | All three |
| 8.1.2 | Windows Store Updates | `winget upgrade` for Store | Microsoft Store updates | All three |
| 8.1.3 | Driver Updates | Check via `pnputil` | Driver version checking | PowerShell |
| 8.1.4 | Windows Services | Query Service states | Detect outdated services | All three |
| 8.1.5 | PowerShell Modules | `Get-Module` | Scan PS module updates | All three |
| 8.1.6 | Visual Studio Extensions | Query VS Marketplace | VS Code/VS extensions | All three |

---

## 9. Implementation Roadmap

### Phase 1: Quick Wins (Week 1)

| # | Feature | Priority | Effort |
|---|---------|----------|--------|
| 2.1.1 | OSV API Integration | High | Medium |
| 4.1.1 | JSON Config File | High | Low |
| 5.2.1 | HTML Export | Medium | Low |
| 3.3.1 | Error Classification | Medium | Low |

### Phase 2: Core UX (Week 2)

| # | Feature | Priority | Effort |
|---|---------|----------|--------|
| 3.1.1 | Fuzzy Search | High | Medium |
| 3.2.1 | Scan Checkpointing | Medium | Medium |
| 3.4.1 | System Notifications | Medium | Low |
| 4.2.x | Environment Variables | High | Low |

### Phase 3: Data & Export (Week 3)

| # | Feature | Priority | Effort |
|---|---------|----------|--------|
| 5.1.1 | SQLite Database | Medium | Medium |
| 5.2.x | Additional Export Formats | Medium | Low |
| 5.4.x | Data Import/Merge | Low | Medium |

### Phase 4: Advanced Features (Week 4)

| # | Feature | Priority | Effort |
|---|---------|----------|--------|
| 6.1.x | Task Scheduler | Medium | High |
| 6.2.x | Rollback Support | Low | High |
| 6.3.x | Dependency Graph | Low | Medium |

### Phase 5: Expansion (Week 5)

| # | Feature | Priority | Effort |
|---|---------|----------|--------|
| 1.1.1 | Scoop scanner | High | Medium |
| 1.1.2 | .NET Global Tools | Medium | Medium |
| 1.2.x | Windows Store Apps | Medium | Medium |

### Phase 6: Enterprise (Week 6)

| # | Feature | Priority | Effort |
|---|---------|----------|--------|
| 6.4.x | Remote Management | Medium | High |
| 6.5.x | Plugin Architecture | Low | High |
| 7.x.x | Performance Optimization | Medium | Medium |

---

## Feature Checklist

Mark completed features here:

```
[X] 1.1.1 - Scoop scanner
[X] 1.1.2 - .NET Global Tools
[X] 1.1.3 - Cargo crates.io API
[X] 1.2.1 - AppX scanning
[X] 1.2.2 - MSIX scanning
[X] 2.1.1 - OSV API Integration
[X] 2.1.2 - PyPI Security JSON
```

v2.6.0 - GitHub Advisory Database + Local Advisory Import
[X] 2.1.2 - PyPI Security JSON
[X] 2.1.3 - NPM Audit Full Parse
[X] 2.1.4 - GitHub Advisory
[X] 2.1.5 - Local Advisory Import
[X] 2.2.1 - CVSS Score Display
[X] 2.2.2 - CVE Details Table
[X] 2.2.3 - Vulnerability History
[X] 2.2.4 - Security Summary Stats
[X] 2.3.1 - Critical Alert Priority
[X] 2.3.2 - Security Update Auto-Priority

[X] 3.1.1 - Fuzzy Search
[X] 3.1.2 - Package Multi-Select
[X] 3.1.3 - Keyboard Navigation
[X] 3.1.4 - Real-time Filtering
[X] 3.1.5 - Preview Changes
[X] 3.2.1 - Scan Checkpointing
[X] 3.2.2 - Resume Interrupted Scan
[X] 3.2.3 - ETA Display
[X] 3.2.4 - Per-Source Progress
[X] 3.3.1 - Error Classification
[X] 3.3.2 - Recovery Suggestions
[X] 3.3.3 - Verbose Mode (replaced by --debug)
[X] 3.3.4 - Error Log File
[ ] 3.4.1 - System Notifications
[ ] 3.4.2 - Email Alerts
[ ] 3.4.3 - Webhook Notifications
[ ] 3.4.4 - Custom Script Hooks
[ ] 3.5.1 - Custom Theme
[ ] 3.5.2 - More Display Formats
[ ] 3.5.3 - Source Icons
[ ] 3.5.4 - Status Icons

[ ] 4.1.1 - JSON Config File
[ ] 4.1.2 - YAML Config Support
[ ] 4.1.3 - Config Validation
[ ] 4.1.4 - Config Migration
[ ] 4.2.1 - SYSTEM_UPDATE_SOURCES
[ ] 4.2.2 - SYSTEM_UPDATE_TIMEOUT
[ ] 4.2.3 - SYSTEM_UPDATE_WORKERS
[ ] 4.2.4 - SYSTEM_UPDATE_EXCLUDE
[ ] 4.2.5 - SYSTEM_UPDATE_LOG_LEVEL
[ ] 4.3.1 - Named Profiles
[ ] 4.3.2 - Profile Switching
[ ] 4.3.3 - Profile Export/Import

[ ] 5.1.1 - SQLite Database
[ ] 5.1.2 - Version History
[ ] 5.1.3 - Trend Analysis
[ ] 5.1.4 - Report Generation
[ ] 5.2.1 - HTML Export
[ ] 5.2.2 - XML Export
[ ] 5.2.3 - Markdown Export
[ ] 5.2.4 - Diff Export
[ ] 5.2.5 - PDF Export
[ ] 5.3.1 - Custom HTML Templates
[ ] 5.3.2 - Logo Insertion
[ ] 5.3.3 - Report Branding
[ ] 5.4.1 - Import Scan Data
[ ] 5.4.2 - Merge Scans
[ ] 5.4.3 - Cloud Sync

[ ] 6.1.1 - Task Scheduler Integration
[ ] 6.1.2 - Daily/Weekly Scans
[ ] 6.1.3 - Conditional Actions
[ ] 6.2.1 - Version Snapshots
[ ] 6.2.2 - One-Click Rollback
[ ] 6.2.3 - Snapshot Listing
[ ] 6.3.1 - Graphviz DOT Export
[ ] 6.3.2 - Conflict Detection
[ ] 6.3.3 - Minimal Update Set
[ ] 6.4.1 - WinRM Remote Execution
[ ] 6.4.2 - Inventory Management
[ ] 6.4.3 - Consolidated Reports
[ ] 6.4.4 - Mass Update
[ ] 6.5.1 - Custom Scanners
[ ] 6.5.2 - Custom Notifiers
[ ] 6.5.3 - Plugin API

[ ] 7.1.1 - Incremental Scan
[ ] 7.1.2 - Delta Cache
[ ] 7.1.3 - LRU Memory Cache
[ ] 7.1.4 - Pre-fetch
[ ] 7.2.1 - Worker Pool
[ ] 7.2.2 - Shared Deduplication
[ ] 7.2.3 - Graceful Degradation
[ ] 7.3.1 - Batch API Requests
[ ] 7.3.2 - Rate Limiting
[ ] 7.3.3 - Response Caching
[ ] 7.4.1 - Compressed Cache
[ ] 7.4.2 - Data Pruning
[ ] 7.4.3 - Selective Storage

[ ] 8.1.1 - AppX Scanning
[ ] 8.1.2 - Windows Store Updates
[ ] 8.1.3 - Driver Updates
[ ] 8.1.4 - Windows Services
[ ] 8.1.5 - PowerShell Modules
[ ] 8.1.6 - Visual Studio Extensions
```

---

*Document generated for System Update CLI v3.3.0*
*Python-only implementation - Last updated: April 2026*