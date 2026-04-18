# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## 📝 License

This project is provided as-is for system administration and package management.

---

## 🆕 Latest Changes

### v2.9.0 (April 2026)
- **Critical Alert Priority**: Critical vulnerabilities now sorted first and highlighted with 🚨 emoji and bold red blink effect
- **Security Update Auto-Priority**: Vulnerable packages are now prioritized and updated separately from regular updates

### v2.8.0 (April 2026)
- **Python-only Repository**: Simplified to only Python implementation (removed Node.js and PowerShell scripts)
- **Repository Cleanup**: Removed all Node.js and PowerShell files, tests, and documentation

### v2.7.0 (April 2026)
- **CVSS Score Display**: Show CVSS scores for vulnerabilities in security tables
- **Security Summary Stats**: Added detailed security summary with colored severity counts and affected package counts
- **Vulnerability History**: Implemented persistent vulnerability tracking over time in `vulnerability_history.json`
- **Enhanced CVE Details**: Added detailed vulnerability metadata including affected versions and published dates

### v2.6.0 (April 2026)
- **GitHub Advisory Database**: Added vulnerability scanning via GitHub Advisory API
- **Local Advisory Import**: Added support for custom vulnerability data from local JSON file (~/.system_update/advisories.json)

### v2.5.0 (April 2026)
- **NPM Audit Full Parse**: Enhanced npm vulnerability scanning to extract detailed advisory info from npm audit JSON output including via array details, advisoryUrl, fixAvailable, isDirect, and effects

### v2.4.0 (April 2026)
- **PyPI Security JSON**: Added vulnerability checking via PyPI JSON API for direct vulnerability data

### v2.3.0 (April 2026)
- **OSV API Integration**: Added Google's OSV vulnerability database support for all supported ecosystems
- **Extended vulnerability scanning**: Now checks npm, PyPI, crates.io, RubyGems, Go, CocoaPods, and Hex packages

### v2.2.0 (April 2026)
- **.NET Global Tools support**: Added .NET CLI tools scanning via `dotnet tool list -g`
- **Scoop support**: Added Scoop package manager support
- **AppX/Packaged Apps support**: Added Windows Store apps scanning via `Get-AppxPackage`
- **MSIX support**: Added MSIX packages scanning
- **New `--show-all` flag**: Show all packages including up-to-date ones (default shows only updates)
- **Improved output format**: "💾 Showing" line now appears after the package table
- **New "🎯 Found" message**: Clear indication of available updates count at the end

### v2.1.0 (April 2026)
- **Cargo crates.io API**: Now queries crates.io API directly instead of requiring cargo-install-update
- **Improved Rust scanning**: Better version comparison for Rust packages

### v2.0.0 (March 2026)
- **Major rewrite**: Reimplemented in Python with Rich UI
- **Parallel scanning**: ThreadPoolExecutor for concurrent package scanning
- **Security features**: OSV, GitHub Advisory, PyPI vulnerability scanning

### v1.0.0 (March 2026)
- Initial release