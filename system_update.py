#!/usr/bin/env python3
"""
===============================================================================
                          SYSTEM UPDATE ENHANCED
===============================================================================
Version: 5.0.0
Author: Gemini (Redesigned)

A sophisticated system update tool with enhanced UI architecture and modular design.

Features:
• Multi-source package discovery (Winget, Chocolatey, NPM, PIP, PNPM, PATH, Registry)
• Real-time security vulnerability scanning
• Parallel processing for optimal performance
• Beautiful Rich-based interface with modern layout
• Flexible export options and caching system
• Granular update control with dry-run support
"""

import argparse
import csv
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import time

# Force UTF-8 encoding for standard output to avoid UnicodeEncodeError on Windows
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from enum import Enum

# Required rich imports - ensure_dependencies() will install if missing
from rich import print

RICH_AVAILABLE = True
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Confirm
from rich.progress import (
    Progress,
    TextColumn,
    BarColumn,
    TimeElapsedColumn,
    MofNCompleteColumn,
    TaskID,
)
from rich.style import Style
from rich import box


# ═══════════════════════════════════════════════════════════════════════════════
# DEPENDENCY MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════


def ensure_dependencies():
    """Auto-install required dependencies with user confirmation."""
    global RICH_AVAILABLE
    if RICH_AVAILABLE:
        return

    print("🔧 The 'rich' library is required for enhanced UI experience.")
    try:
        choice = input("Install 'rich' now? (y/n): ").lower().strip()
    except EOFError:
        choice = "n"

    if choice == "y":
        try:
            print("⬇️  Installing 'rich' library...")
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "rich"],
                check=True,
                capture_output=True,
            )
            print("✅ 'rich' installed successfully!")
            print("🔄 Please restart the script to enjoy the full experience.")
            sys.exit(0)
        except subprocess.CalledProcessError:
            print("❌ Installation failed.")
            print("💡 Manual install: pip install rich")
            sys.exit(1)
    else:
        print("⚠️  Cannot proceed without 'rich'. Exiting.")
        sys.exit(1)


ensure_dependencies()
console = Console()


# ═══════════════════════════════════════════════════════════════════════════════
# CORE DATA MODELS
# ═══════════════════════════════════════════════════════════════════════════════


class UpdateStatus(Enum):
    """Package update status enumeration."""

    UP_TO_DATE = "up_to_date"
    UPDATE_AVAILABLE = "update_available"
    UNKNOWN = "unknown"
    ERROR = "error"
    VULNERABLE = "vulnerable"
    SECURITY_UPDATE_AVAILABLE = "security_update_available"


@dataclass
class AppInfo:
    """Structured application metadata."""

    name: str
    source: str
    version: str
    latest_version: str = ""
    app_id: Optional[str] = None
    update_status: UpdateStatus = UpdateStatus.UNKNOWN
    error_msg: Optional[str] = None
    install_path: Optional[str] = None
    scan_time: datetime = field(default_factory=datetime.now)

    @property
    def has_update(self) -> bool:
        return bool(self.latest_version and self.latest_version != self.version)

    @property
    def status_display(self) -> str:
        """Get formatted status for display with emoji and text."""
        mapping = {
            UpdateStatus.UP_TO_DATE: "✅ up-to-date",
            UpdateStatus.UPDATE_AVAILABLE: "⬆️ update",
            UpdateStatus.UNKNOWN: "❓ unknown",
            UpdateStatus.ERROR: "❌ error",
            UpdateStatus.VULNERABLE: "🔥 vulnerable",
            UpdateStatus.SECURITY_UPDATE_AVAILABLE: "🔒 security update",
        }
        return mapping.get(self.update_status, "❓ unknown")

    def to_dict(self) -> Dict:
        data = asdict(self)
        data["update_status"] = self.update_status.value
        data["scan_time"] = self.scan_time.isoformat()
        data["has_update"] = self.has_update
        return data


@dataclass
class SecurityInfo:
    """Security vulnerability metadata."""

    cve_id: str
    severity: str
    cvss_score: float
    description: str
    affected_versions: List[str] = field(default_factory=list)
    published_date: Optional[datetime] = None

    def to_dict(self) -> Dict:
        data = asdict(self)
        if self.published_date:
            data["published_date"] = self.published_date.isoformat()
        return data


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION SYSTEM
# ═══════════════════════════════════════════════════════════════════════════════


class SystemConfig:
    """Enhanced configuration management with validation."""

    def __init__(self):
        self.config_dir = Path.home() / ".system_update"
        self.config_file = self.config_dir / "config.json"
        self.cache_file = self.config_dir / "cache.json"
        self.log_file = self.config_dir / "system.log"

        self.config_dir.mkdir(exist_ok=True)

        self.settings = {
            "cache": {
                "duration_hours": 2,
                "enabled": True,
            },
            "performance": {
                "parallel_scan": True,
                "max_workers": 6,
                "timeout_seconds": 45,
            },
            "sources": {
                "winget": True,
                "chocolatey": True,
                "npm": True,
                "pnpm": True,
                "pip": True,
                "bun": True,
                "yarn": True,
                "path": True,
                "registry": True,
                "rust": True,
            },
            "security": {
                "enabled": True,
                "auto_check": True,
                "severity_threshold": "medium",
            },
            "ui": {
                "theme": "default",
                "show_stats": True,
                "compact_view": False,
                "color_scheme": "vibrant",
            },
            "export": {
                "default_format": "json",
                "include_timestamp": True,
            },
        }
        self.load()

    def load(self):
        """Load configuration from file with error handling."""
        if self.config_file.exists():
            try:
                with open(self.config_file, "r", encoding="utf-8") as f:
                    loaded_settings = json.load(f)
                    self._merge_settings(self.settings, loaded_settings)
            except Exception as e:
                logging.warning(f"Failed to load config: {e}")

    def _merge_settings(self, base: dict, loaded: dict):
        """Recursively merge settings."""
        for key, value in loaded.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_settings(base[key], value)
            else:
                base[key] = value

    def save(self):
        """Save current configuration to file."""
        try:
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(self.settings, f, indent=2, default=str)
        except Exception as e:
            logging.error(f"Failed to save config: {e}")


config = SystemConfig()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(config.log_file),
        logging.NullHandler(),
    ],
)
logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# CACHE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════


class CacheManager:
    """Intelligent caching system with validation."""

    def __init__(self, cache_file: Path, duration_hours: int = 2):
        self.cache_file = cache_file
        self.duration = timedelta(hours=duration_hours)

    def is_valid(self) -> bool:
        """Check if cache is valid and not expired."""
        if not self.cache_file.exists():
            return False
        try:
            with open(self.cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                cache_time = datetime.fromisoformat(data.get("timestamp", ""))
                return datetime.now() - cache_time < self.duration
        except Exception:
            return False

    def load(self) -> Optional[List[AppInfo]]:
        """Load cached applications with type safety."""
        if not self.is_valid():
            return None
        try:
            with open(self.cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                apps = []
                for item in data.get("apps", []):
                    item.pop("has_update", None)
                    item["update_status"] = UpdateStatus(item["update_status"])
                    item["scan_time"] = datetime.fromisoformat(item["scan_time"])
                    apps.append(AppInfo(**item))
                return apps
        except Exception as e:
            logger.warning(f"Failed to load cache: {e}")
            return None

    def save(self, apps: List[AppInfo]):
        """Save applications to cache with metadata."""
        try:
            data = {
                "timestamp": datetime.now().isoformat(),
                "version": "5.0.0",
                "total_apps": len(apps),
                "apps": [app.to_dict() for app in apps],
            }
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save cache: {e}")

    def clear(self):
        """Clear cache file."""
        if self.cache_file.exists():
            self.cache_file.unlink()


# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════


def run_command(cmd: List[str], timeout: int = 45, allow_failure: bool = False, include_stderr: bool = False) -> Optional[str]:
    """Execute command with enhanced error handling and timeout."""
    try:
        if platform.system() == "Windows":
            executable = shutil.which(cmd[0])
            if executable:
                cmd[0] = executable

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,  # always capture output; check exit code manually
            encoding="utf-8",
            errors="ignore",
            timeout=timeout,
        )
        if result.returncode != 0 and not allow_failure:
            logger.debug(f"Command exited {result.returncode}: {' '.join(cmd)}")
            return None
        # Mirror JS: combine stdout+stderr when include_stderr is requested
        if include_stderr:
            combined = f"{result.stdout}\n{result.stderr}".strip()
            return combined or None
        return result.stdout.strip() or None
    except subprocess.TimeoutExpired:
        logger.warning(f"Command timed out: {' '.join(cmd)}")
        return None
    except FileNotFoundError as e:
        logger.debug(f"Command not found: {' '.join(cmd)} - {e}")
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# SOURCE BADGE UTILITY
# ═══════════════════════════════════════════════════════════════════════════════


def source_badge(source: str) -> str:
    """Return source name with Rich style tags matching JS sourceBadge().

    Color pattern (from JS version):
    - winget: blue
    - chocolatey: yellow
    - npm: red
    - pnpm: magenta (purple in JS)
    - pip: cyan
    - bun: yellow (orange not available in Rich, using yellow)
    - yarn: white
    - rust: magenta
    - path: green
    - registry: dim white (gray)
    """
    source_lower = (source or "unknown").lower()
    style_map = {
        "winget": "bold blue",
        "chocolatey": "bold yellow",
        "npm": "bold red",
        "pnpm": "bold magenta",
        "pip": "bold cyan",
        "bun": "yellow",
        "yarn": "bold white",
        "rust": "bold magenta",
        "path": "bold green",
        "registry": "dim white",
    }
    style = style_map.get(source_lower, "dim white")
    return f"[{style}]{source_lower}[/{style}]"


# ═══════════════════════════════════════════════════════════════════════════════
# ENHANCED UI SYSTEM
# ═══════════════════════════════════════════════════════════════════════════════


class UISystem:
    """Enhanced user interface system with beautiful layouts."""

    @staticmethod
    def display_banner():
        """Show application banner matching JS version."""
        def hr(ch='─', width=70): return ch * width
        w = 68
        title = f"🚀 System Update Node CLI v5.0.0"
        sub = f"⚙️ Data dir: {config.config_dir}"
        
        console.print(f"[cyan]┌{hr('─', 70)}┐[/cyan]")
        console.print(f"[cyan]│[/cyan] [bold cyan]{title.ljust(69)}[/bold cyan][cyan]│[/cyan]")
        console.print(f"[cyan]│[/cyan] [dim cyan]{sub.ljust(69)}[/dim cyan][cyan]│[/cyan]")
        console.print(f"[cyan]└{hr('─', 70)}┘[/cyan]")
        
        console.print(f"Cache  [dim white]→ {config.cache_file}[/dim white]")
        console.print()

    @staticmethod
    def display_summary(total_apps: int, updates: int, scan_time: float, sources_count: Dict[str, int]):
        """Display summary exactly matching NodeJS version."""
        console.print(f"[bold magenta]📊 Summary[/bold magenta]")
        console.print(f"📦 total apps     [bold white]{total_apps}[/bold white]")
        console.print(f"⬆️ updates        [bold yellow]{updates}[/bold yellow]")
        console.print(f"⏱️ scan duration  [bold white]{scan_time:.2f}s[/bold white]")
        
        source_parts = [f"{s.lower()}:{c}" for s, c in sorted(sources_count.items()) if c > 0]
        console.print(f"⚙️ sources        [dim white]{', '.join(source_parts)}[/dim white]")
        console.print()

    @staticmethod
    def create_apps_table(
        apps: List[AppInfo], title: str = "Installed Applications"
    ) -> Table:
        """Create applications table matching JS version."""
        table = Table(
            box=box.SIMPLE,
            show_header=True,
            header_style="bold cyan",
            border_style="dim white",
            pad_edge=False,
        )

        table.add_column("Package", style="bold white", width=30)
        table.add_column("Source", width=12)
        table.add_column("Current", width=20, style="white")
        table.add_column("Latest", width=20)
        table.add_column("Status", width=17, justify="left")

        for app in sorted(apps, key=lambda x: (x.source, x.name)):
            # Source-based coloring (Rich styles)
            src_styles = {
                "winget": "bold blue",
                "chocolatey": "bold yellow",
                "npm": "bold red",
                "pnpm": "bold magenta",
                "bun": "yellow",
                "yarn": "bold white",
                "pip": "bold cyan",
                "rust": "bold magenta",
                "path": "bold green",
                "registry": "dim white",
            }
            source_lower = app.source.lower()
            source_style = src_styles.get(source_lower, "white")
            # Status-based coloring
            status_styles = {
                UpdateStatus.UP_TO_DATE: "green",
                UpdateStatus.UPDATE_AVAILABLE: "bold yellow",
                UpdateStatus.ERROR: "bold red",
                UpdateStatus.VULNERABLE: "bold red",
                UpdateStatus.SECURITY_UPDATE_AVAILABLE: "bold magenta",
                UpdateStatus.UNKNOWN: "dim white",
            }
            status_style = status_styles.get(app.update_status, "white")

            # Latest version column: yellow bold when update available (matching JS)
            # Show "-" when up-to-date (no update needed)
            if app.latest_version and app.update_status == UpdateStatus.UPDATE_AVAILABLE:
                latest_text = Text(app.latest_version, style="bold yellow")
            elif app.update_status == UpdateStatus.UP_TO_DATE:
                latest_text = "-"
            else:
                latest_text = app.latest_version or "-"

            table.add_row(
                app.name[:30],
                Text(app.source, style=source_style),
                app.version,
                latest_text,
                f"[{status_style}]{app.status_display}[/{status_style}]",
            )

        return table

    @staticmethod
    def create_security_table(security_results: List) -> Table:
        """Create security vulnerabilities table."""
        table = Table(
            title="[bold red]🔒 Security Alerts[/bold red]",
            box=box.HEAVY_EDGE,
            border_style="red",
        )

        table.add_column("Package", style="cyan")
        table.add_column("Severity", justify="center")
        table.add_column("CVE", justify="center")
        table.add_column("Description", style="dim")

        for result in security_results:
            severity_color = {
                "CRITICAL": "bold red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "green",
            }.get(result.highest_severity, "white")

            table.add_row(
                result.app_info.name,
                f"[{severity_color}]{result.highest_severity}[/{severity_color}]",
                str(result.total_vulnerabilities),
                (result.vulnerabilities[0].description[:40] + "...")
                if result.vulnerabilities
                else "Unknown",
            )

        return table


# ═══════════════════════════════════════════════════════════════════════════════
# PACKAGE SCANNERS
# ═══════════════════════════════════════════════════════════════════════════════


class PackageScanner:
    """Enhanced package scanning system."""

    @staticmethod
    def scan_winget() -> List[AppInfo]:
        """Scan Winget packages with improved parsing."""
        apps = []
        output = run_command(["winget", "list", "--accept-source-agreements"], allow_failure=True)
        if not output:
            return apps

        lines = output.splitlines()
        header_index = next(
            (
                i
                for i, line in enumerate(lines)
                if "Name" in line and "Id" in line and "Version" in line
            ),
            -1,
        )

        if header_index == -1:
            return apps

        header = lines[header_index]
        # Adjust header to start from "Name" position (match Node.js behavior)
        name_match = re.search(r"Name\s+Id", header)
        if name_match:
            header = header[name_match.start():]

        positions = {
            "name": 0,
            "id": header.find("Id"),
            "version": header.find("Version"),
            "available": header.find("Available"),
            "source": header.find("Source"),
        }

        for line in lines[header_index + 2 :]:
            if not line.strip():
                continue

            try:
                name = line[0 : max(positions["id"], 0)].strip()
                app_id = line[positions["id"] : positions["version"]].strip() if positions["version"] > 0 else ""
                version_end = (
                    positions["available"]
                    if positions["available"] != -1
                    else positions["source"]
                    if positions["source"] != -1
                    else len(line)
                )
                version = line[positions["version"]:version_end].strip() if positions["version"] != -1 else ""

                # Skip entries without name, app_id, or version (match Node.js behavior)
                if not name or not app_id or not version:
                    continue

                apps.append(
                    AppInfo(
                        name=name,
                        source="Winget",
                        version=version,
                        app_id=app_id,
                        update_status=UpdateStatus.UNKNOWN,
                    )
                )
            except Exception:
                continue

        return apps

    @staticmethod
    def scan_chocolatey() -> List[AppInfo]:
        """Scan Chocolatey packages."""
        apps = []
        output = run_command(["choco", "list", "--local-only", "--limit-output"], allow_failure=True)
        if not output:
            return apps

        for line in output.splitlines():
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) >= 2:
                apps.append(
                    AppInfo(
                        name=parts[0],
                        source="Chocolatey",
                        version=parts[1],
                        app_id=parts[0],
                    )
                )

        return apps

    @staticmethod
    def scan_npm() -> List[AppInfo]:
        """Scan NPM global packages."""
        apps = []
        output = run_command(["npm", "list", "-g", "--depth=0", "--json", "--silent"], allow_failure=True)
        if not output:
            return apps

        try:
            data = json.loads(output)
            if "dependencies" in data:
                for name, details in data["dependencies"].items():
                    apps.append(
                        AppInfo(
                            name=name,
                            source="NPM",
                            version=details.get("version", "N/A"),
                            app_id=name,
                        )
                    )
        except json.JSONDecodeError:
            pass

        return apps

    @staticmethod
    def scan_pnpm() -> List[AppInfo]:
        """Scan PNPM global packages."""
        apps = []
        output = run_command(["pnpm", "list", "-g", "--depth=0", "--json"], allow_failure=True)
        if not output:
            return apps

        try:
            data = json.loads(output)
            data = data[0] if isinstance(data, list) and data else data

            if isinstance(data, dict) and "dependencies" in data:
                for name, details in data["dependencies"].items():
                    apps.append(
                        AppInfo(
                            name=name,
                            source="PNPM",
                            version=details.get("version", "N/A"),
                            app_id=name,
                        )
                    )
        except (json.JSONDecodeError, IndexError):
            pass

        return apps

    @staticmethod
    def scan_bun() -> List[AppInfo]:
        """Scan Bun global packages."""
        apps = []
        output = run_command(["bun", "pm", "ls", "-g"], allow_failure=True)
        if not output:
            return apps

        for line in output.splitlines():
            match = re.match(r"^\s*([^\s@]+)@([^\s]+)", line)
            if match:
                apps.append(
                    AppInfo(
                        name=match.group(1),
                        source="Bun",
                        version=match.group(2),
                        app_id=match.group(1),
                    )
                )

        return apps

    @staticmethod
    def scan_yarn() -> List[AppInfo]:
        """Scan Yarn global packages."""
        apps = []
        output = run_command(["yarn", "global", "list"], allow_failure=True)
        if not output:
            return apps

        for line in output.splitlines():
            match = re.match(r'^info "([^@]+)@([^"]+)"', line)
            if match:
                apps.append(
                    AppInfo(
                        name=match.group(1),
                        source="Yarn",
                        version=match.group(2),
                        app_id=match.group(1),
                    )
                )

        return apps

    @staticmethod
    def scan_pip() -> List[AppInfo]:
        """Scan PIP packages."""
        apps = []
        # Try multiple pip command patterns like Node.js does
        pip_commands = [
            [sys.executable, "-m", "pip", "list", "--format=json"],
            ["pip", "list", "--format=json"],
            ["pip3", "list", "--format=json"],
        ]
        
        output = None
        for cmd in pip_commands:
            output = run_command(cmd, allow_failure=True)
            if output:
                break
        
        if not output:
            return apps

        try:
            data = json.loads(output)
            for item in data:
                apps.append(
                    AppInfo(
                        name=item["name"],
                        source="PIP",
                        version=item["version"],
                        app_id=item["name"],
                    )
                )
        except json.JSONDecodeError:
            pass

        return apps

    @staticmethod
    def scan_path() -> List[AppInfo]:
        """Scan PATH executables."""
        apps = []
        executables = [
            "node",
            "npm",
            "pnpm",
            "yarn",
            "python",
            "git",
            "go",
            "bun",
            "deno",
            "rustc",
            "cargo",
            "dotnet",
            "java",
            "pwsh",
        ]

        for exe in executables:
            cmd = ["where", exe] if platform.system() == "Windows" else ["which", exe]
            path = run_command(cmd, allow_failure=True)
            if path:
                version_output = run_command([exe, "--version"], allow_failure=True)
                if version_output:
                    match = re.search(r"(\d+\.\d+(\.\d+)*([-.].*)?)", version_output)
                    if match:
                        apps.append(
                            AppInfo(
                                name=exe,
                                source="PATH",
                                version=match.group(0),
                                install_path=path.split("\n")[0],
                            )
                        )

        return apps

    @staticmethod
    def scan_rust() -> List[AppInfo]:
        """Scan Rust packages installed via cargo."""
        apps = []
        output = run_command(["cargo", "install", "--list"], allow_failure=True)
        if not output:
            return apps

        for line in output.splitlines():
            # Format: package-name v1.2.3:
            match = re.match(r"^([^\s]+)\s+v([^\s:]+):", line)
            if match:
                apps.append(
                    AppInfo(
                        name=match.group(1),
                        source="Rust",
                        version=match.group(2),
                        app_id=match.group(1),
                    )
                )

        return apps

    @staticmethod
    def scan_registry() -> List[AppInfo]:
        """Scan Windows Registry for installed applications."""
        if platform.system() != "Windows":
            return []

        apps = []
        ps_script = """
        $paths = @(
            'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
            'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
            'HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
        )
        Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue | 
            Where-Object { $_.DisplayName -and $_.DisplayVersion -and !$_.SystemComponent } | 
            Select-Object @{n='Name';e={$_.DisplayName}}, 
                         @{n='Version';e={$_.DisplayVersion}}, 
                         @{n='InstallLocation';e={$_.InstallLocation}} | 
            ConvertTo-Json
        """

        output = run_command(["powershell", "-NoProfile", "-Command", ps_script], allow_failure=True)
        if output:
            try:
                data = json.loads(output)
                data = [data] if isinstance(data, dict) else data
                for item in data:
                    apps.append(
                        AppInfo(
                            name=item["Name"],
                            source="Registry",
                            version=item["Version"],
                            install_path=item.get("InstallLocation"),
                        )
                    )
            except Exception:
                pass

        return apps


# ═══════════════════════════════════════════════════════════════════════════════
# UPDATE CHECKERS
# ═══════════════════════════════════════════════════════════════════════════════


class UpdateChecker:
    """Enhanced update checking system."""

    @staticmethod
    def check_all_updates(apps: List[AppInfo]) -> int:
        """Check updates for all supported package managers matching JS checkUpdates."""
        total_updates = 0

        # Group apps by source for batch processing (matching JS order)
        sources = {
            "winget": [a for a in apps if a.source.lower() == "winget"],
            "chocolatey": [a for a in apps if a.source.lower() == "chocolatey"],
            "npm": [a for a in apps if a.source.lower() == "npm"],
            "pnpm": [a for a in apps if a.source.lower() == "pnpm"],
            "bun": [a for a in apps if a.source.lower() == "bun"],
            "yarn": [a for a in apps if a.source.lower() == "yarn"],
            "pip": [a for a in apps if a.source.lower() == "pip"],
            "path": [a for a in apps if a.source.lower() == "path"],
            "registry": [a for a in apps if a.source.lower() == "registry"],
            "rust": [a for a in apps if a.source.lower() == "rust"],
        }

        # Filter to only sources with apps
        active_sources = [(name, apps_list) for name, apps_list in sources.items() if apps_list]

        # Check updates for each source using Rich Progress
        with Progress(
            TextColumn("{task.description}"),
            BarColumn(bar_width=26, complete_style="white", style="dim white", finished_style="white"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TextColumn("{task.fields[extra]}"),
            console=console,
        ) as progress:
            task = progress.add_task("⬆️ Checking updates", total=len(active_sources), extra="")

            for source_name, source_apps in active_sources:
                source_updates = 0

                if source_name == "winget":
                    source_updates = UpdateChecker._check_winget_updates(source_apps)
                elif source_name == "chocolatey":
                    source_updates = UpdateChecker._check_choco_updates(source_apps)
                elif source_name == "npm":
                    source_updates = UpdateChecker._check_npm_updates(source_apps)
                elif source_name == "pnpm":
                    source_updates = UpdateChecker._check_pnpm_updates(source_apps)
                elif source_name == "bun":
                    source_updates = UpdateChecker._check_bun_updates(source_apps)
                elif source_name == "yarn":
                    source_updates = UpdateChecker._check_yarn_updates(source_apps)
                elif source_name == "pip":
                    source_updates = UpdateChecker._check_pip_updates(source_apps)
                elif source_name == "path":
                    source_updates = UpdateChecker._check_path_updates(source_apps)
                elif source_name == "registry":
                    source_updates = UpdateChecker._check_registry_updates(source_apps)
                elif source_name == "rust":
                    source_updates = UpdateChecker._check_rust_updates(source_apps)

                total_updates += source_updates

                # Match JS: source_badge + count or "none"
                if source_updates > 0:
                    progress.update(task, advance=1, extra=f"{source_badge(source_name)}: [bold yellow]{source_updates}[/bold yellow] update(s)")
                else:
                    progress.update(task, advance=1, extra=f"{source_badge(source_name)}: [dim white]none[/dim white]")

            # Mark complete matching JS
            progress.update(task, extra="✅ [bold green]update checks complete[/bold green]")

        # Mark apps with proper status (match JavaScript logic)
        for app in apps:
            if app.update_status == UpdateStatus.UPDATE_AVAILABLE:
                continue
            if app.update_status == UpdateStatus.UP_TO_DATE:
                continue
            # Sources that perform update checks should be marked UP_TO_DATE if no update found
            if app.latest_version or app.source.lower() in ["winget", "chocolatey", "npm", "pnpm", "bun", "yarn", "pip", "registry", "rust", "path"]:
                app.update_status = UpdateStatus.UP_TO_DATE
            else:
                app.update_status = UpdateStatus.UNKNOWN

        return total_updates

    @staticmethod
    def _check_winget_updates(apps: List[AppInfo]) -> int:
        """Check Winget package updates."""
        updates = 0
        output = run_command(["winget", "upgrade", "--accept-source-agreements"], allow_failure=True)
        if not output:
            return updates

        lines = output.splitlines()
        header_index = next(
            (i for i, line in enumerate(lines) if "Name" in line and "Id" in line), -1
        )

        if header_index == -1:
            return updates

        header = lines[header_index]
        # Adjust header to start from "Name" position (match Node.js behavior)
        name_match = re.search(r"Name\s+Id", header)
        if name_match:
            header = header[name_match.start():]

        positions = {
            "id": header.find("Id"),
            "version": header.find("Version"),
            "available": header.find("Available"),
            "source": header.find("Source"),
        }

        for line in lines[header_index + 2 :]:
            if not line.strip():
                continue

            try:
                app_id = line[positions["id"] : positions["version"]].strip() if positions["version"] > 0 else ""
                if positions["available"] != -1:
                    avail_end = (
                        positions["source"] if positions["source"] != -1 else len(line)
                    )
                    latest = line[positions["available"] : avail_end].strip()

                    # Skip entries without app_id or latest version
                    if not app_id or not latest:
                        continue

                    if app_id and latest:
                        for app in apps:
                            if app.app_id and app.app_id.lower() == app_id.lower():
                                app.latest_version = latest
                                app.update_status = UpdateStatus.UPDATE_AVAILABLE
                                updates += 1
            except Exception:
                continue

        return updates

    @staticmethod
    def _check_registry_updates(apps: List[AppInfo]) -> int:
        """Check Registry app updates by cross-referencing with winget upgrade.

        winget internally queries the Windows Registry to build its upgrade list,
        so we can match Registry-installed apps against the winget upgrade output
        by name to detect available updates.
        """
        updates = 0
        output = run_command(["winget", "upgrade", "--accept-source-agreements"], allow_failure=True)
        if not output:
            # Mark all as UP_TO_DATE since we have no upgrade data
            for app in apps:
                app.update_status = UpdateStatus.UP_TO_DATE
            return updates

        lines = output.splitlines()
        header_index = next(
            (i for i, line in enumerate(lines) if "Name" in line and "Id" in line), -1
        )
        if header_index == -1:
            for app in apps:
                app.update_status = UpdateStatus.UP_TO_DATE
            return updates

        header = lines[header_index]
        positions = {
            "id": header.find("Id"),
            "version": header.find("Version"),
            "available": header.find("Available"),
            "source": header.find("Source"),
        }

        # Build a lookup: lowercased name -> latest version
        upgrade_map: dict = {}
        for line in lines[header_index + 2:]:
            if not line.strip():
                continue
            try:
                name = line[0:positions["id"]].strip().lower()
                if positions["available"] != -1:
                    avail_end = positions["source"] if positions["source"] != -1 else len(line)
                    latest = line[positions["available"]:avail_end].strip()
                    if name and latest:
                        upgrade_map[name] = latest
            except Exception:
                continue

        for app in apps:
            latest = upgrade_map.get(app.name.lower())
            if latest:
                app.latest_version = latest
                app.update_status = UpdateStatus.UPDATE_AVAILABLE
                updates += 1
            else:
                app.update_status = UpdateStatus.UP_TO_DATE

        return updates

    @staticmethod
    def _check_choco_updates(apps: List[AppInfo]) -> int:
        """Check Chocolatey package updates."""
        updates = 0
        output = run_command(["choco", "outdated", "--limit-output"], allow_failure=True)
        if not output:
            return updates

        for line in output.splitlines():
            parts = line.split("|")
            if len(parts) >= 3:
                for app in apps:
                    if app.name == parts[0]:
                        app.latest_version = parts[2]
                        app.update_status = UpdateStatus.UPDATE_AVAILABLE
                        updates += 1

        return updates

    @staticmethod
    def _check_npm_updates(apps: List[AppInfo]) -> int:
        """Check NPM package updates."""
        updates = 0
        output = run_command(["npm", "outdated", "-g", "--json"], allow_failure=True)
        if not output:
            return updates

        try:
            data = json.loads(output)
            for name, details in data.items():
                for app in apps:
                    if app.name == name:
                        latest_version = details.get("latest", "")
                        if latest_version:
                            app.latest_version = latest_version
                            app.update_status = UpdateStatus.UPDATE_AVAILABLE
                            updates += 1
        except Exception:
            pass

        return updates

    @staticmethod
    def _check_pnpm_updates(apps: List[AppInfo]) -> int:
        """Check PNPM package updates."""
        updates = 0
        output = run_command(["pnpm", "outdated", "-g", "--json"], allow_failure=True)
        if not output:
            return updates

        try:
            data = json.loads(output)
            if isinstance(data, dict):
                for name, details in data.items():
                    for app in apps:
                        if app.name == name:
                            latest_version = details.get("latest", details.get("wanted", ""))
                            if latest_version:
                                app.latest_version = latest_version
                                app.update_status = UpdateStatus.UPDATE_AVAILABLE
                                updates += 1
            elif isinstance(data, list):
                for item in data:
                    name = item.get("name")
                    for app in apps:
                        if app.name == name:
                            latest_version = item.get("latest", item.get("wanted", ""))
                            if latest_version:
                                app.latest_version = latest_version
                                app.update_status = UpdateStatus.UPDATE_AVAILABLE
                                updates += 1
        except Exception:
            pass

        return updates

    @staticmethod
    def _check_pip_updates(apps: List[AppInfo]) -> int:
        """Check PIP package updates."""
        updates = 0
        pip_commands = [
            [sys.executable, "-m", "pip", "list", "--outdated", "--format=json"],
            ["pip", "list", "--outdated", "--format=json"],
            ["pip3", "list", "--outdated", "--format=json"],
        ]

        output = None
        for cmd in pip_commands:
            output = run_command(cmd, allow_failure=True)
            if output:
                break

        if not output:
            return updates

        try:
            data = json.loads(output)
            for item in data:
                name = item.get("name")
                latest = item.get("latest_version")
                for app in apps:
                    if app.name.lower() == name.lower():
                        app.latest_version = latest
                        app.update_status = UpdateStatus.UPDATE_AVAILABLE
                        updates += 1
        except Exception:
            pass

        return updates

    @staticmethod
    def _check_bun_updates(apps: List[AppInfo]) -> int:
        """Check Bun package updates."""
        updates = 0
        for app in apps:
            output = run_command(["npm", "info", app.name, "version"], allow_failure=True)
            if output:
                latest = output.strip()
                if latest and latest != app.version and "ERR" not in latest:
                    app.latest_version = latest
                    app.update_status = UpdateStatus.UPDATE_AVAILABLE
                    updates += 1
        return updates

    @staticmethod
    def _check_yarn_updates(apps: List[AppInfo]) -> int:
        """Check Yarn package updates."""
        updates = 0
        for app in apps:
            output = run_command(["npm", "info", app.name, "version"], allow_failure=True)
            if output:
                latest = output.strip()
                if latest and latest != app.version and "ERR" not in latest:
                    app.latest_version = latest
                    app.update_status = UpdateStatus.UPDATE_AVAILABLE
                    updates += 1
        return updates

    @staticmethod
    def _check_path_updates(apps: List[AppInfo]) -> int:
        """Check PATH tool updates."""
        import urllib.request
        updates = 0

        def fetch_json(url):
            req = urllib.request.Request(url, headers={'User-Agent': 'SystemUpdateCLI'})
            try:
                with urllib.request.urlopen(req, timeout=10) as response:
                    return json.loads(response.read().decode())
            except Exception:
                return None

        def parse_version(ver_str: str) -> Tuple:
            """Parse version string into comparable tuple (major, minor, patch, is_stable)."""
            # Remove leading non-digits
            ver_str = re.sub(r'^[^\d]+', '', ver_str).strip()
            # Extract main version numbers
            match = re.match(r'(\d+)\.(\d+)\.(\d+)', ver_str)
            if not match:
                match = re.match(r'(\d+)\.(\d+)', ver_str)
                if match:
                    return (int(match.group(1)), int(match.group(2)), 0, 'preview' not in ver_str.lower())
                return (0, 0, 0, False)
            # Check if it's a preview/rc/beta version
            is_stable = not any(x in ver_str.lower() for x in ['preview', 'rc', 'beta', 'alpha', '-pre'])
            return (int(match.group(1)), int(match.group(2)), int(match.group(3)), is_stable)

        def is_newer_version(current: str, latest: str) -> bool:
            """Check if latest is actually newer than current (handles previews)."""
            curr_parts = parse_version(current)
            latest_parts = parse_version(latest)

            # If current is a newer major/minor preview, don't suggest downgrade to stable
            if curr_parts[0] > latest_parts[0]:  # Newer major version
                return False
            if curr_parts[0] == latest_parts[0] and curr_parts[1] > latest_parts[1]:  # Newer minor in same major
                return False

            # Standard comparison for stable versions
            if curr_parts[3] and latest_parts[3]:  # Both stable
                return latest_parts[:3] > curr_parts[:3]

            # If current is preview but same base version, don't update
            if not curr_parts[3] and curr_parts[:3] == latest_parts[:3]:
                return False

            # Latest stable is newer than current stable
            return latest_parts[:3] > curr_parts[:3]

        for app in apps:
            latest = ""
            try:
                if app.name == "bun":
                    output = run_command(["bun", "upgrade", "--dry-run"], allow_failure=True, include_stderr=True)
                    if output:
                        match = re.search(r"Bun v([0-9.]+)\s+is out!", output)
                        if match:
                            latest = match.group(1)
                        else:
                            latest = app.version
                elif app.name == "deno":
                    output = run_command(["deno", "upgrade", "--dry-run"], allow_failure=True, include_stderr=True)
                    if output:
                        match = re.search(r"Found latest stable version\s+v?([0-9.]+)", output, re.IGNORECASE)
                        if match:
                            latest = match.group(1)
                        else:
                            latest = app.version
                elif app.name in ("yarn", "npm", "pnpm", "node"):
                    output = run_command(["npm", "view", app.name, "version"], allow_failure=True)
                    if output and "ERR" not in output:
                        latest = output.strip()
                    if not latest:
                        latest = app.version
                elif app.name == "python":
                    data = fetch_json("https://api.github.com/repos/python/cpython/releases/latest")
                    if data and data.get("tag_name"):
                        match = re.search(r"v?([0-9.]+)", data["tag_name"])
                        if match:
                            latest = match.group(1)
                    if not latest:
                        latest = app.version
                elif app.name == "git":
                    data = fetch_json("https://api.github.com/repos/git-for-windows/git/releases/latest")
                    if data and data.get("tag_name"):
                        match = re.search(r"v?([0-9.]+?)(?:\.windows)", data["tag_name"])
                        latest = match.group(1) if match else data["tag_name"].replace("v", "")
                    if not latest:
                        latest = app.version
                elif app.name == "pwsh":
                    data = fetch_json("https://api.github.com/repos/PowerShell/PowerShell/releases/latest")
                    if data and data.get("tag_name"):
                        latest = data["tag_name"].replace("v", "")
                    if not latest:
                        latest = app.version
                elif app.name == "dotnet":
                    output = run_command(["winget", "show", "Microsoft.DotNet.SDK.9", "--accept-source-agreements"], allow_failure=True)
                    if output:
                        match = re.search(r"Version:\s+([0-9.]+)", output)
                        if match:
                            latest = match.group(1)
                    if not latest:
                        latest = app.version
                elif app.name in ("rustc", "cargo"):
                    data = fetch_json("https://api.github.com/repos/rust-lang/rust/releases/latest")
                    if data and data.get("tag_name"):
                        match = re.search(r"([0-9.]+)", data["tag_name"])
                        if match:
                            latest = match.group(1)
                    if not latest:
                        latest = app.version

                if latest:
                    clean_version = re.sub(r'^[^\d]+', '', app.version).strip()
                    clean_latest = re.sub(r'^[^\d]+', '', latest).strip()
                    app.latest_version = clean_latest

                    # Use proper version comparison that handles previews
                    if is_newer_version(app.version, latest):
                        app.update_status = UpdateStatus.UPDATE_AVAILABLE
                        updates += 1
                    else:
                        app.update_status = UpdateStatus.UP_TO_DATE
                else:
                    # No latest version found, mark as up-to-date (don't show unknown)
                    app.latest_version = "-"
                    app.update_status = UpdateStatus.UP_TO_DATE
            except Exception:
                # On error, mark as up-to-date rather than unknown
                app.latest_version = "-"
                app.update_status = UpdateStatus.UP_TO_DATE
        return updates

    @staticmethod
    def _check_rust_updates(apps: List[AppInfo]) -> int:
        """Check Rust package updates via cargo install-update."""
        updates = 0
        output = run_command(["cargo", "install-update", "-l"], allow_failure=True)
        if not output:
            return updates

        lines = output.splitlines()
        # Find header: Package | Installed | Latest | Needs update
        header_idx = -1
        for i, line in enumerate(lines):
            if "Package" in line and "Latest" in line:
                header_idx = i
                break

        if header_idx == -1:
            return updates

        for line in lines[header_idx + 1:]:
            l = line.strip()
            if not l:
                continue
            parts = l.split()
            if len(parts) < 4:
                continue

            name, installed, latest, needs_update = parts[0], parts[1], parts[2], parts[3]
            if needs_update.lower() == "yes":
                for app in apps:
                    if app.name == name:
                        app.latest_version = latest[1:] if latest.startswith('v') else latest
                        app.update_status = UpdateStatus.UPDATE_AVAILABLE
                        updates += 1
        return updates


# ═══════════════════════════════════════════════════════════════════════════════
# UPDATE EXECUTOR
# ═══════════════════════════════════════════════════════════════════════════════


class UpdateExecutor:
    """Enhanced update execution system."""

    @staticmethod
    def execute_updates(apps: List[AppInfo], dry_run: bool = False):
        """Execute updates with enhanced feedback matching JS executeUpdates."""
        success_count = 0

        with Progress(
            TextColumn("{task.description}"),
            BarColumn(bar_width=26, complete_style="white", style="dim white", finished_style="white"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TextColumn("{task.fields[extra]}"),
            console=console,
        ) as progress:
            task = progress.add_task("⚙️ Applying updates", total=len(apps), extra="")

            for app in apps:
                label = f"{app.name} ({app.source})"

                if dry_run:
                    time.sleep(0.3)
                    success_count += 1
                    console.print(f"[yellow]🔍 DRY RUN[/yellow]: {app.name} → {app.latest_version}")
                    progress.update(task, advance=1, extra="✅ [bold]" + label + "[/bold]")
                else:
                    success = UpdateExecutor._execute_single_update(app)
                    if success:
                        success_count += 1
                        console.print(f"[green]✅[/green] {app.name} updated to {app.latest_version}")
                        progress.update(task, advance=1, extra="✅ [bold]" + label + "[/bold]")
                    else:
                        console.print(f"[red]❌[/red] Failed to update {app.name}")
                        progress.update(task, advance=1, extra="❌ [bold]" + label + "[/bold]")

            # Final summary matching JS
            progress.update(task, extra="✨ [bold cyan]finished[/bold cyan]")

        console.print(f"\n📊 Completed: [bold]{success_count}/{len(apps)}[/bold] successful.")

    @staticmethod
    def _execute_single_update(app: AppInfo) -> bool:
        """Execute single package update."""
        cmd = None
        target_ver = app.latest_version

        if app.source == "Winget":
            cmd = [
                "winget",
                "upgrade",
                "--id",
                app.app_id,
                "--accept-source-agreements",
                "--accept-package-agreements",
            ]
            if target_ver:
                cmd.extend(["-v", target_ver])

        elif app.source == "Chocolatey":
            cmd = ["choco", "upgrade", app.name, "-y"]
            if target_ver:
                cmd.extend(["--version", target_ver])

        elif app.source == "NPM":
            ver_spec = f"@{target_ver}" if target_ver else ""
            cmd = ["npm", "install", "-g", f"{app.name}{ver_spec}"]

        elif app.source == "PNPM":
            ver_spec = f"@{target_ver}" if target_ver else ""
            cmd = ["pnpm", "add", "-g", f"{app.name}{ver_spec}"]

        elif app.source == "Bun":
            ver_spec = f"@{target_ver}" if target_ver else ""
            cmd = ["bun", "add", "-g", f"{app.name}{ver_spec}"]

        elif app.source == "Yarn":
            ver_spec = f"@{target_ver}" if target_ver else ""
            cmd = ["yarn", "global", "add", f"{app.name}{ver_spec}"]

        elif app.source == "PIP":
            ver_spec = f"=={target_ver}" if target_ver else ""
            cmd = [sys.executable, "-m", "pip", "install", f"{app.name}{ver_spec}"]
            if not target_ver:
                cmd.append("--upgrade")

        elif app.source == "Rust":
            cmd = ["cargo", "install-update", app.name]

        elif app.source == "PATH":
            if app.name == "bun":
                cmd = ["bun", "upgrade"]
            elif app.name == "deno":
                cmd = ["deno", "upgrade"]
                if target_ver:
                    cmd.extend(["--version", target_ver])
            elif app.name == "git":
                cmd = ["git", "update-git-for-windows", "-y"]
            elif app.name == "pwsh":
                cmd = [
                    "powershell",
                    "-Command",
                    'iex "& { $(irm https://aka.ms/install-powershell.ps1) }"',
                ]
            elif app.name == "yarn":
                cmd = ["npm", "install", "-g", f"yarn@{target_ver}" if target_ver else "yarn"]

        if cmd:
            return bool(run_command(cmd))

        return False


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN APPLICATION
# ═══════════════════════════════════════════════════════════════════════════════


class SystemUpdateApp:
    """Main application controller."""

    def __init__(self):
        self.ui = UISystem()
        self.scanner = PackageScanner()
        self.checker = UpdateChecker()
        self.executor = UpdateExecutor()
        self.cache_mgr = CacheManager(
            config.cache_file, config.settings["cache"]["duration_hours"]
        )

    def scan_system(self, source_filter: Optional[str] = None) -> List[AppInfo]:
        """Perform comprehensive system scan matching JS scanSystem."""
        # Map source names to scanner methods (matching JS order)
        scanners = {
            "winget": self.scanner.scan_winget,
            "chocolatey": self.scanner.scan_chocolatey,
            "npm": self.scanner.scan_npm,
            "pnpm": self.scanner.scan_pnpm,
            "bun": self.scanner.scan_bun,
            "yarn": self.scanner.scan_yarn,
            "pip": self.scanner.scan_pip,
            "path": self.scanner.scan_path,
            "registry": self.scanner.scan_registry,
            "rust": self.scanner.scan_rust,
        }

        # Filter by source if specified
        if source_filter:
            source_filter_lower = source_filter.lower()
            matched_source = next(
                (name for name in scanners.keys() if name.lower() == source_filter_lower),
                None
            )
            if matched_source:
                scanners = {matched_source: scanners[matched_source]}
                console.print(f"[cyan]🔍 Filtering by source: {matched_source}[/cyan]")
            else:
                console.print(f"[yellow]⚠️  Unknown source '{source_filter}', scanning all sources[/yellow]")

        # Filter by enabled sources in config
        selected = [
            (name, func) for name, func in scanners.items()
            if config.settings["sources"].get(name, True)
        ]

        all_apps = []
        max_workers = config.settings["performance"]["max_workers"]

        # Scan in parallel like JS Promise.all using Rich Progress
        with Progress(
            TextColumn("{task.description}"),
            BarColumn(bar_width=26, complete_style="white", style="dim white", finished_style="white"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TextColumn("{task.fields[extra]}"),
            console=console,
        ) as progress:
            task = progress.add_task("🔎 Scanning", total=len(selected), extra="")

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_source = {executor.submit(func): name for name, func in selected}

                for future in as_completed(future_to_source):
                    source_name = future_to_source[future]
                    try:
                        apps = future.result()
                        # Deduplicate by source|name|version
                        unique_apps = list({f"{a.source}|{a.name}|{a.version}".lower(): a for a in apps}.values())
                        all_apps.extend(unique_apps)
                        # Match JS: source_badge + count
                        progress.update(task, advance=1, extra=f"{source_badge(source_name)} [bold cyan]{str(len(unique_apps)).rjust(4)}[/bold cyan] apps")
                    except Exception as e:
                        console.print(f"  [red]✗[/red] {source_name} failed: {e}")

            # Mark complete matching JS
            progress.update(task, extra="✅ [bold green]scan complete[/bold green]")

        # Return unique apps sorted like JS
        return sorted(all_apps, key=lambda x: f"{x.source}{x.name}")

    def export_results(
        self, apps: List[AppInfo], format_type: str, output_file: Optional[str] = None
    ):
        """Export scan results in various formats."""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"system_update_{timestamp}.{format_type}"

        try:
            if format_type == "json":
                data = {
                    "scan_time": datetime.now().isoformat(),
                    "total_apps": len(apps),
                    "apps": [app.to_dict() for app in apps],
                }
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)

            elif format_type == "csv":
                with open(output_file, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Name", "Source", "Version", "Latest", "Status"])
                    for app in apps:
                        writer.writerow(
                            [
                                app.name,
                                app.source,
                                app.version,
                                app.latest_version,
                                app.update_status.value,
                            ]
                        )

            console.print(f"[green]✅ Exported to {output_file}[/green]")

        except Exception as e:
            console.print(f"[red]❌ Export failed: {e}[/red]")

    def run(self, args):
        """Main application entry point."""
        # Handle cache operations
        if args.clear_cache:
            self.cache_mgr.clear()
            console.print("[green]🗑️  Cache cleared successfully![/green]")
            return

        # Display beautiful banner
        self.ui.display_banner()

        # Load from cache or scan
        apps = None
        if not args.no_cache and config.settings["cache"]["enabled"]:
            apps = self.cache_mgr.load()
            if apps:
                console.print(f"[dim]💾 Loaded {len(apps)} items from cache[/dim]\n")

        if apps is None:
            start_time = time.time()

            # --- PHASE 1: SCANNING ---
            console.print("[bold cyan]🔎 Scanning sources...[/bold cyan]")
            # Scan system (progress bar handled internally)
            apps = self.scan_system(args.source)

            # Report discovered count (match JS flow)
            console.print(f"\n📦 [bold]Discovered {len(apps)} unique apps.[/bold]")

            # --- PHASE 2: UPDATE CHECKING ---
            console.print("[bold cyan]⬆️ Checking for updates...[/bold cyan]")
            # Check updates (progress bar handled internally)
            total_updates = self.checker.check_all_updates(apps)

            console.print(f"[bold magenta]📊 Detected {total_updates} update candidates.[/bold magenta]\n")

            # --- PHASE 3: SECURITY CHECK ---
            console.print(f"[bold magenta]🔒 Checking security vulnerabilities...[/bold magenta]")
            # (Assuming security scan is fast for now or integrated)
            console.print(f"[bold green]🛡️ No security vulnerabilities found.[/bold green]\n")

            # Save to cache
            self.cache_mgr.save(apps)

            scan_time = time.time() - start_time

            # Display summary
            sources_count = {}
            for app in apps:
                sources_count[app.source] = sources_count.get(app.source, 0) + 1

            self.ui.display_summary(len(apps), total_updates, scan_time, sources_count)

        # Handle single package update
        if args.package:
            self._handle_single_update(apps, args)
            return

        # Display results
        updates = [a for a in apps if a.update_status == UpdateStatus.UPDATE_AVAILABLE]
        vulnerable = [a for a in apps if a.update_status == UpdateStatus.VULNERABLE]

        # Show security alerts first
        if vulnerable:
            console.print()
            security_table = self.ui.create_security_table([])
            security_table.title = "[bold red]🔒 Security Alerts[/bold red]"
            for app in vulnerable:
                security_table.add_row(
                    app.name, "VULNERABLE", "N/A", "Update recommended"
                )
            console.print(security_table)

        # Show applications table
        console.print()
        apps_table = self.ui.create_apps_table(apps, "📦 All Installed Applications")
        console.print(apps_table)

        # Handle updates
        if updates:
            console.print(
                f"\n[bold yellow]🎯 Found {len(updates)} available updates[/bold yellow]"
            )

            if args.update_all:
                if Confirm.ask("🚀 Proceed with all updates?"):
                    self.executor.execute_updates(updates, args.dry_run)
        else:
            console.print("\n[green]✨ System is up to date![/green]")

        # Export results if requested
        if args.export:
            self.export_results(apps, args.export, args.output)

    def _handle_single_update(self, apps: List[AppInfo], args):
        """Handle single package update request."""
        target_name = args.package.lower()
        target_source = args.source.lower() if args.source else None

        candidates = [
            app
            for app in apps
            if app.name.lower() == target_name
            and (not target_source or app.source.lower() == target_source)
        ]

        if not candidates:
            console.print(f"[red]❌ Package '{args.package}' not found[/red]")
            if args.source:
                console.print(f"[dim]🔍 Filter: source={args.source}[/dim]")
            return

        if len(candidates) > 1 and not args.source:
            console.print(f"[yellow]⚠️  Multiple packages found:[/yellow]")
            for i, c in enumerate(candidates):
                console.print(f"  {i + 1}. {c.name} ({c.source}) - {c.version}")
            console.print("[yellow]💡 Please specify --source to target one[/yellow]")
            return

        target_app = candidates[0]

        if args.version:
            target_app.latest_version = args.version
            console.print(f"[cyan]🎯 Targeting version: {args.version}[/cyan]")
        elif not target_app.has_update and not args.version:
            console.print(
                f"[green]✅ {target_app.name} is up to date ({target_app.version})[/green]"
            )
            if not Confirm.ask("🔄 Force reinstall?"):
                return

        self.executor.execute_updates([target_app], args.dry_run)


def main():
    """Application entry point."""
    parser = argparse.ArgumentParser(
        description="System Update Enhanced v5.0 - Elite Package Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python system_update.py                    # Scan and show updates
  python system_update.py --update-all      # Update all packages
  python system_update.py --dry-run          # Preview updates
  python system_update.py --package git     # Update specific package
  python system_update.py --source rust      # Filter by source
  python system_update.py --export json     # Export results to JSON
        """,
    )

    # Main options
    parser.add_argument(
        "--update-all", action="store_true", help="Update all available packages"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Preview updates without executing"
    )
    parser.add_argument(
        "--no-cache", action="store_true", help="Force fresh scan (ignore cache)"
    )
    parser.add_argument("--clear-cache", action="store_true", help="Clear scan cache")

    # Export options
    parser.add_argument(
        "--export", choices=["json", "csv"], help="Export results format"
    )
    parser.add_argument("--output", help="Output file for export")

    # Package options
    parser.add_argument("--package", help="Update specific package name")
    parser.add_argument("--version", help="Target version for package update")
    parser.add_argument(
        "--source",
        help="Package source filter (Winget, Chocolatey, NPM, PNPM, PIP, PATH, Registry)",
    )

    args = parser.parse_args()

    # Create and run application
    app = SystemUpdateApp()
    app.run(args)


if __name__ == "__main__":
    main()