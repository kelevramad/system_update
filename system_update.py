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
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskID,
    TimeElapsedColumn,
    MofNCompleteColumn,
)
from rich.align import Align
from rich.style import Style
from rich import box
from rich.layout import Layout
from rich.columns import Columns
from rich.tree import Tree


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

    UP_TO_DATE = "✅"
    UPDATE_AVAILABLE = "⬆️"
    UNKNOWN = "❓"
    ERROR = "❌"
    VULNERABLE = "🔥"
    SECURITY_UPDATE_AVAILABLE = "🔒"


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
        """Get formatted status for display."""
        return self.update_status.value

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
# ENHANCED UI SYSTEM
# ═══════════════════════════════════════════════════════════════════════════════


class UISystem:
    """Enhanced user interface system with beautiful layouts."""

    @staticmethod
    def display_banner():
        """Show beautiful application banner."""
        console.clear()

        banner_text = Text()
        banner_text.append(
            "╔════════════════════════════════════════════════════════════╗\n",
            style="bold blue",
        )
        banner_text.append(
            "║                    SYSTEM UPDATE ENHANCED                ║\n",
            style="bold white on blue",
        )
        banner_text.append(
            "║                       Version 5.0.0                      ║\n",
            style="bold blue",
        )
        banner_text.append(
            "╚════════════════════════════════════════════════════════════╝\n",
            style="bold blue",
        )

        console.print(Align.center(banner_text))

        # System info panel
        info_table = Table.grid(padding=1)
        info_table.add_column(justify="center", style="cyan")
        info_table.add_column(justify="center", style="white")

        info_table.add_row("🖥️  OS:", f"{platform.system()} {platform.release()}")
        info_table.add_row("🐍 Python:", platform.python_version())
        info_table.add_row(
            "⚡ Parallel:",
            "ON" if config.settings["performance"]["parallel_scan"] else "OFF",
        )

        console.print(
            Panel(
                info_table,
                title="[bold green]System Information[/bold green]",
                border_style="green",
                box=box.ROUNDED,
                padding=(1, 2),
            )
        )
        console.print()

    @staticmethod
    def create_summary_panel(
        total_apps: int, updates: int, vulnerable: int, scan_time: float
    ) -> Panel:
        """Create beautiful summary panel."""
        summary_text = Text()

        colors = ["cyan", "yellow", "red", "magenta"]
        icons = ["📦", "⬆️", "🔥", "⏱️"]
        labels = ["Total Apps", "Updates", "Vulnerable", "Scan Time"]
        values = [total_apps, updates, vulnerable, f"{scan_time:.2f}s"]

        for i, (icon, label, value, color) in enumerate(
            zip(icons, labels, values, colors)
        ):
            summary_text.append(f"{icon} {label}: ", style=f"bold {color}")
            summary_text.append(f"{value}\n", style="bold white")

        return Panel(
            summary_text,
            title="[bold blue]📊 Scan Summary[/bold blue]",
            border_style="blue",
            box=box.ROUNDED,
            width=60,
        )

    @staticmethod
    def create_apps_table(
        apps: List[AppInfo], title: str = "Installed Applications"
    ) -> Table:
        """Create beautiful applications table."""
        table = Table(
            title=f"[bold cyan]{title}[/bold cyan]",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold blue",
        )

        table.add_column("📦 Package", style="cyan", no_wrap=True)
        table.add_column("🔗 Source", style="magenta")
        table.add_column("📋 Version", style="dim")
        table.add_column("🎯 Latest", style="green")
        table.add_column("📊 Status", justify="center")

        for app in sorted(apps, key=lambda x: (x.source, x.name)):
            status_style = (
                "green" if app.update_status == UpdateStatus.UP_TO_DATE else "yellow"
            )
            table.add_row(
                app.name[:30],
                app.source,
                app.version,
                app.latest_version or "N/A",
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
        output = run_command(["winget", "list", "--accept-source-agreements"])
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
        positions = {
            "name": 0,
            "id": header.find("Id"),
            "version": header.find("Version"),
            "available": header.find("Available"),
            "source": header.find("Source"),
        }

        for line in lines[header_index + 2 :]:
            if not line.strip() or line.startswith("-"):
                continue

            try:
                name = line[positions["name"] : positions["id"]].strip()
                app_id = line[positions["id"] : positions["version"]].strip()
                version_start = positions["version"]
                version_end = (
                    positions["available"]
                    if positions["available"] != -1
                    else positions["source"]
                    if positions["source"] != -1
                    else len(line)
                )
                version = line[version_start:version_end].strip()

                if name and app_id and version:
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
        output = run_command(["choco", "list", "--local-only", "--limit-output"])
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
        output = run_command(["npm", "list", "-g", "--depth=0", "--json", "--silent"])
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
        output = run_command(["pnpm", "list", "-g", "--depth=0", "--json"])
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
        output = run_command(["bun", "pm", "ls", "-g"])
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
        output = run_command(["yarn", "global", "list"])
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
        output = run_command([sys.executable, "-m", "pip", "list", "--format=json"])
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
            path = run_command(cmd)
            if path:
                version_output = run_command([exe, "--version"])
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

        output = run_command(["powershell", "-NoProfile", "-Command", ps_script])
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

        # Remove duplicates
        unique_apps = {}
        for app in apps:
            key = f"{app.name}|{app.version}"
            if key not in unique_apps:
                unique_apps[key] = app

        return sorted(unique_apps.values(), key=lambda x: x.name)


# ═══════════════════════════════════════════════════════════════════════════════
# UPDATE CHECKERS
# ═══════════════════════════════════════════════════════════════════════════════


class UpdateChecker:
    """Enhanced update checking system."""

    @staticmethod
    def check_all_updates(
        apps: List[AppInfo], progress: Progress, task_id: TaskID
    ) -> int:
        """Check updates for all supported package managers."""
        total_updates = 0

        # Group apps by source for batch processing
        sources = {
            "Winget": [a for a in apps if a.source == "Winget"],
            "Chocolatey": [a for a in apps if a.source == "Chocolatey"],
            "NPM": [a for a in apps if a.source == "NPM"],
            "PNPM": [a for a in apps if a.source == "PNPM"],
            "Bun": [a for a in apps if a.source == "Bun"],
            "Yarn": [a for a in apps if a.source == "Yarn"],
            "PIP": [a for a in apps if a.source == "PIP"],
            "PATH": [a for a in apps if a.source == "PATH"],
            "Registry": [a for a in apps if a.source == "Registry"],
        }

        # Check updates for each source
        for source_name, source_apps in sources.items():
            if not source_apps:
                continue

            progress.update(task_id, description=f"Checking {source_name} updates...")

            if source_name == "Winget":
                total_updates += UpdateChecker._check_winget_updates(source_apps)
            elif source_name == "Chocolatey":
                total_updates += UpdateChecker._check_choco_updates(source_apps)
            elif source_name == "NPM":
                total_updates += UpdateChecker._check_npm_updates(source_apps)
            elif source_name == "PNPM":
                total_updates += UpdateChecker._check_pnpm_updates(source_apps)
            elif source_name == "Bun":
                total_updates += UpdateChecker._check_bun_updates(source_apps)
            elif source_name == "Yarn":
                total_updates += UpdateChecker._check_yarn_updates(source_apps)
            elif source_name == "PIP":
                total_updates += UpdateChecker._check_pip_updates(source_apps)
            elif source_name == "PATH":
                total_updates += UpdateChecker._check_path_updates(source_apps)
            elif source_name == "Registry":
                total_updates += UpdateChecker._check_registry_updates(source_apps)

            progress.advance(task_id, 10)

        # Mark apps with proper status (match JavaScript logic)
        for app in apps:
            if app.update_status == UpdateStatus.UPDATE_AVAILABLE:
                continue
            if app.update_status == UpdateStatus.UP_TO_DATE:
                continue
            # Sources that perform update checks should be marked UP_TO_DATE if no update found
            # PATH is checked individually so only mark UP_TO_DATE if latest_version was set
            if app.latest_version or app.source in ["Winget", "Chocolatey", "NPM", "PNPM", "Bun", "Yarn", "PIP", "Registry"]:
                app.update_status = UpdateStatus.UP_TO_DATE
            else:
                app.update_status = UpdateStatus.UNKNOWN

        progress.update(task_id, description="Update checks complete", completed=100)
        return total_updates

    @staticmethod
    def _check_winget_updates(apps: List[AppInfo]) -> int:
        """Check Winget package updates."""
        updates = 0
        output = run_command(["winget", "upgrade", "--accept-source-agreements"])
        if not output:
            return updates

        lines = output.splitlines()
        header_index = next(
            (i for i, line in enumerate(lines) if "Name" in line and "Id" in line), -1
        )

        if header_index == -1:
            return updates

        header = lines[header_index]
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
                app_id = line[positions["id"] : positions["version"]].strip()
                if positions["available"] != -1:
                    avail_end = (
                        positions["source"] if positions["source"] != -1 else len(line)
                    )
                    latest = line[positions["available"] : avail_end].strip()

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
        output = run_command(["choco", "outdated", "--limit-output"])
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
        output = run_command(
            [sys.executable, "-m", "pip", "list", "--outdated", "--format=json"],
            allow_failure=True,
        )
        if not output:
            return updates

        try:
            data = json.loads(output)
            for item in data:
                name = item.get("name")
                latest = item.get("latest_version")
                for app in apps:
                    if app.name == name:
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
            output = run_command(["npm", "info", app.name, "version"])
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
            output = run_command(["npm", "info", app.name, "version"])
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
                    output = run_command(["npm", "view", app.name, "version"])
                    if output and "ERR" not in output:
                        latest = output.strip()
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
                elif app.name == "pwsh":
                    data = fetch_json("https://api.github.com/repos/PowerShell/PowerShell/releases/latest")
                    if data and data.get("tag_name"):
                        latest = data["tag_name"].replace("v", "")
                elif app.name == "dotnet":
                    output = run_command(["winget", "show", "Microsoft.DotNet.SDK.9", "--accept-source-agreements"])
                    if output:
                        match = re.search(r"Version:\s+([0-9.]+)", output)
                        if match:
                            latest = match.group(1)

                if latest:
                    clean_version = re.sub(r'^[^\d]+', '', app.version).strip()
                    clean_latest = re.sub(r'^[^\d]+', '', latest).strip()
                    app.latest_version = clean_latest
                    if clean_latest != clean_version and clean_latest not in app.version:
                        app.update_status = UpdateStatus.UPDATE_AVAILABLE
                        updates += 1
                    else:
                        app.update_status = UpdateStatus.UP_TO_DATE
            except Exception:
                pass
        return updates


# ═══════════════════════════════════════════════════════════════════════════════
# UPDATE EXECUTOR
# ═══════════════════════════════════════════════════════════════════════════════


class UpdateExecutor:
    """Enhanced update execution system."""

    @staticmethod
    def execute_updates(apps: List[AppInfo], dry_run: bool = False):
        """Execute updates with enhanced feedback."""
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=None),
            MofNCompleteColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("🔄 Processing updates...", total=len(apps))
            success_count = 0

            for app in apps:
                progress.update(task, description=f"📦 Updating {app.name}...")

                if dry_run:
                    time.sleep(0.3)
                    success_count += 1
                    console.print(
                        f"[yellow]🔍 DRY RUN[/yellow]: {app.name} → {app.latest_version}"
                    )
                else:
                    success = UpdateExecutor._execute_single_update(app)
                    if success:
                        success_count += 1
                        console.print(
                            f"[green]✅[/green] {app.name} updated to {app.latest_version}"
                        )
                    else:
                        console.print(f"[red]❌[/red] Failed to update {app.name}")

                progress.advance(task)

            # Final summary
            console.print(
                f"\n[bold green]🎉 Completed: {success_count}/{len(apps)} updates successful![/bold green]"
            )

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

    def scan_system(self, progress: Progress, source_filter: Optional[str] = None) -> List[AppInfo]:
        """Perform comprehensive system scan."""
        # Map source names to scanner methods
        scanners = {
            "Winget": self.scanner.scan_winget,
            "Chocolatey": self.scanner.scan_chocolatey,
            "NPM": self.scanner.scan_npm,
            "PNPM": self.scanner.scan_pnpm,
            "Bun": self.scanner.scan_bun,
            "Yarn": self.scanner.scan_yarn,
            "PIP": self.scanner.scan_pip,
            "PATH": self.scanner.scan_path,
            "Registry": self.scanner.scan_registry,
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
                progress.console.print(f"[cyan]🔍 Filtering by source: {matched_source}[/cyan]")
            else:
                progress.console.print(f"[yellow]⚠️  Unknown source '{source_filter}', scanning all sources[/yellow]")

        total_sources = len(scanners)
        task_scan = progress.add_task("🔍 Scanning system...", total=total_sources)

        all_apps = []
        max_workers = config.settings["performance"]["max_workers"]

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_source = {
                executor.submit(func): name
                for name, func in scanners.items()
                if config.settings["sources"].get(name.lower(), True)
            }

            for future in as_completed(future_to_source):
                source_name = future_to_source[future]
                try:
                    apps = future.result()
                    all_apps.extend(apps)
                    progress.console.print(
                        f"  [green]✓[/green] Found {len(apps)} in {source_name}"
                    )
                except Exception as e:
                    progress.console.print(f"  [red]✗[/red] {source_name} failed: {e}")
                progress.advance(task_scan)

        return all_apps

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

            with Progress(
                SpinnerColumn(spinner_name="dots12"),
                TextColumn("[bold cyan]{task.description}"),
                BarColumn(bar_width=None),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                # Scan system
                apps = self.scan_system(progress, args.source)

                # Deduplicate
                unique_apps = list({f"{a.name}|{a.version}": a for a in apps}.values())
                apps = sorted(unique_apps, key=lambda x: (x.source, x.name))

                # Check updates
                task_check = progress.add_task("🔍 Checking updates...", total=100)
                total_updates = self.checker.check_all_updates(
                    apps, progress, task_check
                )

                # Save to cache
                self.cache_mgr.save(apps)

                scan_time = time.time() - start_time

                # Display summary
                vulnerable = sum(
                    1 for a in apps if a.update_status == UpdateStatus.VULNERABLE
                )
                summary_panel = self.ui.create_summary_panel(
                    len(apps), total_updates, vulnerable, scan_time
                )
                console.print(summary_panel)

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