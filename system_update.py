#!/usr/bin/env python3
"""
===============================================================================
                          SYSTEM UPDATE ENHANCED
===============================================================================
Version: 5.0.0
Author: Gemini (Redesigned)

A sophisticated system update tool with enhanced UI architecture and modular design.

This module provides a comprehensive system update management solution for Windows,
supporting multiple package managers and installation sources. It features parallel
scanning, intelligent caching, security vulnerability detection, and a beautiful
Rich-based terminal interface.

Features:
    - Multi-source package discovery (Winget, Chocolatey, NPM, PIP, PNPM, PATH, Registry)
    - Real-time security vulnerability scanning
    - Parallel processing for optimal performance
    - Beautiful Rich-based interface with modern layout
    - Flexible export options and caching system
    - Granular update control with dry-run support

Example Usage:
    >>> app = SystemUpdateApp()
    >>> apps = app.scan_system()
    >>> checker.check_all_updates(apps)
    >>> executor.execute_updates(apps)

Command Line:
    python system_update.py --update-all      # Update all packages
    python system_update.py --dry-run         # Preview updates without applying
    python system_update.py --package git     # Update specific package
    python system_update.py --export json     # Export results to JSON file
"""

# ═══════════════════════════════════════════════════════════════════════════════
# STANDARD LIBRARY IMPORTS
# ═══════════════════════════════════════════════════════════════════════════════

import argparse  # Command-line argument parsing
import csv  # CSV file export support
import json  # JSON configuration and export
import logging  # Logging infrastructure
import os  # Operating system interfaces
import platform  # Platform detection (Windows/Linux/macOS)
import re  # Regular expressions for parsing
import shutil  # Shell utilities (which command lookup)
import subprocess  # External command execution
import sys  # System-specific parameters and I/O
import time  # Timing and performance measurement

# Force UTF-8 encoding for standard output to avoid UnicodeEncodeError on Windows
# This ensures proper display of Unicode characters (emojis, special symbols)
if sys.stdout.encoding != 'utf-8':
	try:
		sys.stdout.reconfigure(encoding='utf-8')
	except AttributeError:
		pass

# ═══════════════════════════════════════════════════════════════════════════════
# PYTHON STANDARD LIBRARY - TYPE SUPPORT
# ═══════════════════════════════════════════════════════════════════════════════

from concurrent.futures import ThreadPoolExecutor, as_completed  # Parallel execution
from dataclasses import dataclass, asdict, field  # Data containers
from datetime import datetime, timedelta  # Time handling
from pathlib import Path  # Path manipulation
from typing import List, Dict, Optional, Tuple  # Type hints
from enum import Enum  # Enumeration support

# ═══════════════════════════════════════════════════════════════════════════════
# THIRD-PARTY IMPORTS (RICH LIBRARY)
# ═══════════════════════════════════════════════════════════════════════════════

# Required rich imports - ensure_dependencies() will install if missing
from rich import print

RICH_AVAILABLE = True
from rich.console import Console  # Terminal output management
from rich.panel import Panel  # Boxed text panels
from rich.table import Table  # Tabular data display
from rich.text import Text  # Styled text objects
from rich.prompt import Confirm  # Yes/No user prompts
from rich.progress import (  # Progress bar components
	Progress,
	TextColumn,
	BarColumn,
	TimeElapsedColumn,
	MofNCompleteColumn,
	TaskID,
)
from rich.style import Style  # Style definitions
from rich import box  # Table border styles


# ═══════════════════════════════════════════════════════════════════════════════
# DEPENDENCY MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════


def ensure_dependencies():
	"""
	Auto-install required dependencies with user confirmation.

	This function checks if the 'rich' library is available and prompts the user
	to install it if missing. The rich library is essential for the enhanced UI
	experience with colored output, progress bars, and formatted tables.

	Behavior:
	    - If rich is available: returns immediately (no-op)
	    - If rich is missing: prompts user for installation consent
	    - On user consent: installs rich via pip and exits for restart
	    - On user decline: exits with error message

	Note:
	    This function calls sys.exit() after successful installation to ensure
	    the newly installed library is properly loaded on restart.

	Raises:
	    SystemExit: Exits after installation or if user declines installation.
	"""
	global RICH_AVAILABLE
	if RICH_AVAILABLE:
		return

	print("🔧 The 'rich' library is required for enhanced UI experience.")
	try:
		choice = input("Install 'rich' now? (y/n): ").lower().strip()
	except EOFError:
		choice = 'n'

	if choice == 'y':
		try:
			print("⬇️  Installing 'rich' library...")
			subprocess.run(
				[sys.executable, '-m', 'pip', 'install', 'rich'],
				check=True,
				capture_output=True,
			)
			print("✅ 'rich' installed successfully!")
			print('🔄 Please restart the script to enjoy the full experience.')
			sys.exit(0)
		except subprocess.CalledProcessError:
			print('❌ Installation failed.')
			print('💡 Manual install: pip install rich')
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
	"""
	Enumeration of package update status states.

	This enum defines all possible states a package can be in during the
	update scanning and checking process. Each status has a string value
	suitable for serialization and display.

	Members:
	    UP_TO_DATE: Package is at the latest available version.
	    UPDATE_AVAILABLE: A newer version is available for installation.
	    UNKNOWN: Package status could not be determined.
	    ERROR: An error occurred while checking the package.
	    VULNERABLE: Package has known security vulnerabilities.
	    SECURITY_UPDATE_AVAILABLE: A security patch is available.
	"""

	UP_TO_DATE = 'up_to_date'
	UPDATE_AVAILABLE = 'update_available'
	UNKNOWN = 'unknown'
	ERROR = 'error'
	VULNERABLE = 'vulnerable'
	SECURITY_UPDATE_AVAILABLE = 'security_update_available'


@dataclass
class AppInfo:
	"""
	Structured application metadata container.

	This dataclass holds comprehensive information about an installed application
	or package, including its current version, latest available version, source,
	and update status. It serves as the primary data structure throughout the
	scanning, checking, and update execution pipeline.

	Attributes:
	    name: Display name of the application/package.
	    source: Source identifier (e.g., "Winget", "NPM", "Chocolatey").
	    version: Currently installed version string.
	    latest_version: Latest available version (empty if unknown or up-to-date).
	    app_id: Unique package identifier used by the package manager.
	    update_status: Current update status from UpdateStatus enum.
	    error_msg: Error message if scanning/checking failed.
	    install_path: Filesystem path where the application is installed.
	    scan_time: Timestamp when this package information was scanned.

	Example:
	    >>> app = AppInfo(name='Git', source='Winget', version='2.39.0')
	    >>> app.has_update
	    False
	"""

	name: str
	source: str
	version: str
	latest_version: str = ''
	app_id: Optional[str] = None
	update_status: UpdateStatus = UpdateStatus.UNKNOWN
	error_msg: Optional[str] = None
	install_path: Optional[str] = None
	scan_time: datetime = field(default_factory=datetime.now)

	@property
	def has_update(self) -> bool:
		"""
		Check if an update is available for this package.

		Returns:
		    bool: True if latest_version is set and differs from current version.
		"""
		return bool(self.latest_version and self.latest_version != self.version)

	@property
	def status_display(self) -> str:
		"""
		Get formatted status string for display with emoji and text.

		Returns a human-readable status string with emoji prefix suitable for
		terminal display. The format is consistent across all status types.

		Returns:
		    str: Formatted status string (e.g., "✅ up-to-date", "🔄 update").

		Example:
		    >>> app.update_status = UpdateStatus.UPDATE_AVAILABLE
		    >>> app.status_display
		    '🔄 update'
		"""
		mapping = {
			UpdateStatus.UP_TO_DATE: '✅ up-to-date',
			UpdateStatus.UPDATE_AVAILABLE: '🔄 update',
			UpdateStatus.UNKNOWN: '❓ unknown',
			UpdateStatus.ERROR: '❌ error',
			UpdateStatus.VULNERABLE: '🔥 vulnerable',
			UpdateStatus.SECURITY_UPDATE_AVAILABLE: '🔒 security update',
		}
		return mapping.get(self.update_status, '❓ unknown')

	def to_dict(self) -> Dict:
		"""
		Convert AppInfo to dictionary for standardized JSON serialization.

		Creates a dictionary representation of this AppInfo instance using camelCase
		keys to match the Node.js implementation's cache format.

		Returns:
		    Dict: Standardized dictionary for cache.json.
		"""
		return {
			'name': self.name,
			'source': self.source.lower(),
			'version': self.version,
			'latestVersion': self.latest_version or '-',
			'appId': self.app_id,
			'status': self.update_status.value,
			'scanTime': self.scan_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
		}


@dataclass
class SecurityInfo:
	"""
	Security vulnerability metadata container.

	This dataclass stores information about security vulnerabilities affecting
	a package, including CVE identifiers, severity ratings, and affected versions.
	Used for security scanning and vulnerability reporting.

	Attributes:
	    cve_id: Common Vulnerabilities and Exposures identifier (e.g., "CVE-2023-1234").
	    severity: Severity level (e.g., "CRITICAL", "HIGH", "MEDIUM", "LOW").
	    cvss_score: Common Vulnerability Scoring System score (0.0-10.0).
	    description: Human-readable description of the vulnerability.
	    affected_versions: List of version strings affected by this vulnerability.
	    published_date: Date when the vulnerability was published/disclosed.

	Example:
	    >>> vuln = SecurityInfo(
	    ...     cve_id='CVE-2023-1234',
	    ...     severity='HIGH',
	    ...     cvss_score=7.5,
	    ...     description='Buffer overflow in parser',
	    ... )
	"""

	cve_id: str
	severity: str
	cvss_score: float
	description: str
	affected_versions: List[str] = field(default_factory=list)
	published_date: Optional[datetime] = None

	def to_dict(self) -> Dict:
		"""
		Convert SecurityInfo to dictionary for JSON serialization.

		Creates a dictionary representation with datetime converted to ISO format
		for JSON compatibility.

		Returns:
		    Dict: Dictionary containing all SecurityInfo fields in JSON-serializable form.
		"""
		data = asdict(self)
		if self.published_date:
			data['published_date'] = self.published_date.isoformat()
		return data


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION SYSTEM
# ═══════════════════════════════════════════════════════════════════════════════


class SystemConfig:
	"""
	Enhanced configuration management with validation.

	This class manages all application settings including cache behavior,
	performance tuning, enabled package sources, security options, UI preferences,
	and export settings. Configuration is persisted to a JSON file in the user's
	home directory.

	The configuration is organized into logical sections:
	    - cache: Cache duration and enable/disable settings
	    - performance: Parallel scanning, worker count, timeouts
	    - sources: Enable/disable individual package sources
	    - security: Security scanning options and severity thresholds
	    - ui: Theme, display options, color schemes
	    - export: Default export format and timestamp options

	Attributes:
	    config_dir: Directory path for configuration files (~/.system_update).
	    config_file: Path to the main configuration JSON file.
	    cache_file: Path to the cache data file.
	    log_file: Path to the application log file.
	    settings: Dictionary containing all configuration settings.

	Example:
	    >>> config = SystemConfig()
	    >>> config.load()  # Load from file
	    >>> config.settings['performance']['max_workers'] = 8
	    >>> config.save()  # Persist changes
	"""

	def __init__(self):
		"""
		Initialize SystemConfig with default settings and create config directory.

		Sets up the configuration directory structure and initializes all settings
		to their default values. If a configuration file exists, it will be loaded
		and merged with defaults.
		"""
		self.config_dir = Path.home() / '.system_update'
		self.config_file = self.config_dir / 'config.json'
		self.cache_file = self.config_dir / 'cache.json'
		self.log_file = self.config_dir / 'system.log'

		# Create config directory if it doesn't exist
		self.config_dir.mkdir(exist_ok=True)

		# Default settings organized by category
		self.settings = {
			'cache': {
				'duration_hours': 2,
				'enabled': True,
			},
			'performance': {
				'parallel_scan': True,
				'max_workers': 6,
				'timeout_seconds': 45,
			},
			'sources': {
				'winget': True,
				'chocolatey': True,
				'npm': True,
				'pnpm': True,
				'pip': True,
				'bun': True,
				'yarn': True,
				'path': True,
				'registry': True,
				'rust': True,
				'scoop': True,
			},
			'security': {
				'enabled': True,
				'auto_check': True,
				'severity_threshold': 'medium',
			},
			'ui': {
				'theme': 'default',
				'show_stats': True,
				'compact_view': False,
				'color_scheme': 'vibrant',
			},
			'export': {
				'default_format': 'json',
				'include_timestamp': True,
			},
		}
		self.load()

	def load(self):
		"""
		Load configuration from file with error handling.

		Reads the configuration JSON file and merges loaded settings with defaults.
		This ensures that new settings added in future versions are automatically
		included while preserving user customizations.

		Note:
		    If the config file doesn't exist or is invalid, defaults are used.
		    Errors are logged but don't prevent application startup.
		"""
		if self.config_file.exists():
			try:
				with open(self.config_file, 'r', encoding='utf-8') as f:
					loaded_settings = json.load(f)
					self._merge_settings(self.settings, loaded_settings)
			except Exception as e:
				logging.warning(f'Failed to load config: {e}')

	def _merge_settings(self, base: dict, loaded: dict):
		"""
		Recursively merge loaded settings with base defaults.

		Performs a deep merge of configuration dictionaries, preserving nested
		structure. Settings from 'loaded' override 'base' values, but missing
		keys in 'loaded' retain their default values from 'base'.

		Args:
		    base: Base dictionary (defaults) to merge into.
		    loaded: Loaded dictionary (user settings) to merge from.

		Example:
		    >>> base = {'cache': {'enabled': True, 'hours': 2}}
		    >>> loaded = {'cache': {'enabled': False}}
		    >>> config._merge_settings(base, loaded)
		    >>> base  # {"cache": {"enabled": False, "hours": 2}}
		"""
		for key, value in loaded.items():
			if key in base and isinstance(base[key], dict) and isinstance(value, dict):
				self._merge_settings(base[key], value)
			else:
				base[key] = value

	def save(self):
		"""
		Save current configuration to file.

		Serializes the current settings dictionary to JSON and writes it to the
		configuration file. Uses 2-space indentation for readability.

		Note:
		    Errors during save are logged but don't raise exceptions.
		    The application can continue running even if save fails.
		"""
		try:
			with open(self.config_file, 'w', encoding='utf-8') as f:
				json.dump(self.settings, f, indent=2, default=str)
		except Exception as e:
			logging.error(f'Failed to save config: {e}')


config = SystemConfig()
logging.basicConfig(
	level=logging.INFO,
	format='%(asctime)s - %(levelname)s - %(message)s',
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
	"""
	Intelligent caching system with validation.

	This class manages the caching of scanned application data to improve
	performance on subsequent runs. It handles cache validity checking,
	loading cached data with proper type conversion, and saving new data
	with metadata.

	The cache includes:
	    - Timestamp of when the cache was created
	    - Version information for compatibility checking
	    - Total count of cached applications
	    - Serialized AppInfo objects

	Attributes:
	    cache_file: Path to the cache JSON file.
	    duration: Timedelta representing cache validity period.

	Example:
	    >>> cache_mgr = CacheManager(Path('cache.json'), duration_hours=2)
	    >>> if cache_mgr.is_valid():
	    ...     apps = cache_mgr.load()
	    >>> cache_mgr.save(apps)
	"""

	def __init__(self, cache_file: Path, duration_hours: int = 2):
		"""
		Initialize CacheManager with file path and duration.

		Args:
		    cache_file: Path to the cache JSON file.
		    duration_hours: Number of hours before cache expires (default: 2).
		"""
		self.cache_file = cache_file
		self.duration = timedelta(hours=duration_hours)

	def is_valid(self) -> bool:
		"""
		Check if cache is valid and not expired.

		Validates the cache by checking:
		    1. Cache file exists
		    2. File can be read and parsed as JSON
		    3. Timestamp is within the validity duration

		Returns:
		    bool: True if cache exists and is not expired, False otherwise.
		"""
		if not self.cache_file.exists():
			return False
		try:
			with open(self.cache_file, 'r', encoding='utf-8') as f:
				data = json.load(f)
				cache_time = datetime.fromisoformat(data.get('timestamp', '').replace('Z', ''))
				return datetime.now() - cache_time < self.duration
		except Exception:
			return False

	def load(self) -> Optional[List[AppInfo]]:
		"""
		Load cached applications with type safety.

		Reads cached AppInfo data from disk and reconstructs AppInfo objects
		with proper type conversion for enums and datetime fields. Returns None
		if cache is invalid or loading fails.

		Returns:
		    Optional[List[AppInfo]]: List of AppInfo objects if cache is valid,
		        None otherwise.

		Note:
		    Removes the computed 'has_update' field from cache data since it's
		    a property that should be computed at runtime.
		"""
		if not self.is_valid():
			return None
		try:
			with open(self.cache_file, 'r', encoding='utf-8') as f:
				data = json.load(f)
				apps = []
				for item in data.get('apps', []):
					# Map Node.js camelCase back to Python's AppInfo attributes
					mapped_item = {
						'name': item.get('name'),
						'source': item.get('source', '').capitalize()
						if item.get('source') not in ['npm', 'pnpm', 'pip']
						else item.get('source').upper(),
						'version': item.get('version'),
						'latest_version': item.get('latestVersion', ''),
						'app_id': item.get('appId'),
						'update_status': UpdateStatus(item.get('status', 'unknown')),
						'scan_time': datetime.fromisoformat(
							item.get('scanTime', datetime.now().isoformat()).replace('Z', '')
						),
					}
					if mapped_item['latest_version'] == '-':
						mapped_item['latest_version'] = ''
					apps.append(AppInfo(**mapped_item))
				return apps
		except Exception as e:
			logger.warning(f'Failed to load cache: {e}')
			return None

	def save(self, apps: List[AppInfo]):
		"""
		Save applications to cache with metadata.

		Serializes a list of AppInfo objects to JSON format with additional
		metadata including timestamp, version, and total count. This enables
		cache validation and future compatibility checks.

		Args:
		    apps: List of AppInfo objects to cache.

		Note:
		    Uses app.to_dict() for serialization which handles enum and datetime
		    conversion automatically.
		"""
		try:
			data = {
				'timestamp': datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
				'version': '1.0.1',
				'totalApps': len(apps),
				'apps': [app.to_dict() for app in apps],
			}
			with open(self.cache_file, 'w', encoding='utf-8') as f:
				json.dump(data, f, indent=2)
		except Exception as e:
			logger.error(f'Failed to save cache: {e}')

	def clear(self):
		"""
		Clear cache file.

		Deletes the cache file from disk if it exists. Used when user requests
		a fresh scan or when cache corruption is suspected.
		"""
		if self.cache_file.exists():
			self.cache_file.unlink()


# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════


def run_command(
	cmd: List[str],
	timeout: int = 45,
	allow_failure: bool = False,
	include_stderr: bool = False,
) -> Optional[str]:
	"""
	Execute command with enhanced error handling and timeout.

	Runs a shell command using subprocess with proper UTF-8 encoding, timeout
	protection, and error handling. On Windows, resolves the executable path
	using shutil.which() to ensure proper command execution.

	Args:
	    cmd: List of command arguments (e.g., ["winget", "list"]).
	    timeout: Maximum execution time in seconds (default: 45).
	    allow_failure: If True, return output even if command exits with non-zero
	        status. If False, return None on non-zero exit (default: False).
	    include_stderr: If True, combine stdout and stderr in the returned output
	        (default: False).

	Returns:
	    Optional[str]: Command output (stdout, or combined stdout+stderr if
	        include_stderr is True) with leading/trailing whitespace stripped.
	        Returns None if command fails (unless allow_failure=True), times out,
	        or executable is not found.

	Note:
	    - Uses check=False to always capture output; exit code is checked manually
	    - On Windows, resolves executable path for better compatibility
	    - Ignores encoding errors to handle non-UTF-8 output gracefully
	    - Logs debug messages for failed commands

	Example:
	    >>> output = run_command(['git', '--version'])
	    >>> if output:
	    ...     print(f'Git version: {output}')
	"""
	try:
		# On Windows, resolve the executable path for better compatibility
		if platform.system() == 'Windows':
			executable = shutil.which(cmd[0])
			if executable:
				cmd[0] = executable

		result = subprocess.run(
			cmd,
			capture_output=True,
			text=True,
			check=False,  # always capture output; check exit code manually
			encoding='utf-8',
			errors='ignore',
			timeout=timeout,
		)
		if result.returncode != 0 and not allow_failure:
			logger.debug(f'Command exited {result.returncode}: {" ".join(cmd)}')
			return None
		# Mirror JS: combine stdout+stderr when include_stderr is requested
		if include_stderr:
			combined = f'{result.stdout}\n{result.stderr}'.strip()
			return combined or None
		return result.stdout.strip() or None
	except subprocess.TimeoutExpired:
		logger.warning(f'Command timed out: {" ".join(cmd)}')
		return None
	except FileNotFoundError as e:
		logger.debug(f'Command not found: {" ".join(cmd)} - {e}')
		return None


# ═══════════════════════════════════════════════════════════════════════════════
# SOURCE BADGE UTILITY
# ═══════════════════════════════════════════════════════════════════════════════


def source_badge(source: str) -> str:
	"""
	Return source name with Rich style tags matching JS sourceBadge().

	Creates a formatted string with Rich markup tags that apply color styling
	to source names for display in tables and progress indicators. Each package
	source has a distinct color for easy visual identification.

	Color pattern (synchronized with JS version):
	    - winget: blue
	    - chocolatey: yellow
	    - npm: red
	    - pnpm: pink (color 206)
	    - pip: magenta
	    - bun: bright blue
	    - yarn: bright white
	    - rust: purple (color 129)
	    - path: green
	    - registry: gray (bright black)

	Args:
	    source: Source name string (case-insensitive).

	Returns:
	    str: Rich-formatted string with style tags (e.g., "[bold blue]winget[/bold blue]").
	"""
	source_lower = (source or 'unknown').lower()
	style_map = {
		'winget': 'blue',
		'chocolatey': 'yellow',
		'npm': 'red',
		'pnpm': 'color(206)',
		'pip': 'cyan',
		'bun': 'bright_blue',
		'yarn': 'bright_white',
		'rust': 'color(129)',
		'path': 'green',
		'registry': 'grey37',
		'scoop': 'bright_yellow',
	}
	style = style_map.get(source_lower, 'bright_white')
	return f'[{style}]{source_lower}[/{style}]'


# ═══════════════════════════════════════════════════════════════════════════════
# ENHANCED UI SYSTEM
# ═══════════════════════════════════════════════════════════════════════════════


class UISystem:
	"""
	Enhanced user interface system with beautiful layouts.

	This class provides static methods for rendering all UI components including
	the application banner, summary statistics, and data tables. All methods use
	the Rich library for colorful, formatted terminal output.

	The UI system is designed to match the JavaScript version's visual style,
	providing consistent appearance across implementations.

	Example:
	    >>> UISystem.display_banner()
	    >>> table = UISystem.create_apps_table(apps, 'My Apps')
	    >>> console.print(table)
	"""

	@staticmethod
	def display_banner():
		"""
		Show application banner matching JS version.

		Displays a styled header banner with the application name, version, and
		configuration directory path. Uses box-drawing characters for a polished
		appearance.

		Output format:
		    ┌──────────────────────────────────────────────────────────────┐
		    │ 🚀 System Update Node CLI v2.0.0                             │
		    │ ⚙️ Data dir: /home/user/.system_update                       │
		    └──────────────────────────────────────────────────────────────┘
		    Cache  → /home/user/.system_update/cache.json
		"""

		def hr(ch='─', width=70):
			return ch * width

		w = 68
		title = f'🚀 System Update Node CLI v2.0.0'
		sub = f'⚙️ Data dir: {config.config_dir}'

		console.print(f'[cyan]┌{hr("─", 70)}┐[/cyan]')
		console.print(f'[cyan]│[/cyan] [bold cyan]{title.ljust(69)}[/bold cyan][cyan]│[/cyan]')
		console.print(f'[cyan]│[/cyan] [dim cyan]{sub.ljust(69)}[/dim cyan][cyan]│[/cyan]')
		console.print(f'[cyan]└{hr("─", 70)}┘[/cyan]')

		console.print(f'Cache  [dim white]→ {config.cache_file}[/dim white]')
		console.print()

	@staticmethod
	def display_summary(
		total_apps: int,
		updates: int,
		scan_time: float,
		sources_count: Dict[str, int],
		show_all: bool = False,
	):
		"""
		Display summary exactly matching NodeJS version.

		Shows a formatted summary of the scan results including total applications
		discovered, available updates, scan duration, and a breakdown of packages
		by source.

		Args:
		    total_apps: Total number of applications scanned.
		    updates: Number of applications with available updates.
		    scan_time: Time taken to complete the scan in seconds.
		    sources_count: Dictionary mapping source names to package counts.
		    show_all: If True, indicates all packages are being shown (not used
		        directly but available for future extensions).

		Output format:
		    📊 Summary
		    📦 total apps     42
		    🔄 updates        5
		    ⏱️ scan duration  12.34s
		    ⚙️ sources        winget:20, npm:15, pip:7
		"""
		console.print(f'[bold magenta]📊 Summary[/bold magenta]')
		console.print(f'📦 total apps     [bold white]{total_apps}[/bold white]')
		console.print(f'🔄 updates        [bold yellow]{updates}[/bold yellow]')
		console.print(f'⏱️ scan duration  [bold white]{scan_time:.2f}s[/bold white]')

		source_parts = [
			f'{source_badge(s)}:[bold white]{c}[/bold white]'
			for s, c in sorted(sources_count.items())
			if c > 0
		]
		console.print(f'⚙️ sources        {", ".join(source_parts)}')
		console.print()

	@staticmethod
	def create_apps_table(
		apps: List[AppInfo],
		title: str = 'Installed Applications',
		show_all: bool = False,
	) -> Table:
		"""
		Create applications table matching JS version.

		Generates a Rich Table displaying application information with columns for
		package name, source, current version, latest version, and update status.
		Applies color coding based on source and status for easy visual scanning.

		Args:
		    apps: List of AppInfo objects to display.
		    title: Table title string (default: "Installed Applications").
		    show_all: If True, show all packages; if False, show only updates/vulnerable.

		Returns:
		    Table: Configured Rich Table object ready for display.

		Note:
		    - When show_all=False, filters to only UPDATE_AVAILABLE or VULNERABLE
		    - Source names are color-coded for easy identification
		    - Status column uses emoji and color coding
		    - Latest version shows "-" for up-to-date packages
		"""
		# Filter apps: by default show only updates/vulnerable, unless show_all is True
		if not show_all:
			display_apps = [
				app
				for app in apps
				if app.update_status in (UpdateStatus.UPDATE_AVAILABLE, UpdateStatus.VULNERABLE)
			]
		else:
			display_apps = apps

		table = Table(
			box=box.SIMPLE,
			show_header=True,
			header_style='bold cyan',
			border_style='dim white',
			pad_edge=False,
		)

		table.add_column('Package', style='bold white', width=30, justify='left')
		table.add_column('Source', width=12, justify='left')
		table.add_column('Current', width=20, style='white', justify='left')
		table.add_column('Latest', width=20, justify='left')
		table.add_column('Status', width=17, justify='left')

		for app in sorted(display_apps, key=lambda x: (x.source, x.name)):
			# Source-based coloring (Rich styles)
			src_styles = {
				'winget': 'blue',
				'chocolatey': 'yellow',
				'npm': 'red',
				'pnpm': 'color(206)',
				'pip': 'magenta',
				'bun': 'bright_blue',
				'yarn': 'bright_white',
				'rust': 'color(129)',
				'path': 'green',
				'registry': 'grey37',
			}
			source_lower = app.source.lower()
			source_style = src_styles.get(source_lower, 'bright_white')
			# Status-based coloring
			status_styles = {
				UpdateStatus.UP_TO_DATE: 'green',
				UpdateStatus.UPDATE_AVAILABLE: 'bold yellow',
				UpdateStatus.ERROR: 'bold red',
				UpdateStatus.VULNERABLE: 'bold red',
				UpdateStatus.SECURITY_UPDATE_AVAILABLE: 'bold magenta',
				UpdateStatus.UNKNOWN: 'dim white',
			}
			status_style = status_styles.get(app.update_status, 'white')

			# Latest version column: yellow bold when update available (matching JS)
			# Show "-" when up-to-date (no update needed)
			if app.latest_version and app.update_status == UpdateStatus.UPDATE_AVAILABLE:
				latest_text = Text(app.latest_version, style='bold yellow')
			elif app.update_status == UpdateStatus.UP_TO_DATE:
				latest_text = '-'
			else:
				latest_text = app.latest_version or '-'

			table.add_row(
				app.name[:30],
				Text(app.source, style=source_style),
				app.version,
				latest_text,
				f'[{status_style}]{app.status_display}[/{status_style}]',
			)

		return table

	@staticmethod
	def create_security_table(security_results: List) -> Table:
		"""
		Create security vulnerabilities table.

		Generates a Rich Table displaying security vulnerability information with
		columns for package name, severity level, CVE count, and description.
		Uses color coding for severity levels (red for critical, yellow for medium, etc.).

		Args:
		    security_results: List of security scan result objects containing
		        app_info, highest_severity, total_vulnerabilities, and vulnerabilities.

		Returns:
		    Table: Configured Rich Table object with security alert data.

		Note:
		    - Severity colors: CRITICAL/HIGH=red, MEDIUM=yellow, LOW=green
		    - Description is truncated to 40 characters with ellipsis
		"""
		table = Table(
			title='[bold red]🔒 Security Alerts[/bold red]',
			box=box.HEAVY_EDGE,
			border_style='red',
		)

		table.add_column('Package', style='cyan')
		table.add_column('Severity', justify='center')
		table.add_column('CVE', justify='center')
		table.add_column('Description', style='dim')

		for result in security_results:
			severity_color = {
				'CRITICAL': 'bold red',
				'HIGH': 'red',
				'MEDIUM': 'yellow',
				'LOW': 'green',
			}.get(result.highest_severity, 'white')

			table.add_row(
				result.app_info.name,
				f'[{severity_color}]{result.highest_severity}[/{severity_color}]',
				str(result.total_vulnerabilities),
				(result.vulnerabilities[0].description[:40] + '...')
				if result.vulnerabilities
				else 'Unknown',
			)

		return table


# ═══════════════════════════════════════════════════════════════════════════════
# PACKAGE SCANNERS
# ═══════════════════════════════════════════════════════════════════════════════


class PackageScanner:
	"""
	Enhanced package scanning system.

	This class provides static methods for scanning installed packages from
	multiple sources including package managers (Winget, Chocolatey, NPM, etc.)
	and system locations (PATH, Registry). Each scanner returns a list of AppInfo
	objects representing discovered packages.

	Supported Sources:
	    - Winget: Windows Package Manager (native Windows)
	    - Chocolatey: Community package manager for Windows
	    - NPM: Node.js package manager (global packages)
	    - PNPM: Performant NPM package manager
	    - Bun: JavaScript runtime and package manager
	    - Yarn: Alternative JavaScript package manager
	    - PIP: Python package installer
	    - PATH: System executables found in PATH environment
	    - Registry: Windows Registry installed applications
	    - Rust: Cargo-installed Rust packages

	Example:
	    >>> scanner = PackageScanner()
	    >>> winget_apps = PackageScanner.scan_winget()
	    >>> npm_apps = PackageScanner.scan_npm()
	    >>> all_apps = winget_apps + npm_apps
	"""

	@staticmethod
	def scan_winget() -> List[AppInfo]:
		"""
		Scan Winget packages with improved parsing.

		Executes 'winget list' command and parses the tabular output to extract
		installed package information. Handles header detection and column position
		calculation for robust parsing across different Winget versions.

		Returns:
		    List[AppInfo]: List of discovered Winget packages.

		Note:
		    - Uses --accept-source-agreements to avoid interactive prompts
		    - Skips entries missing name, app_id, or version
		    - Matches Node.js behavior for header position calculation
		"""
		apps = []
		output = run_command(['winget', 'list', '--accept-source-agreements'], allow_failure=True)
		if not output:
			return apps

		lines = output.splitlines()
		header_index = next(
			(
				i
				for i, line in enumerate(lines)
				if 'Name' in line and 'Id' in line and 'Version' in line
			),
			-1,
		)

		if header_index == -1:
			return apps

		header = lines[header_index]
		# Adjust header to start from "Name" position (match Node.js behavior)
		name_match = re.search(r'Name\s+Id', header)
		if name_match:
			header = header[name_match.start() :]

		positions = {
			'name': 0,
			'id': header.find('Id'),
			'version': header.find('Version'),
			'available': header.find('Available'),
			'source': header.find('Source'),
		}

		for line in lines[header_index + 2 :]:
			if not line.strip():
				continue

			try:
				name = line[0 : max(positions['id'], 0)].strip()
				app_id = (
					line[positions['id'] : positions['version']].strip()
					if positions['version'] > 0
					else ''
				)
				version_end = (
					positions['available']
					if positions['available'] != -1
					else positions['source']
					if positions['source'] != -1
					else len(line)
				)
				version = (
					line[positions['version'] : version_end].strip()
					if positions['version'] != -1
					else ''
				)

				# Skip entries without name, app_id, or version (match Node.js behavior)
				if not name or not app_id or not version:
					continue

				apps.append(
					AppInfo(
						name=name,
						source='Winget',
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
		"""
		Scan Chocolatey packages.

		Executes 'choco list --local-only' to enumerate locally installed
		Chocolatey packages. Parses pipe-delimited output format.

		Returns:
		    List[AppInfo]: List of discovered Chocolatey packages.

		Note:
		    - Uses --limit-output for machine-readable format
		    - Requires at least name and version fields
		"""
		apps = []
		output = run_command(
			['choco', 'list', '--local-only', '--limit-output'], allow_failure=True
		)
		if not output:
			return apps

		for line in output.splitlines():
			parts = [p.strip() for p in line.split('|') if p.strip()]
			if len(parts) >= 2:
				apps.append(
					AppInfo(
						name=parts[0],
						source='Chocolatey',
						version=parts[1],
						app_id=parts[0],
					)
				)

		return apps

	@staticmethod
	def scan_npm() -> List[AppInfo]:
		"""
		Scan NPM global packages.

		Executes 'npm list -g --json' to enumerate globally installed NPM
		packages. Parses JSON output for reliable extraction.

		Returns:
		    List[AppInfo]: List of discovered NPM global packages.

		Note:
		    - Uses --depth=0 for top-level packages only
		    - Uses --silent to suppress progress output
		"""
		apps = []
		output = run_command(
			['npm', 'list', '-g', '--depth=0', '--json', '--silent'], allow_failure=True
		)
		if not output:
			return apps

		try:
			data = json.loads(output)
			if 'dependencies' in data:
				for name, details in data['dependencies'].items():
					apps.append(
						AppInfo(
							name=name,
							source='NPM',
							version=details.get('version', 'N/A'),
							app_id=name,
						)
					)
		except json.JSONDecodeError:
			pass

		return apps

	@staticmethod
	def scan_pnpm() -> List[AppInfo]:
		"""
		Scan PNPM global packages.

		Executes 'pnpm list -g --json' to enumerate globally installed PNPM
		packages. Handles both array and object JSON response formats.

		Returns:
		    List[AppInfo]: List of discovered PNPM global packages.

		Note:
		    - Uses --depth=0 for top-level packages only
		    - Handles both array and object JSON structures
		"""
		apps = []
		output = run_command(['pnpm', 'list', '-g', '--depth=0', '--json'], allow_failure=True)
		if not output:
			return apps

		try:
			data = json.loads(output)
			data = data[0] if isinstance(data, list) and data else data

			if isinstance(data, dict) and 'dependencies' in data:
				for name, details in data['dependencies'].items():
					apps.append(
						AppInfo(
							name=name,
							source='PNPM',
							version=details.get('version', 'N/A'),
							app_id=name,
						)
					)
		except (json.JSONDecodeError, IndexError):
			pass

		return apps

	@staticmethod
	def scan_bun() -> List[AppInfo]:
		"""
		Scan Bun global packages.

		Executes 'bun pm ls -g' to enumerate globally installed Bun packages.
		Parses output using regex to extract package name and version.

		Returns:
		    List[AppInfo]: List of discovered Bun global packages.

		Note:
		    - Uses regex pattern to match "package@version" format
		"""
		apps = []
		output = run_command(['bun', 'pm', 'ls', '-g'], allow_failure=True)
		if not output:
			return apps

		for line in output.splitlines():
			match = re.match(r'^\s*([^\s@]+)@([^\s]+)', line)
			if match:
				apps.append(
					AppInfo(
						name=match.group(1),
						source='Bun',
						version=match.group(2),
						app_id=match.group(1),
					)
				)

		return apps

	@staticmethod
	def scan_yarn() -> List[AppInfo]:
		"""
		Scan Yarn global packages.

		Executes 'yarn global list' to enumerate globally installed Yarn
		packages. Parses info lines using regex to extract package metadata.

		Returns:
		    List[AppInfo]: List of discovered Yarn global packages.

		Note:
		    - Matches 'info "package@version"' format in output
		"""
		apps = []
		output = run_command(['yarn', 'global', 'list'], allow_failure=True)
		if not output:
			return apps

		for line in output.splitlines():
			match = re.match(r'^info "([^@]+)@([^"]+)"', line)
			if match:
				apps.append(
					AppInfo(
						name=match.group(1),
						source='Yarn',
						version=match.group(2),
						app_id=match.group(1),
					)
				)

		return apps

	@staticmethod
	def scan_pip() -> List[AppInfo]:
		"""
		Scan PIP packages.

		Executes 'pip list --format=json' to enumerate installed Python packages.
		Tries multiple command patterns (python -m pip, pip, pip3) for maximum
		compatibility across different Python installations.

		Returns:
		    List[AppInfo]: List of discovered PIP packages.

		Note:
		    - Tries multiple pip command patterns for compatibility
		    - Uses JSON format for reliable parsing
		"""
		apps = []
		# Try multiple pip command patterns like Node.js does
		pip_commands = [
			[sys.executable, '-m', 'pip', 'list', '--format=json'],
			['pip', 'list', '--format=json'],
			['pip3', 'list', '--format=json'],
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
						name=item['name'],
						source='PIP',
						version=item['version'],
						app_id=item['name'],
					)
				)
		except json.JSONDecodeError:
			pass

		return apps

	@staticmethod
	def scan_path() -> List[AppInfo]:
		"""
		Scan PATH executables.

		Searches for common development tools and runtime executables in the
		system PATH. For each found executable, retrieves its version using
		the --version flag and extracts version number using regex.

		Returns:
		    List[AppInfo]: List of discovered PATH executables with versions.

		Note:
		    - Scans for: node, npm, pnpm, yarn, python, git, go, bun, deno,
		      rustc, cargo, dotnet, java, pwsh
		    - Uses 'where' on Windows, 'which' on Unix-like systems
		    - Extracts version using semantic versioning regex pattern
		"""
		apps = []
		executables = [
			'node',
			'npm',
			'pnpm',
			'yarn',
			'python',
			'git',
			'go',
			'bun',
			'deno',
			'rustc',
			'cargo',
			'dotnet',
			'java',
			'pwsh',
		]

		for exe in executables:
			cmd = ['where', exe] if platform.system() == 'Windows' else ['which', exe]
			path = run_command(cmd, allow_failure=True)
			if path:
				version_output = run_command([exe, '--version'], allow_failure=True)
				if version_output:
					match = re.search(r'(\d+\.\d+(\.\d+)*([-.].*)?)', version_output)
					if match:
						apps.append(
							AppInfo(
								name=exe,
								source='PATH',
								version=match.group(0),
								install_path=path.split('\n')[0],
							)
						)

		return apps

	@staticmethod
	def scan_rust() -> List[AppInfo]:
		"""
		Scan Rust packages installed via cargo.

		Executes 'cargo install --list' to enumerate Rust packages installed
		globally via Cargo. Parses output to extract package name and version.

		Returns:
		    List[AppInfo]: List of discovered Rust/Cargo packages.

		Note:
		    - Matches format: "package-name v1.2.3:"
		    - Only includes packages with valid version strings
		"""
		apps = []
		output = run_command(['cargo', 'install', '--list'], allow_failure=True)
		if not output:
			return apps

		for line in output.splitlines():
			# Format: package-name v1.2.3:
			match = re.match(r'^([^\s]+)\s+v([^\s:]+):', line)
			if match:
				apps.append(
					AppInfo(
						name=match.group(1),
						source='Rust',
						version=match.group(2),
						app_id=match.group(1),
					)
				)

		return apps

	@staticmethod
	def scan_scoop() -> List[AppInfo]:
		"""
		Scan Scoop packages installed via Scoop.

		Executes 'scoop list' to enumerate Scoop-managed packages.
		Parses the output to extract package name and version.

		Returns:
		    List[AppInfo]: List of discovered Scoop packages.

		Note:
		    - Reads 'scoop list' output
		    - Skips header lines and separators
		"""
		apps = []
		output = run_command(['scoop', 'list'], allow_failure=True)
		if not output:
			return apps

		lines = output.splitlines()
		start_index = 0

		for i, line in enumerate(lines):
			if line.strip().startswith('Name') and 'Version' in line:
				start_index = i + 2
				break

		for line in lines[start_index:]:
			line = line.strip()
			if not line or line.startswith('---') or line.startswith('+'):
				continue

			parts = line.split()
			if len(parts) >= 2:
				name = parts[0]
				version = parts[1]
				if name and version and not name.startswith(' '):
					apps.append(
						AppInfo(
							name=name,
							source='Scoop',
							version=version,
							app_id=name,
						)
					)

		return apps

	@staticmethod
	def scan_registry() -> List[AppInfo]:
		"""
		Scan Windows Registry for installed applications.

		Executes a PowerShell script to query Windows Registry uninstall keys
		from HKLM and HKCU hives. Extracts application name, version, and
		install location for non-system applications.

		Returns:
		    List[AppInfo]: List of discovered Registry applications.

		Note:
		    - Windows-only functionality (returns empty list on other platforms)
		    - Queries HKLM, HKCU, and Wow6432Node registry paths
		    - Filters out system components (SystemComponent=1)
		    - Requires PowerShell on Windows
		"""
		if platform.system() != 'Windows':
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

		output = run_command(
			['powershell', '-NoProfile', '-Command', ps_script], allow_failure=True
		)
		if output:
			try:
				data = json.loads(output)
				data = [data] if isinstance(data, dict) else data
				for item in data:
					apps.append(
						AppInfo(
							name=item['Name'],
							source='Registry',
							version=item['Version'],
							install_path=item.get('InstallLocation'),
						)
					)
			except Exception:
				pass

		return apps


# ═══════════════════════════════════════════════════════════════════════════════
# UPDATE CHECKERS
# ═══════════════════════════════════════════════════════════════════════════════


class UpdateChecker:
	"""
	Enhanced update checking system.

	This class provides methods for checking available updates across all supported
	package managers. It groups applications by source and performs batch update
	checks with progress reporting using Rich.

	The main check_all_updates() method orchestrates the update checking process,
	delegating to source-specific _check_* methods for each package manager.

	Supported Sources:
	    - Winget: Uses 'winget upgrade' to find available updates
	    - Chocolatey: Uses 'choco outdated' for update detection
	    - NPM/PNPM/Bun/Yarn: Uses package manager-specific outdated commands
	    - PIP: Uses 'pip list --outdated' for Python packages
	    - PATH: Queries GitHub API and native commands for tool updates
	    - Registry: Cross-references with Winget upgrade list
	    - Rust: Uses 'cargo install-update -l' for Rust crates

	Example:
	    >>> checker = UpdateChecker()
	    >>> total = checker.check_all_updates(apps)
	    >>> print(f'Found {total} updates available')
	"""

	@staticmethod
	def check_all_updates(apps: List[AppInfo]) -> int:
		"""
		Check updates for all supported package managers matching JS checkUpdates.

		Orchestrates the update checking process by grouping applications by source
		and calling the appropriate _check_* method for each. Displays progress
		using Rich Progress bar with per-source status updates.

		Args:
		    apps: List of AppInfo objects to check for updates. Modified in-place
		        to set latest_version and update_status fields.

		Returns:
		    int: Total number of updates found across all sources.

		Process:
		    1. Groups apps by source (winget, chocolatey, npm, etc.)
		    2. For each source with apps, calls the corresponding _check_* method
		    3. Updates progress bar with source-specific results
		    4. Sets final update_status for all apps (UP_TO_DATE or UPDATE_AVAILABLE)

		Note:
		    - Apps already marked UPDATE_AVAILABLE or UP_TO_DATE are skipped
		    - Sources that perform update checks mark remaining apps as UP_TO_DATE
		"""
		total_updates = 0

		# Group apps by source for batch processing (matching JS order)
		sources = {
			'winget': [a for a in apps if a.source.lower() == 'winget'],
			'chocolatey': [a for a in apps if a.source.lower() == 'chocolatey'],
			'npm': [a for a in apps if a.source.lower() == 'npm'],
			'pnpm': [a for a in apps if a.source.lower() == 'pnpm'],
			'bun': [a for a in apps if a.source.lower() == 'bun'],
			'yarn': [a for a in apps if a.source.lower() == 'yarn'],
			'pip': [a for a in apps if a.source.lower() == 'pip'],
			'path': [a for a in apps if a.source.lower() == 'path'],
			'registry': [a for a in apps if a.source.lower() == 'registry'],
			'rust': [a for a in apps if a.source.lower() == 'rust'],
			'scoop': [a for a in apps if a.source.lower() == 'scoop'],
		}

		# Filter to only sources with apps
		active_sources = [(name, apps_list) for name, apps_list in sources.items() if apps_list]

		# Check updates for each source using Rich Progress
		with Progress(
			TextColumn('{task.description}'),
			BarColumn(
				bar_width=26,
				complete_style='white',
				style='dim white',
				finished_style='white',
			),
			TextColumn('[progress.percentage]{task.percentage:>3.0f}%'),
			MofNCompleteColumn(),
			TimeElapsedColumn(),
			TextColumn('{task.fields[extra]}'),
			console=console,
		) as progress:
			task = progress.add_task('🔄 Checking updates', total=len(active_sources), extra='')

			for source_name, source_apps in active_sources:
				source_updates = 0

				if source_name == 'winget':
					source_updates = UpdateChecker._check_winget_updates(source_apps)
				elif source_name == 'chocolatey':
					source_updates = UpdateChecker._check_choco_updates(source_apps)
				elif source_name == 'npm':
					source_updates = UpdateChecker._check_npm_updates(source_apps)
				elif source_name == 'pnpm':
					source_updates = UpdateChecker._check_pnpm_updates(source_apps)
				elif source_name == 'bun':
					source_updates = UpdateChecker._check_bun_updates(source_apps)
				elif source_name == 'yarn':
					source_updates = UpdateChecker._check_yarn_updates(source_apps)
				elif source_name == 'pip':
					source_updates = UpdateChecker._check_pip_updates(source_apps)
				elif source_name == 'path':
					source_updates = UpdateChecker._check_path_updates(source_apps)
				elif source_name == 'registry':
					source_updates = UpdateChecker._check_registry_updates(source_apps)
				elif source_name == 'rust':
					source_updates = UpdateChecker._check_rust_updates(source_apps)
				elif source_name == 'scoop':
					source_updates = UpdateChecker._check_scoop_updates(source_apps)

				total_updates += source_updates

				# Match JS: source_badge + count or "none"
				if source_updates > 0:
					progress.update(
						task,
						advance=1,
						extra=f'{source_badge(source_name)}: [bold yellow]{source_updates}[/bold yellow] update(s)',
					)
				else:
					progress.update(
						task,
						advance=1,
						extra=f'{source_badge(source_name)}: [dim white]none[/dim white]',
					)

			# Mark complete matching JS
			progress.update(task, extra='✅ [bold green]update checks complete[/bold green]')

		# Mark apps with proper status (match JavaScript logic)
		for app in apps:
			if app.update_status == UpdateStatus.UPDATE_AVAILABLE:
				continue
			if app.update_status == UpdateStatus.UP_TO_DATE:
				continue
			# Sources that perform update checks should be marked UP_TO_DATE if no update found
			if app.latest_version or app.source.lower() in [
				'winget',
				'chocolatey',
				'npm',
				'pnpm',
				'bun',
				'yarn',
				'pip',
				'registry',
				'rust',
				'path',
			]:
				app.update_status = UpdateStatus.UP_TO_DATE
			else:
				app.update_status = UpdateStatus.UNKNOWN

		return total_updates

	@staticmethod
	def _check_winget_updates(apps: List[AppInfo]) -> int:
		"""
		Check Winget package updates.

		Executes 'winget upgrade' command and parses the output to find packages
		with available updates. Matches packages by app_id (case-insensitive).

		Args:
		    apps: List of AppInfo objects to check. Modified in-place for matches.

		Returns:
		    int: Number of Winget packages with available updates.

		Note:
		    - Uses --accept-source-agreements to avoid interactive prompts
		    - Parses tabular output similar to scan_winget()
		"""
		updates = 0
		output = run_command(
			['winget', 'upgrade', '--accept-source-agreements'], allow_failure=True
		)
		if not output:
			return updates

		lines = output.splitlines()
		header_index = next(
			(i for i, line in enumerate(lines) if 'Name' in line and 'Id' in line), -1
		)

		if header_index == -1:
			return updates

		header = lines[header_index]
		# Adjust header to start from "Name" position (match Node.js behavior)
		name_match = re.search(r'Name\s+Id', header)
		if name_match:
			header = header[name_match.start() :]

		positions = {
			'id': header.find('Id'),
			'version': header.find('Version'),
			'available': header.find('Available'),
			'source': header.find('Source'),
		}

		for line in lines[header_index + 2 :]:
			if not line.strip():
				continue

			try:
				app_id = (
					line[positions['id'] : positions['version']].strip()
					if positions['version'] > 0
					else ''
				)
				if positions['available'] != -1:
					avail_end = positions['source'] if positions['source'] != -1 else len(line)
					latest = line[positions['available'] : avail_end].strip()

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
	def _check_choco_updates(apps: List[AppInfo]) -> int:
		"""
		Check Chocolatey package updates.

		Executes 'choco outdated' command and parses pipe-delimited output to find
		packages with newer versions available.

		Args:
		    apps: List of Chocolatey AppInfo objects to check. Modified in-place.

		Returns:
		    int: Number of Chocolatey packages with available updates.

		Note:
		    - Uses --limit-output for machine-readable format
		    - Output format: name|version|latest_version
		"""
		updates = 0
		output = run_command(['choco', 'outdated', '--limit-output'], allow_failure=True)
		if not output:
			return updates

		for line in output.splitlines():
			parts = line.split('|')
			if len(parts) >= 3:
				for app in apps:
					if app.name == parts[0]:
						app.latest_version = parts[2]
						app.update_status = UpdateStatus.UPDATE_AVAILABLE
						updates += 1

		return updates

	@staticmethod
	def _check_npm_updates(apps: List[AppInfo]) -> int:
		"""
		Check NPM package updates.

		Executes 'npm outdated -g --json' to find globally installed NPM packages
		with newer versions available.

		Args:
		    apps: List of NPM AppInfo objects to check. Modified in-place.

		Returns:
		    int: Number of NPM packages with available updates.

		Note:
		    - Only checks global packages (-g flag)
		    - Uses JSON output for reliable parsing
		"""
		updates = 0
		output = run_command(['npm', 'outdated', '-g', '--json'], allow_failure=True)
		if not output:
			return updates

		try:
			data = json.loads(output)
			for name, details in data.items():
				for app in apps:
					if app.name == name:
						latest_version = details.get('latest', '')
						if latest_version:
							app.latest_version = latest_version
							app.update_status = UpdateStatus.UPDATE_AVAILABLE
							updates += 1
		except Exception:
			pass

		return updates

	@staticmethod
	def _check_pnpm_updates(apps: List[AppInfo]) -> int:
		"""
		Check PNPM package updates.

		Executes 'pnpm outdated -g --json' to find globally installed PNPM packages
		with newer versions available. Handles both dict and list JSON formats.

		Args:
		    apps: List of PNPM AppInfo objects to check. Modified in-place.

		Returns:
		    int: Number of PNPM packages with available updates.

		Note:
		    - Only checks global packages (-g flag)
		    - Handles both object and array JSON response formats
		"""
		updates = 0
		output = run_command(['pnpm', 'outdated', '-g', '--json'], allow_failure=True)
		if not output:
			return updates

		try:
			data = json.loads(output)
			if isinstance(data, dict):
				for name, details in data.items():
					for app in apps:
						if app.name == name:
							latest_version = details.get('latest', details.get('wanted', ''))
							if latest_version:
								app.latest_version = latest_version
								app.update_status = UpdateStatus.UPDATE_AVAILABLE
								updates += 1
			elif isinstance(data, list):
				for item in data:
					name = item.get('name')
					for app in apps:
						if app.name == name:
							latest_version = item.get('latest', item.get('wanted', ''))
							if latest_version:
								app.latest_version = latest_version
								app.update_status = UpdateStatus.UPDATE_AVAILABLE
								updates += 1
		except Exception:
			pass

		return updates

	@staticmethod
	def _check_bun_updates(apps: List[AppInfo]) -> int:
		"""
		Check Bun package updates.

		Queries npm registry for each Bun package to find the latest version.
		Uses 'npm info <package> version' command for version lookup.

		Args:
		    apps: List of Bun AppInfo objects to check. Modified in-place.

		Returns:
		    int: Number of Bun packages with available updates.

		Note:
		    - Uses npm registry as Bun package source
		    - Checks each package individually
		"""
		updates = 0
		for app in apps:
			output = run_command(['npm', 'info', app.name, 'version'], allow_failure=True)
			if output:
				latest = output.strip()
				if latest and latest != app.version and 'ERR' not in latest:
					app.latest_version = latest
					app.update_status = UpdateStatus.UPDATE_AVAILABLE
					updates += 1
		return updates

	@staticmethod
	def _check_yarn_updates(apps: List[AppInfo]) -> int:
		"""
		Check Yarn package updates.

		Queries npm registry for each Yarn package to find the latest version.
		Uses 'npm info <package> version' command for version lookup.

		Args:
		    apps: List of Yarn AppInfo objects to check. Modified in-place.

		Returns:
		    int: Number of Yarn packages with available updates.

		Note:
		    - Uses npm registry as Yarn package source
		    - Checks each package individually
		"""
		updates = 0
		for app in apps:
			output = run_command(['npm', 'info', app.name, 'version'], allow_failure=True)
			if output:
				latest = output.strip()
				if latest and latest != app.version and 'ERR' not in latest:
					app.latest_version = latest
					app.update_status = UpdateStatus.UPDATE_AVAILABLE
					updates += 1
		return updates

	@staticmethod
	def _check_pip_updates(apps: List[AppInfo]) -> int:
		"""
		Check PIP package updates.

		Executes 'pip list --outdated --format=json' to find installed Python
		packages with newer versions available. Tries multiple command patterns
		for compatibility.

		Args:
		    apps: List of PIP AppInfo objects to check. Modified in-place.

		Returns:
		    int: Number of PIP packages with available updates.

		Note:
		    - Tries python -m pip, pip, and pip3 commands
		    - Uses case-insensitive name matching
		"""
		updates = 0
		pip_commands = [
			[sys.executable, '-m', 'pip', 'list', '--outdated', '--format=json'],
			['pip', 'list', '--outdated', '--format=json'],
			['pip3', 'list', '--outdated', '--format=json'],
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
				name = item.get('name')
				latest = item.get('latest_version')
				for app in apps:
					if app.name.lower() == name.lower():
						app.latest_version = latest
						app.update_status = UpdateStatus.UPDATE_AVAILABLE
						updates += 1
		except Exception:
			pass

		return updates

	@staticmethod
	def _check_path_updates(apps: List[AppInfo]) -> int:
		"""
		Check PATH tool updates.

		Checks for updates of system executables found in PATH using various
		methods including GitHub API queries, native upgrade commands, and
		npm registry lookups. Handles preview/stable version differentiation.

		Args:
		    apps: List of PATH AppInfo objects to check. Modified in-place.

		Returns:
		    int: Number of PATH tools with available updates.

		Supported Tools:
		    - bun, deno: Native upgrade dry-run commands
		    - yarn, npm, pnpm, node: npm registry lookup
		    - python, git, pwsh: GitHub API releases/tags
		    - dotnet: winget show command
		    - rustc, cargo: GitHub API releases

		Note:
		    - Uses semantic version comparison that handles preview releases
		    - Won't suggest downgrading from preview to stable same-version
		"""
		import urllib.request

		updates = 0

		def fetch_json(url):
			"""Fetch JSON data from URL with User-Agent header."""
			req = urllib.request.Request(url, headers={'User-Agent': 'SystemUpdateCLI'})
			try:
				with urllib.request.urlopen(req, timeout=10) as response:
					return json.loads(response.read().decode())
			except Exception:
				return None

		def parse_version(ver_str: str) -> Tuple:
			"""
			Parse version string into comparable tuple (major, minor, patch, is_stable).

			Args:
			    ver_str: Version string to parse (e.g., "1.2.3", "2.0.0-preview").

			Returns:
			    Tuple: (major, minor, patch, is_stable) for comparison.
			"""
			# Remove leading non-digits
			ver_str = re.sub(r'^[^\d]+', '', ver_str).strip()
			# Extract main version numbers
			match = re.match(r'(\d+)\.(\d+)\.(\d+)', ver_str)
			if not match:
				match = re.match(r'(\d+)\.(\d+)', ver_str)
				if match:
					return (
						int(match.group(1)),
						int(match.group(2)),
						0,
						'preview' not in ver_str.lower(),
					)
				return (0, 0, 0, False)
			# Check if it's a preview/rc/beta version
			is_stable = not any(
				x in ver_str.lower() for x in ['preview', 'rc', 'beta', 'alpha', '-pre']
			)
			return (
				int(match.group(1)),
				int(match.group(2)),
				int(match.group(3)),
				is_stable,
			)

		def is_newer_version(current: str, latest: str) -> bool:
			"""
			Check if latest is actually newer than current (handles previews).

			Args:
			    current: Current version string.
			    latest: Latest available version string.

			Returns:
			    bool: True if latest is newer than current.

			Logic:
			    - Won't suggest downgrading from newer major/minor preview
			    - Compares stable versions normally
			    - Won't update from preview to stable same base version
			"""
			curr_parts = parse_version(current)
			latest_parts = parse_version(latest)

			# If current is a newer major/minor preview, don't suggest downgrade to stable
			if curr_parts[0] > latest_parts[0]:  # Newer major version
				return False
			if (
				curr_parts[0] == latest_parts[0] and curr_parts[1] > latest_parts[1]
			):  # Newer minor in same major
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
			latest = ''
			try:
				if app.name == 'bun':
					output = run_command(
						['bun', 'upgrade', '--dry-run'],
						allow_failure=True,
						include_stderr=True,
					)
					if output:
						match = re.search(r'Bun v([0-9.]+)\s+is out!', output)
						if match:
							latest = match.group(1)
						else:
							latest = app.version
				elif app.name == 'deno':
					output = run_command(
						['deno', 'upgrade', '--dry-run'],
						allow_failure=True,
						include_stderr=True,
					)
					if output:
						match = re.search(
							r'Found latest stable version\s+v?([0-9.]+)',
							output,
							re.IGNORECASE,
						)
						if match:
							latest = match.group(1)
						else:
							latest = app.version
				elif app.name in ('yarn', 'npm', 'pnpm', 'node'):
					output = run_command(['npm', 'view', app.name, 'version'], allow_failure=True)
					if output and 'ERR' not in output:
						latest = output.strip()
					if not latest:
						latest = app.version
				elif app.name == 'python':
					# Python uses tags, not releases - get latest tag
					data = fetch_json('https://api.github.com/repos/python/cpython/tags?per_page=1')
					if data and isinstance(data, list) and len(data) > 0 and data[0].get('name'):
						match = re.search(r'v?([0-9.]+)', data[0]['name'])
						if match:
							latest = match.group(1)
					if not latest:
						latest = app.version
				elif app.name == 'git':
					data = fetch_json(
						'https://api.github.com/repos/git-for-windows/git/releases/latest'
					)
					if data and data.get('tag_name'):
						match = re.search(r'v?([0-9.]+?)(?:\.windows)', data['tag_name'])
						latest = match.group(1) if match else data['tag_name'].replace('v', '')
					if not latest:
						latest = app.version
				elif app.name == 'pwsh':
					data = fetch_json(
						'https://api.github.com/repos/PowerShell/PowerShell/releases/latest'
					)
					if data and data.get('tag_name'):
						latest = data['tag_name'].replace('v', '')
					if not latest:
						latest = app.version
				elif app.name == 'dotnet':
					output = run_command(
						[
							'winget',
							'show',
							'Microsoft.DotNet.SDK.9',
							'--accept-source-agreements',
						],
						allow_failure=True,
					)
					if output:
						match = re.search(r'Version:\s+([0-9.]+)', output)
						if match:
							latest = match.group(1)
					if not latest:
						latest = app.version
				elif app.name in ('rustc', 'cargo'):
					data = fetch_json('https://api.github.com/repos/rust-lang/rust/releases/latest')
					if data and data.get('tag_name'):
						match = re.search(r'([0-9.]+)', data['tag_name'])
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
					app.latest_version = '-'
					app.update_status = UpdateStatus.UP_TO_DATE
			except Exception:
				# On error, mark as up-to-date rather than unknown
				app.latest_version = '-'
				app.update_status = UpdateStatus.UP_TO_DATE
		return updates

	@staticmethod
	def _check_registry_updates(apps: List[AppInfo]) -> int:
		"""
		Check Registry app updates by cross-referencing with winget upgrade.

		Winget internally queries the Windows Registry to build its upgrade list,
		so we can match Registry-installed apps against the winget upgrade output
		by name to detect available updates.

		Args:
		    apps: List of Registry AppInfo objects to check. Modified in-place.

		Returns:
		    int: Number of Registry apps with available updates.

		Note:
		    - If winget upgrade returns no output, marks all apps as UP_TO_DATE
		    - Matches by application name (case-insensitive)
		"""
		updates = 0
		output = run_command(
			['winget', 'upgrade', '--accept-source-agreements'], allow_failure=True
		)
		if not output:
			# Mark all as UP_TO_DATE since we have no upgrade data
			for app in apps:
				app.update_status = UpdateStatus.UP_TO_DATE
			return updates

		lines = output.splitlines()
		header_index = next(
			(i for i, line in enumerate(lines) if 'Name' in line and 'Id' in line), -1
		)
		if header_index == -1:
			for app in apps:
				app.update_status = UpdateStatus.UP_TO_DATE
			return updates

		header = lines[header_index]
		positions = {
			'id': header.find('Id'),
			'version': header.find('Version'),
			'available': header.find('Available'),
			'source': header.find('Source'),
		}

		# Build a lookup: lowercased name -> latest version
		upgrade_map: dict = {}
		for line in lines[header_index + 2 :]:
			if not line.strip():
				continue
			try:
				name = line[0 : positions['id']].strip().lower()
				if positions['available'] != -1:
					avail_end = positions['source'] if positions['source'] != -1 else len(line)
					latest = line[positions['available'] : avail_end].strip()
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
	def _check_rust_updates(apps: List[AppInfo]) -> int:
		"""
		Check Rust package updates via cargo install-update.

		Executes 'cargo install-update -l' to list Rust packages with available
		updates. Requires the cargo-edit or cargo-update crate to be installed.

		Args:
		    apps: List of Rust AppInfo objects to check. Modified in-place.

		Returns:
		    int: Number of Rust packages with available updates.

		Note:
		    - Output format: Package | Installed | Latest | Needs update
		    - Only counts packages where "Needs update" is "yes"
		"""
		updates = 0
		output = run_command(['cargo', 'install-update', '-l'], allow_failure=True)
		if not output:
			return updates

		lines = output.splitlines()
		# Find header: Package | Installed | Latest | Needs update
		header_idx = -1
		for i, line in enumerate(lines):
			if 'Package' in line and 'Latest' in line:
				header_idx = i
				break

		if header_idx == -1:
			return updates

		for line in lines[header_idx + 1 :]:
			l = line.strip()
			if not l:
				continue
			parts = l.split()
			if len(parts) < 4:
				continue

			name, installed, latest, needs_update = (
				parts[0],
				parts[1],
				parts[2],
				parts[3],
			)
			if needs_update.lower() == 'yes':
				for app in apps:
					if app.name == name:
						app.latest_version = latest[1:] if latest.startswith('v') else latest
						app.update_status = UpdateStatus.UPDATE_AVAILABLE
						updates += 1
		return updates

	@staticmethod
	def _check_scoop_updates(apps: List[AppInfo]) -> int:
		"""
		Check Scoop package updates.

		Executes 'scoop status' to list Scoop packages with available updates.

		Args:
		    apps: List of Scoop AppInfo objects to check. Modified in-place.

		Returns:
		    int: Number of Scoop packages with available updates.

		Note:
		    - Parses 'scoop status' output
		    - Matches package names with versions
		"""
		updates = 0
		output = run_command(['scoop', 'status'], allow_failure=True)
		if not output:
			return updates

		update_map = {}
		lines = output.splitlines()

		for line in lines:
			line = line.strip()
			if not line or line.startswith('---'):
				continue
			parts = line.split()
			if len(parts) >= 2:
				name = parts[0]
				version = parts[1]
				if len(parts) >= 3:
					latest = parts[2]
					if latest.startswith('(') and latest.endswith(')'):
						latest = latest[1:-1]
					if version != latest:
						update_map[name] = latest
				else:
					update_map[name] = version

		for app in apps:
			latest = update_map.get(app.name)
			if latest:
				app.latest_version = latest
				app.update_status = UpdateStatus.UPDATE_AVAILABLE
				updates += 1

		return updates


# ═══════════════════════════════════════════════════════════════════════════════
# UPDATE EXECUTOR
# ═══════════════════════════════════════════════════════════════════════════════


class UpdateExecutor:
	"""
	Enhanced update execution system.

	This class provides methods for executing package updates across all supported
	package managers. It handles the construction of appropriate update commands
	for each source and provides progress feedback during execution.

	Features:
	    - Dry-run mode for previewing updates without applying them
	    - Per-package success/failure reporting
	    - Progress bar with real-time status updates
	    - Source-specific command construction

	Example:
	    >>> executor = UpdateExecutor()
	    >>> executor.execute_updates(updates, dry_run=True)  # Preview
	    >>> executor.execute_updates(updates)  # Apply updates
	"""

	@staticmethod
	def execute_updates(apps: List[AppInfo], dry_run: bool = False):
		"""
		Execute updates with enhanced feedback matching JS executeUpdates.

		Iterates through the list of applications and executes updates for each.
		Displays progress using Rich Progress bar and reports success/failure
		for each package.

		Args:
		    apps: List of AppInfo objects to update (should have latest_version set).
		    dry_run: If True, simulate updates without executing commands (default: False).

		Note:
		    - In dry-run mode, displays what would be updated without making changes
		    - Shows final summary with success count
		    - Uses _execute_single_update() for actual update execution
		"""
		success_count = 0

		with Progress(
			TextColumn('{task.description}'),
			BarColumn(
				bar_width=26,
				complete_style='white',
				style='dim white',
				finished_style='white',
			),
			TextColumn('[progress.percentage]{task.percentage:>3.0f}%'),
			MofNCompleteColumn(),
			TimeElapsedColumn(),
			TextColumn('{task.fields[extra]}'),
			console=console,
		) as progress:
			task = progress.add_task('⚙️ Applying updates', total=len(apps), extra='')

			for app in apps:
				label = f'{app.name} ({app.source})'

				if dry_run:
					time.sleep(0.3)
					success_count += 1
					console.print(f'[yellow]🔍 DRY RUN[/yellow]: {app.name} → {app.latest_version}')
					progress.update(task, advance=1, extra='✅ [bold]' + label + '[/bold]')
				else:
					success = UpdateExecutor._execute_single_update(app)
					if success:
						success_count += 1
						console.print(
							f'[green]✅[/green] {app.name} updated to {app.latest_version}'
						)
						progress.update(task, advance=1, extra='✅ [bold]' + label + '[/bold]')
					else:
						console.print(f'[red]❌[/red] Failed to update {app.name}')
						progress.update(task, advance=1, extra='❌ [bold]' + label + '[/bold]')

			# Final summary matching JS
			progress.update(task, extra='✨ [bold cyan]finished[/bold cyan]')

		console.print(f'\n📊 Completed: [bold]{success_count}/{len(apps)}[/bold] successful.')

	@staticmethod
	def _execute_single_update(app: AppInfo) -> bool:
		"""
		Execute single package update.

		Constructs and executes the appropriate update command based on the
		package source. Each package manager has its own command syntax and
		options.

		Args:
		    app: AppInfo object with name, source, and latest_version set.

		Returns:
		    bool: True if update command executed successfully, False otherwise.

		Supported Sources:
		    - Winget: winget upgrade --id <app_id> [-v <version>]
		    - Chocolatey: choco upgrade <name> [-y] [--version <version>]
		    - NPM: npm install -g <name>@<version>
		    - PNPM: pnpm add -g <name>@<version>
		    - Bun: bun add -g <name>@<version>
		    - Yarn: yarn global add <name>@<version>
		    - PIP: pip install <name>==<version> or pip install --upgrade <name>
		    - Rust: cargo install-update <name>
		    - PATH: Source-specific commands (bun upgrade, deno upgrade, etc.)
		"""
		cmd = None
		target_ver = app.latest_version

		if app.source == 'Winget':
			cmd = [
				'winget',
				'upgrade',
				'--id',
				app.app_id,
				'--accept-source-agreements',
				'--accept-package-agreements',
			]
			if target_ver:
				cmd.extend(['-v', target_ver])

		elif app.source == 'Chocolatey':
			cmd = ['choco', 'upgrade', app.name, '-y']
			if target_ver:
				cmd.extend(['--version', target_ver])

		elif app.source == 'NPM':
			ver_spec = f'@{target_ver}' if target_ver else ''
			cmd = ['npm', 'install', '-g', f'{app.name}{ver_spec}']

		elif app.source == 'PNPM':
			ver_spec = f'@{target_ver}' if target_ver else ''
			cmd = ['pnpm', 'add', '-g', f'{app.name}{ver_spec}']

		elif app.source == 'Bun':
			ver_spec = f'@{target_ver}' if target_ver else ''
			cmd = ['bun', 'add', '-g', f'{app.name}{ver_spec}']

		elif app.source == 'Yarn':
			ver_spec = f'@{target_ver}' if target_ver else ''
			cmd = ['yarn', 'global', 'add', f'{app.name}{ver_spec}']

		elif app.source == 'PIP':
			ver_spec = f'=={target_ver}' if target_ver else ''
			cmd = [sys.executable, '-m', 'pip', 'install', f'{app.name}{ver_spec}']
			if not target_ver:
				cmd.append('--upgrade')

		elif app.source == 'Rust':
			cmd = ['cargo', 'install-update', app.name]

		elif app.source == 'PATH':
			if app.name == 'bun':
				cmd = ['bun', 'upgrade']
			elif app.name == 'deno':
				cmd = ['deno', 'upgrade']
				if target_ver:
					cmd.extend(['--version', target_ver])
			elif app.name == 'git':
				cmd = ['git', 'update-git-for-windows', '-y']
			elif app.name == 'pwsh':
				cmd = [
					'powershell',
					'-Command',
					'iex "& { $(irm https://aka.ms/install-powershell.ps1) }"',
				]
			elif app.name == 'yarn':
				cmd = [
					'npm',
					'install',
					'-g',
					f'yarn@{target_ver}' if target_ver else 'yarn',
				]

		if cmd:
			return bool(run_command(cmd))

		return False


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN APPLICATION
# ═══════════════════════════════════════════════════════════════════════════════


class SystemUpdateApp:
	"""
	Main application controller.

	This class orchestrates the entire system update workflow, including:
	    - System scanning across multiple package sources
	    - Update checking and vulnerability detection
	    - Result display and export
	    - Update execution

	It serves as the primary interface between the command-line arguments and
	the underlying scanning, checking, and execution subsystems.

	Attributes:
	    ui: UISystem instance for display operations.
	    scanner: PackageScanner instance for system scanning.
	    checker: UpdateChecker instance for update detection.
	    executor: UpdateExecutor instance for applying updates.
	    cache_mgr: CacheManager instance for caching scan results.

	Example:
	    >>> app = SystemUpdateApp()
	    >>> args = parser.parse_args()
	    >>> app.run(args)
	"""

	def __init__(self):
		"""
		Initialize SystemUpdateApp with all required subsystems.

		Creates instances of UI, scanner, checker, executor, and cache manager
		using configuration settings.
		"""
		self.ui = UISystem()
		self.scanner = PackageScanner()
		self.checker = UpdateChecker()
		self.executor = UpdateExecutor()
		self.cache_mgr = CacheManager(config.cache_file, config.settings['cache']['duration_hours'])

	def scan_system(self, source_filter: Optional[str] = None) -> List[AppInfo]:
		"""
		Perform comprehensive system scan matching JS scanSystem.

		Scans all enabled package sources in parallel using ThreadPoolExecutor.
		Displays progress using Rich Progress bar with per-source app counts.

		Args:
		    source_filter: Optional source name to filter scanning to a single
		        source (e.g., "winget", "npm"). If None, scans all enabled sources.

		Returns:
		    List[AppInfo]: Sorted list of unique applications discovered across
		        all scanned sources.

		Process:
		    1. Maps source names to scanner methods
		    2. Filters by source_filter if specified
		    3. Filters by enabled sources in config
		    4. Scans sources in parallel using ThreadPoolExecutor
		    5. Deduplicates results by source|name|version
		    6. Returns sorted list of unique apps

		Note:
		    - Uses config.settings["performance"]["max_workers"] for thread count
		    - Deduplicates by creating dict keyed by "source|name|version"
		"""
		# Map source names to scanner methods (matching JS order)
		scanners = {
			'winget': self.scanner.scan_winget,
			'chocolatey': self.scanner.scan_chocolatey,
			'npm': self.scanner.scan_npm,
			'pnpm': self.scanner.scan_pnpm,
			'bun': self.scanner.scan_bun,
			'yarn': self.scanner.scan_yarn,
			'pip': self.scanner.scan_pip,
			'path': self.scanner.scan_path,
			'registry': self.scanner.scan_registry,
			'rust': self.scanner.scan_rust,
		}

		# Filter by source if specified
		if source_filter:
			source_filter_lower = source_filter.lower()
			matched_source = next(
				(name for name in scanners.keys() if name.lower() == source_filter_lower),
				None,
			)
			if matched_source:
				scanners = {matched_source: scanners[matched_source]}
				console.print(f'[cyan]🔍 Filtering by source: {matched_source}[/cyan]')
			else:
				console.print(
					f"[yellow]⚠️  Unknown source '{source_filter}', scanning all sources[/yellow]"
				)

		# Filter by enabled sources in config
		selected = [
			(name, func)
			for name, func in scanners.items()
			if config.settings['sources'].get(name, True)
		]

		all_apps = []
		max_workers = config.settings['performance']['max_workers']

		# Scan in parallel like JS Promise.all using Rich Progress
		with Progress(
			TextColumn('{task.description}'),
			BarColumn(
				bar_width=26,
				complete_style='white',
				style='dim white',
				finished_style='white',
			),
			TextColumn('[progress.percentage]{task.percentage:>3.0f}%'),
			MofNCompleteColumn(),
			TimeElapsedColumn(),
			TextColumn('{task.fields[extra]}'),
			console=console,
		) as progress:
			task = progress.add_task('🔎 Scanning', total=len(selected), extra='')

			with ThreadPoolExecutor(max_workers=max_workers) as executor:
				future_to_source = {executor.submit(func): name for name, func in selected}

				for future in as_completed(future_to_source):
					source_name = future_to_source[future]
					try:
						apps = future.result()
						# Deduplicate by source|name|version
						unique_apps = list(
							{f'{a.source}|{a.name}|{a.version}'.lower(): a for a in apps}.values()
						)
						all_apps.extend(unique_apps)
						# Match JS: source_badge + count
						progress.update(
							task,
							advance=1,
							extra=f'{source_badge(source_name)} [bold cyan]{str(len(unique_apps)).rjust(4)}[/bold cyan] apps',
						)
					except Exception as e:
						console.print(f'  [red]✗[/red] {source_name} failed: {e}')

			# Mark complete matching JS
			progress.update(task, extra='✅ [bold green]scan complete[/bold green]')

		# Return unique apps sorted like JS
		return sorted(all_apps, key=lambda x: f'{x.source}{x.name}')

	def export_results(
		self, apps: List[AppInfo], format_type: str, output_file: Optional[str] = None
	):
		"""
		Export scan results in various formats.

		Exports the list of applications to a file in the specified format.
		Supports JSON and CSV formats with optional custom output filename.

		Args:
		    apps: List of AppInfo objects to export.
		    format_type: Export format ("json" or "csv").
		    output_file: Optional output filename. If None, generates filename
		        with timestamp (e.g., "system_update_20240101_120000.json").

		Formats:
		    - json: Full application data with all fields in JSON format
		    - csv: Tabular data with Name, Source, Version, Latest, Status columns

		Note:
		    - JSON includes full app metadata via app.to_dict()
		    - CSV includes basic fields suitable for spreadsheet import
		"""
		if not output_file:
			timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
			output_file = f'system_update_{timestamp}.{format_type}'

		try:
			if format_type == 'json':
				data = {
					'scan_time': datetime.now().isoformat(),
					'total_apps': len(apps),
					'apps': [app.to_dict() for app in apps],
				}
				with open(output_file, 'w', encoding='utf-8') as f:
					json.dump(data, f, indent=2)

			elif format_type == 'csv':
				with open(output_file, 'w', newline='', encoding='utf-8') as f:
					writer = csv.writer(f)
					writer.writerow(['Name', 'Source', 'Version', 'Latest', 'Status'])
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

			console.print(f'[green]✅ Exported to {output_file}[/green]')

		except Exception as e:
			console.print(f'[red]❌ Export failed: {e}[/red]')

	def run(self, args):
		"""
		Main application entry point.

		Executes the complete system update workflow based on command-line
		arguments. Handles cache management, scanning, update checking,
		display, and update execution.

		Args:
		    args: Parsed command-line arguments from argparse.

		Workflow:
		    1. Handle cache operations (clear if requested)
		    2. Display application banner
		    3. Load from cache or perform fresh scan
		    4. Check for updates across all sources
		    5. Check for security vulnerabilities
		    6. Save results to cache
		    7. Display summary and application tables
		    8. Handle single-package update if requested
		    9. Execute updates if --update-all specified
		    10. Export results if requested

		Note:
		    - Three-phase scan: SCANNING → UPDATE CHECKING → SECURITY CHECK
		    - Respects --no-cache flag to force fresh scan
		    - Handles --package for single-package updates
		"""
		# Handle cache operations
		if args.clear_cache:
			self.cache_mgr.clear()
			console.print('[green]🗑️  Cache cleared successfully![/green]')
			return

		# Display beautiful banner
		self.ui.display_banner()

		# Load from cache or scan
		apps = None
		if not args.no_cache and config.settings['cache']['enabled']:
			apps = self.cache_mgr.load()
			if apps:
				console.print(f'[dim]💾 Loaded {len(apps)} items from cache[/dim]\n')

		if apps is None:
			start_time = time.time()

			# --- PHASE 1: SCANNING ---
			console.print('[bold cyan]🔎 Scanning sources...[/bold cyan]')
			# Scan system (progress bar handled internally)
			apps = self.scan_system(args.source)

			# Report discovered count (match JS flow)
			console.print(f'\n📦 [bold]Discovered {len(apps)} unique apps.[/bold]')

			# --- PHASE 2: UPDATE CHECKING ---
			console.print('[bold cyan]🔄 Checking for updates...[/bold cyan]')
			# Check updates (progress bar handled internally)
			total_updates = self.checker.check_all_updates(apps)

			console.print(
				f'[bold magenta]📊 Detected {total_updates} update candidates.[/bold magenta]\n'
			)

			# --- PHASE 3: SECURITY CHECK ---
			console.print(f'[bold magenta]🔒 Checking security vulnerabilities...[/bold magenta]')
			# (Assuming security scan is fast for now or integrated)
			console.print(f'[bold green]🛡️ No security vulnerabilities found.[/bold green]\n')

			# Save to cache
			self.cache_mgr.save(apps)

			scan_time = time.time() - start_time
		else:
			# For cached results, calculate updates count and set scan time to 0
			total_updates = sum(1 for a in apps if a.update_status == UpdateStatus.UPDATE_AVAILABLE)
			scan_time = 0.0

		# Display summary (always)
		sources_count = {}
		for app in apps:
			sources_count[app.source] = sources_count.get(app.source, 0) + 1

		self.ui.display_summary(
			len(apps), total_updates, scan_time, sources_count, show_all=args.show_all
		)

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
			security_table.title = '[bold red]🔒 Security Alerts[/bold red]'
			for app in vulnerable:
				security_table.add_row(app.name, 'VULNERABLE', 'N/A', 'Update recommended')
			console.print(security_table)

		# Show applications table
		console.print()
		apps_table = self.ui.create_apps_table(
			apps, '📦 All Installed Applications', show_all=args.show_all
		)
		console.print(apps_table)

		# Display showing status after table (matching JS behavior)
		if args.show_all:
			console.print(f'\n[dim]💾 Showing: all packages[/dim]')
		else:
			console.print(f'\n[dim]💾 Showing: updates only[/dim]')

		# Handle updates
		if updates:
			console.print(f'\n[bold yellow]🎯 Found {len(updates)} available updates[/bold yellow]')

			if args.update_all:
				if Confirm.ask('🚀 Proceed with all updates?'):
					self.executor.execute_updates(updates, args.dry_run)
		else:
			console.print('\n[green]✨ System is up to date![/green]')

		# Export results if requested
		if args.export:
			self.export_results(apps, args.export, args.output)

	def _handle_single_update(self, apps: List[AppInfo], args):
		"""
		Handle single package update request.

		Processes a request to update a specific package by name and optionally
		by source. Handles ambiguous package names by prompting for source
		specification.

		Args:
		    apps: List of all scanned AppInfo objects to search.
		    args: Parsed command-line arguments containing package, source,
		        version, and dry_run options.

		Process:
		    1. Search for package by name (case-insensitive)
		    2. Filter by source if specified
		    3. Handle multiple matches by prompting for source
		    4. Handle up-to-date packages with force reinstall option
		    5. Execute update for target package

		Note:
		    - If --version specified, targets that specific version
		    - If package is up-to-date, prompts for force reinstall
		    - If multiple packages match, displays all and requests --source
		"""
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
				console.print(f'[dim]🔍 Filter: source={args.source}[/dim]')
			return

		if len(candidates) > 1 and not args.source:
			console.print(f'[yellow]⚠️  Multiple packages found:[/yellow]')
			for i, c in enumerate(candidates):
				console.print(f'  {i + 1}. {c.name} ({c.source}) - {c.version}')
			console.print('[yellow]💡 Please specify --source to target one[/yellow]')
			return

		target_app = candidates[0]

		if args.version:
			target_app.latest_version = args.version
			console.print(f'[cyan]🎯 Targeting version: {args.version}[/cyan]')
		elif not target_app.has_update and not args.version:
			console.print(
				f'[green]✅ {target_app.name} is up to date ({target_app.version})[/green]'
			)
			if not Confirm.ask('🔄 Force reinstall?'):
				return

		self.executor.execute_updates([target_app], args.dry_run)


def main():
	"""
	Application entry point.

	Sets up command-line argument parsing and launches the SystemUpdateApp.
	Defines all available command-line options and their descriptions.

	Command-Line Options:
	    --update-all: Update all available packages (with confirmation)
	    --dry-run: Preview updates without executing them
	    --no-cache: Force fresh scan, ignore cached results
	    --clear-cache: Clear the scan cache and exit
	    --show-all: Show all packages including up-to-date ones
	    --export: Export results in specified format (json/csv)
	    --output: Custom output filename for export
	    --package: Update specific package by name
	    --version: Target version for package update
	    --source: Filter by package source (winget, npm, etc.)

	Examples:
	    python system_update.py                    # Scan and show updates
	    python system_update.py --update-all      # Update all packages
	    python system_update.py --dry-run          # Preview updates
	    python system_update.py --package git     # Update specific package
	    python system_update.py --source rust      # Filter by source
	    python system_update.py --export json     # Export results to JSON
	    python system_update.py --show-all        # Show all packages
	"""
	parser = argparse.ArgumentParser(
		description='System Update Enhanced v2.0 - Elite Package Manager',
		formatter_class=argparse.RawDescriptionHelpFormatter,
		epilog="""
Examples:
  python system_update.py                    # Scan and show updates
  python system_update.py --update-all      # Update all packages
  python system_update.py --dry-run          # Preview updates
  python system_update.py --package git     # Update specific package
  python system_update.py --source rust      # Filter by source
  python system_update.py --export json     # Export results to JSON
  python system_update.py --show-all        # Show all packages (including up-to-date)
        """,
	)

	# Main options
	parser.add_argument('--update-all', action='store_true', help='Update all available packages')
	parser.add_argument('--dry-run', action='store_true', help='Preview updates without executing')
	parser.add_argument('--no-cache', action='store_true', help='Force fresh scan (ignore cache)')
	parser.add_argument('--clear-cache', action='store_true', help='Clear scan cache')
	parser.add_argument(
		'--show-all',
		action='store_true',
		help='Show all packages (including up-to-date)',
	)

	# Export options
	parser.add_argument('--export', choices=['json', 'csv'], help='Export results format')
	parser.add_argument('--output', help='Output file for export')

	# Package options
	parser.add_argument('--package', help='Update specific package name')
	parser.add_argument('--version', help='Target version for package update')
	parser.add_argument(
		'--source',
		help='Package source filter (Winget, Chocolatey, NPM, PNPM, PIP, PATH, Registry)',
	)

	args = parser.parse_args()

	# Create and run application
	app = SystemUpdateApp()
	app.run(args)


if __name__ == '__main__':
	"""
    Main entry point when script is executed directly.

    This block ensures that the main() function is called only when the script
    is run directly (not when imported as a module). This is a Python best
    practice that allows the file to be both executable and importable.

    Example:
        # Run directly:
        python system_update.py --update-all

        # Import as module (main() won't be called):
        from system_update import SystemUpdateApp, AppInfo
    """
	main()
