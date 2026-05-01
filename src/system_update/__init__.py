"""System Update CLI — a cross-platform package manager scanner and updater.

Public API for backward compatibility with the flat ``system_update.py`` layout.
Every name listed in ``__all__`` is importable directly from :mod:`system_update`.
"""

from system_update import export
from system_update.cache import CacheManager
from system_update.config import SystemConfig, WarningFileHandler, setup_logging
from system_update.history import HistoryDatabase, VulnerabilityHistory
from system_update.models import (
	AppInfo,
	CommandError,
	ErrorCategory,
	SecurityInfo,
	UpdateStatus,
)
from system_update.notifications import NotificationManager
from system_update.checkers import UpdateChecker
from system_update.cli import main
from system_update.executors import UpdateExecutor
from system_update.app import SystemUpdateApp
from system_update.scanners import PackageScanner
from system_update.security import SecurityChecker
from system_update.ui import DisplayFormatter, ThemeManager, UISystem
from system_update.utils import (
	SOURCE_ICONS,
	THEMES,
	console,
	display_source,
	run_command,
	source_badge,
)

__all__ = [
	'AppInfo',
	'CacheManager',
	'CommandError',
	'DisplayFormatter',
	'ErrorCategory',
	'HistoryDatabase',
	'NotificationManager',
	'PackageScanner',
	'SOURCE_ICONS',
	'SecurityChecker',
	'SecurityInfo',
	'SystemConfig',
	'SystemUpdateApp',
	'THEMES',
	'ThemeManager',
	'UISystem',
	'UpdateChecker',
	'UpdateExecutor',
	'UpdateStatus',
	'VulnerabilityHistory',
	'WarningFileHandler',
	'console',
	'display_source',
	'export',
	'main',
	'run_command',
	'setup_logging',
	'source_badge',
]
