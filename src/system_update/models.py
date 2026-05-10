"""Core data models — dataclasses and enums shared across the package."""

from __future__ import annotations

import json
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional


class ErrorCategory(Enum):
	"""Classification of error types for better error handling."""

	NOT_FOUND = 'not_found'
	TIMEOUT = 'timeout'
	PERMISSION_DENIED = 'permission_denied'
	NETWORK_ERROR = 'network_error'
	PARSE_ERROR = 'parse_error'
	COMMAND_FAILED = 'command_failed'
	UNKNOWN = 'unknown'


class CommandError:
	"""Structured error information with recovery suggestions."""

	def __init__(
		self,
		category: ErrorCategory,
		message: str,
		command: str = '',
		suggestion: str = '',
	) -> None:
		self.category = category
		self.message = message
		self.command = command
		self.suggestion = suggestion

	@staticmethod
	def classify(exception: BaseException, command: str = '') -> 'CommandError':
		"""Classify an exception and provide recovery suggestions."""
		error_type = type(exception).__name__

		if isinstance(exception, FileNotFoundError):
			return CommandError(
				category=ErrorCategory.NOT_FOUND,
				message=f'Command not found: {command}',
				command=command,
				suggestion=f'Ensure {command.split()[0] if command else "the tool"} is installed and in PATH',
			)
		if isinstance(exception, subprocess.TimeoutExpired):
			return CommandError(
				category=ErrorCategory.TIMEOUT,
				message=f'Command timed out: {command}',
				command=command,
				suggestion='Increase timeout or check if the command is hanging',
			)
		if isinstance(exception, PermissionError):
			return CommandError(
				category=ErrorCategory.PERMISSION_DENIED,
				message=f'Permission denied: {command}',
				command=command,
				suggestion='Run as administrator or check file permissions',
			)
		if isinstance(exception, (json.JSONDecodeError, ValueError)):
			return CommandError(
				category=ErrorCategory.PARSE_ERROR,
				message=f'Failed to parse output: {error_type}',
				command=command,
				suggestion='Check command output format or version compatibility',
			)
		if isinstance(exception, subprocess.CalledProcessError):
			return CommandError(
				category=ErrorCategory.COMMAND_FAILED,
				message=f'Command failed with code {exception.returncode}: {command}',
				command=command,
				suggestion='Check command syntax and dependencies',
			)
		return CommandError(
			category=ErrorCategory.UNKNOWN,
			message=f'{error_type}: {str(exception)}',
			command=command,
			suggestion='Check logs for details or run with --debug',
		)


class UpdateStatus(Enum):
	"""Enumeration of package update status states."""

	UP_TO_DATE = 'up_to_date'
	UPDATE_AVAILABLE = 'update_available'
	UNKNOWN = 'unknown'
	ERROR = 'error'
	VULNERABLE = 'vulnerable'
	SECURITY_UPDATE_AVAILABLE = 'security_update_available'


@dataclass
class AppInfo:
	"""Structured application metadata container.

	Central data carrier used throughout the scan → check → update pipeline.
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
	security_findings: List[Dict] = field(default_factory=list)

	@property
	def has_update(self) -> bool:
		"""Return True if a newer version is known and differs from current."""
		return bool(self.latest_version and self.latest_version != self.version)

	@property
	def is_vulnerable(self) -> bool:
		"""Return True if any security findings are attached to this package."""
		return len(self.security_findings) > 0

	@property
	def status_display(self) -> str:
		"""Return a human-readable status string with emoji prefix."""
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
		"""Serialize to dict using camelCase keys (matches cache.json format)."""
		return {
			'name': self.name,
			'source': self.source.lower(),
			'version': self.version,
			'latestVersion': self.latest_version or '-',
			'appId': self.app_id,
			'status': self.update_status.value,
			'scanTime': self.scan_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
			'errorMsg': self.error_msg,
			'installPath': self.install_path,
			'securityFindings': list(self.security_findings),
		}


@dataclass
class SecurityInfo:
	"""Security vulnerability metadata container (CVE + severity + CVSS)."""

	cve_id: str
	severity: str
	cvss_score: float
	description: str
	affected_versions: List[str] = field(default_factory=list)
	published_date: Optional[datetime] = None

	def to_dict(self) -> Dict:
		"""Serialize to dict with ISO-formatted dates for JSON safety."""
		data = asdict(self)
		if self.published_date:
			data['published_date'] = self.published_date.isoformat()
		return data
