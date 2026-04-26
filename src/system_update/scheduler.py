"""Scheduled scans / updates — enhancement section 6.1.

Implements:
    6.1.1 — Task Scheduler integration (Windows ``schtasks``)
    6.1.2 — Daily / weekly / hourly / monthly / onstart / onlogon recurrences
    6.1.3 — Conditional actions evaluated after a scan (in :mod:`conditions`)

On non-Windows the scheduler raises a clear error explaining that the user
should configure cron / systemd / launchd manually. We deliberately don't
try to manage cron on POSIX — Windows Task Scheduler is what the project
targets, and an opinionated cron implementation would silently break user
crontabs.
"""

from __future__ import annotations

import csv
import io
import logging
import platform
import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


# ─── Models ────────────────────────────────────────────────────────────────


_VALID_FREQUENCIES = {'daily', 'weekly', 'hourly', 'monthly', 'onstart', 'onlogon'}
_DEFAULT_TASK_PREFIX = 'SystemUpdate_'


@dataclass
class ScheduleSpec:
	"""User-facing description of a scheduled task."""

	name: str = 'SystemUpdate_Scan'
	frequency: str = 'daily'
	time: str = '09:00'
	days: str = ''  # comma-list for weekly: MON,WED,FRI
	command_args: str = '--no-cache --notify'
	description: str = 'Automated system-update scan'

	def validate(self) -> None:
		if self.frequency not in _VALID_FREQUENCIES:
			raise ValueError(
				f'Invalid frequency {self.frequency!r}. '
				f'Valid: {sorted(_VALID_FREQUENCIES)}'
			)
		if self.frequency in ('daily', 'weekly', 'monthly') and not self.time:
			raise ValueError(f'{self.frequency} schedule requires --schedule-time HH:MM')
		if self.time and ':' not in self.time:
			raise ValueError(f'Invalid --schedule-time {self.time!r} (expected HH:MM)')


# ─── Backend detection ─────────────────────────────────────────────────────


def is_windows() -> bool:
	return platform.system() == 'Windows'


def _require_windows() -> None:
	if not is_windows():
		raise RuntimeError(
			'Task scheduling currently supports Windows Task Scheduler only. '
			'On Linux/macOS, configure cron / systemd / launchd manually — '
			'``system-update`` itself just runs the scan.'
		)


def _python_exe() -> str:
	"""Path to the interpreter the schedule should re-launch us with."""
	return sys.executable


def _build_command(args: str) -> str:
	"""Build the quoted command string passed to ``schtasks /TR``."""
	py = _python_exe()
	cmd_args = (args or '').strip()
	return f'"{py}" -m system_update {cmd_args}'.strip()


def _run_schtasks(argv: List[str]) -> str:
	"""Invoke ``schtasks`` and return stdout, raising on non-zero exit."""
	logger.debug(f'schtasks: {argv}')
	result = subprocess.run(
		argv,
		capture_output=True,
		text=True,
		encoding='utf-8',
		errors='replace',
	)
	if result.returncode != 0:
		err = (result.stderr or result.stdout or '').strip()
		raise RuntimeError(f'schtasks failed: {err}')
	return result.stdout or ''


# ─── 6.1.1 / 6.1.2 — create / delete / list / status ───────────────────────


def create_task(spec: ScheduleSpec) -> Dict:
	"""Create or replace a scheduled task. Returns a dict describing the result."""
	_require_windows()
	spec.validate()

	cmd = _build_command(spec.command_args)
	argv = ['schtasks', '/Create', '/F', '/TN', spec.name, '/TR', cmd]

	if spec.frequency == 'daily':
		argv += ['/SC', 'DAILY', '/ST', spec.time]
	elif spec.frequency == 'weekly':
		argv += ['/SC', 'WEEKLY', '/ST', spec.time]
		if spec.days:
			argv += ['/D', spec.days]
	elif spec.frequency == 'hourly':
		argv += ['/SC', 'HOURLY']
	elif spec.frequency == 'monthly':
		argv += ['/SC', 'MONTHLY', '/ST', spec.time]
	elif spec.frequency == 'onstart':
		argv += ['/SC', 'ONSTART']
	elif spec.frequency == 'onlogon':
		argv += ['/SC', 'ONLOGON']

	out = _run_schtasks(argv)
	return {
		'name': spec.name,
		'frequency': spec.frequency,
		'time': spec.time,
		'days': spec.days,
		'command': cmd,
		'output': out.strip(),
	}


def delete_task(name: str) -> Dict:
	"""Delete a scheduled task by name."""
	_require_windows()
	out = _run_schtasks(['schtasks', '/Delete', '/F', '/TN', name])
	return {'name': name, 'output': out.strip()}


def run_task_now(name: str) -> Dict:
	"""Run a scheduled task immediately."""
	_require_windows()
	out = _run_schtasks(['schtasks', '/Run', '/TN', name])
	return {'name': name, 'output': out.strip()}


def list_tasks(prefix: str = _DEFAULT_TASK_PREFIX) -> List[Dict]:
	"""Return all scheduled tasks whose name starts with ``prefix``.

	Uses ``schtasks /Query /FO CSV /V`` (verbose with header) to recover the
	``Last Run Time`` and ``Last Result`` columns alongside ``Next Run Time``
	and ``Status``. Returns ``[]`` (not error) on non-Windows so callers can
	render an empty state cleanly.
	"""
	if not is_windows():
		return []
	try:
		raw = _run_schtasks(['schtasks', '/Query', '/FO', 'CSV', '/V'])
	except RuntimeError as e:
		logger.warning(f'schtasks query failed: {e}')
		return []

	tasks: List[Dict] = []
	reader = csv.DictReader(io.StringIO(raw))
	seen: set = set()
	for row in reader:
		# Skip the repeated header rows ``schtasks`` emits between task groups.
		task_name_raw = (row.get('TaskName') or '').strip()
		if not task_name_raw or task_name_raw.lower() == 'taskname':
			continue
		task_name = task_name_raw.lstrip('\\')
		if not task_name.startswith(prefix):
			continue
		# Verbose output emits one row per trigger; collapse to one per task.
		if task_name in seen:
			continue
		seen.add(task_name)
		tasks.append({
			'name': task_name,
			'next_run': (row.get('Next Run Time') or '').strip(),
			'status': (row.get('Status') or '').strip(),
			'last_run': (row.get('Last Run Time') or '').strip(),
			'last_result': (row.get('Last Result') or '').strip(),
		})
	return tasks


def task_status(name: str) -> Optional[Dict]:
	"""Return verbose info for ``name`` or ``None`` if not found."""
	_require_windows()
	try:
		raw = _run_schtasks(['schtasks', '/Query', '/TN', name, '/FO', 'LIST', '/V'])
	except RuntimeError:
		return None

	info: Dict[str, str] = {}
	for line in raw.splitlines():
		if ':' not in line:
			continue
		key, _, value = line.partition(':')
		key = key.strip()
		value = value.strip()
		if key:
			info[key] = value
	if not info:
		return None
	return {
		'name': info.get('TaskName', name),
		'status': info.get('Status', ''),
		'last_run_time': info.get('Last Run Time', ''),
		'last_result': info.get('Last Result', ''),
		'next_run_time': info.get('Next Run Time', ''),
		'task_to_run': info.get('Task To Run', ''),
		'schedule_type': info.get('Schedule Type', ''),
		'run_as_user': info.get('Run As User', ''),
	}


__all__ = [
	'ScheduleSpec',
	'is_windows',
	'create_task',
	'delete_task',
	'run_task_now',
	'list_tasks',
	'task_status',
]
