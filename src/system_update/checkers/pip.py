"""Check PIP package updates via ``pip list --outdated`` and PyPI fallback."""

from __future__ import annotations

import json
import os
import sys
import urllib.request
from typing import List

from system_update.models import AppInfo, UpdateStatus
from system_update.utils import run_command

_OUTDATED_COMMANDS = [
	['uv', 'pip', 'list', '--outdated', '--format=json'],
	[sys.executable, '-m', 'pip', 'list', '--outdated', '--format=json'],
	['pip', 'list', '--outdated', '--format=json'],
	['pip3', 'list', '--outdated', '--format=json'],
]

_GLOBAL_PYTHON_EXES = [
	'C:\\Users\\vchav\\AppData\\Local\\Programs\\Python\\Python313\\python.exe',
	'C:\\Python313\\python.exe',
	'C:\\Python312\\python.exe',
	'python.exe',
]


def _pypi_latest(name: str) -> str:
	"""Return the ``info.version`` field for ``name`` from PyPI, or ``''`` on failure."""
	url = f'https://pypi.org/pypi/{name}/json'
	req = urllib.request.Request(url, headers={'User-Agent': 'SystemUpdateCLI'})
	try:
		with urllib.request.urlopen(req, timeout=10) as response:
			data = json.loads(response.read().decode())
		return data.get('info', {}).get('version', '') if isinstance(data, dict) else ''
	except Exception:
		return ''


def check(apps: List[AppInfo]) -> int:
	"""Collect outdated packages for the current Python context."""
	from system_update.scanners.pip import _is_in_venv

	scan_active = _is_in_venv()
	scan_globals = not scan_active

	all_outdated: List[dict] = []

	if scan_active:
		output = None
		for cmd in _OUTDATED_COMMANDS:
			output = run_command(cmd, allow_failure=True)
			if output:
				break
		if output:
			try:
				all_outdated = json.loads(output)
			except Exception:
				pass

	if scan_globals:
		for pyexe in _GLOBAL_PYTHON_EXES:
			if not os.path.exists(pyexe):
				continue
			global_output = run_command(
				[pyexe, '-m', 'pip', 'list', '--outdated', '--format=json'],
				allow_failure=True, scrub_venv=True,
			)
			if global_output and len(global_output) > 10:
				try:
					global_data = json.loads(global_output)
					existing = {p.get('name', '').lower() for p in all_outdated}
					for pkg in global_data:
						if pkg.get('name', '').lower() not in existing:
							all_outdated.append(pkg)
				except Exception:
					pass

	def _newer(installed: str, latest: str) -> bool:
		"""Return True only if ``latest`` is strictly newer than ``installed``."""
		if not installed or not latest:
			return bool(latest and latest != installed)
		try:
			from packaging.version import InvalidVersion, parse

			try:
				return parse(latest) > parse(installed)
			except InvalidVersion:
				return latest != installed
		except ImportError:  # pragma: no cover
			return latest != installed

	updates = 0
	if all_outdated:
		seen: set[str] = set()
		for item in all_outdated:
			if not isinstance(item, dict):
				continue
			name = item.get('name', '')
			latest = item.get('latest_version', '')
			if not name:
				continue
			key = name.lower()
			if key in seen:
				continue
			for app in apps:
				if app.name.lower() != key:
					continue
				# pip-list-outdated may have run against a different interpreter
				# than the one our scanner picked up the package from. Only mark
				# UPDATE_AVAILABLE when the installed version we know about is
				# strictly older than the reported ``latest_version`` — otherwise
				# this install is already at/above the fix and the ``outdated``
				# entry was for a different env.
				if not _newer(app.version, latest):
					seen.add(key)
					break
				app.latest_version = latest
				if app.update_status != UpdateStatus.VULNERABLE:
					app.update_status = UpdateStatus.UPDATE_AVAILABLE
				updates += 1
				seen.add(key)
				break

	for app in apps:
		if app.is_vulnerable and not app.latest_version:
			app.latest_version = _pypi_latest(app.name)

	return updates
