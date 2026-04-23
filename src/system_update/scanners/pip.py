"""Scan PIP-installed Python packages, merging venv/global/user lists."""

from __future__ import annotations

import json
import os
import sys
from typing import Dict, List

from system_update.models import AppInfo
from system_update.utils import run_command

_PIP_COMMANDS = [
	[sys.executable, '-m', 'pip', 'list', '--format=json'],
	['pip', 'list', '--format=json'],
	['pip3', 'list', '--format=json'],
]

_GLOBAL_PYTHON_EXES = [
	'C:\\Users\\vchav\\AppData\\Local\\Programs\\Python\\Python313\\python.exe',
	'C:\\Python313\\python.exe',
	'C:\\Python312\\python.exe',
	'python.exe',
]


def _merge_pip_lists(output1: str, output2: str) -> List[Dict]:
	"""Merge two ``pip list --format=json`` outputs, deduping by package name."""
	merged: Dict[str, Dict] = {}
	for raw in (output1, output2):
		try:
			data = json.loads(raw) if isinstance(raw, str) else raw
			for item in data:
				if isinstance(item, dict) and 'name' in item:
					merged[item['name']] = item
		except (json.JSONDecodeError, AttributeError, TypeError):
			continue
	return list(merged.values())


def scan() -> List[AppInfo]:
	"""Return all PIP packages discoverable via the active interpreter and globals."""
	output = None
	for cmd in _PIP_COMMANDS:
		output = run_command(cmd, allow_failure=True)
		if output:
			break

	all_packages: List[Dict] = []
	for pyexe in _GLOBAL_PYTHON_EXES:
		if os.path.exists(pyexe):
			try:
				global_output = run_command(
					[pyexe, '-m', 'pip', 'list', '--format=json'], allow_failure=True
				)
				if global_output and len(global_output) > 100:
					if output and len(output) > 100:
						all_packages = _merge_pip_lists(output, global_output)
					else:
						all_packages = json.loads(global_output)
					break
			except Exception:
				pass

	if not all_packages:
		try:
			user_output = run_command(
				[sys.executable, '-m', 'pip', 'list', '--format=json', '--user'],
				allow_failure=True,
			)
			if output and user_output:
				all_packages = _merge_pip_lists(output, user_output)
		except Exception:
			pass

	if not all_packages and output:
		try:
			all_packages = json.loads(output)
		except json.JSONDecodeError:
			pass

	apps: List[AppInfo] = []
	seen: set[str] = set()
	for item in all_packages:
		name = item.get('name')
		if name and name not in seen:
			seen.add(name)
			apps.append(
				AppInfo(
					name=name,
					source='PIP',
					version=item.get('version', 'unknown'),
					app_id=name,
				)
			)
	return apps
