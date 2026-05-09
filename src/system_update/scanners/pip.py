"""Scan PIP-installed Python packages — context-aware (venv vs system)."""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Dict, List, Optional

from system_update.models import AppInfo
from system_update.utils import run_command

logger = logging.getLogger(__name__)


def _is_in_venv() -> bool:
	"""Return True when the running interpreter is inside a venv."""
	return (
		hasattr(sys, 'real_prefix')
		or (getattr(sys, 'base_prefix', sys.prefix) != sys.prefix)
		or bool(os.environ.get('VIRTUAL_ENV') or os.environ.get('CONDA_PREFIX'))
	)


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


def _parse_pip_list(raw: Optional[str]) -> List[Dict]:
	"""Decode a ``pip list --format=json`` output. Returns ``[]`` on any failure."""
	if not raw:
		return []
	try:
		data = json.loads(raw)
	except (json.JSONDecodeError, TypeError):
		return []
	return [item for item in data if isinstance(item, dict) and 'name' in item]


def _is_older(a: str, b: str) -> bool:
	"""Return True if version ``a`` is strictly older than ``b`` (PEP 440)."""
	if not a or not b:
		return False
	try:
		from packaging.version import InvalidVersion, parse

		try:
			return parse(a) < parse(b)
		except InvalidVersion:
			return False
	except ImportError:  # pragma: no cover
		return False


def _collect_pip_packages() -> Dict[str, Dict]:
	"""Discover packages from the current Python context.

	Returns a dict keyed by package name; each value holds:
	* ``version``     — installed version
	* ``interpreter`` — full path of the Python that owns the package

	When running inside a venv, scan that active interpreter. Otherwise scan
	known global Python installs.
	"""
	merged: Dict[str, Dict] = {}

	def _record(items: List[Dict], interpreter: str) -> None:
		for item in items:
			name = item.get('name')
			if not name:
				continue
			version = item.get('version', 'unknown')
			existing = merged.get(name)
			if existing is None:
				merged[name] = {'version': version, 'interpreter': interpreter}
				continue
			# Already recorded — keep the older version if multiple Python
			# executable aliases point at overlapping package sets.
			if _is_older(version, existing['version']):
				merged[name] = {'version': version, 'interpreter': interpreter}

	scan_active = _is_in_venv()
	scan_globals = not scan_active

	if scan_globals:
		for pyexe in _GLOBAL_PYTHON_EXES:
			if not os.path.exists(pyexe):
				continue
			# scrub_venv: under ``uv run`` (or any active venv) VIRTUAL_ENV
			# leaks into subprocess env and can shadow the interpreter we
			# explicitly invoke — pip honours it for some operations. Drop
			# it so the global Python's own site-packages are reported.
			out = run_command(
				[pyexe, '-m', 'pip', 'list', '--format=json'],
				allow_failure=True, scrub_venv=True,
			)
			if out and len(out) > 100:
				_record(_parse_pip_list(out), pyexe)

	if scan_active:
		for cmd in _PIP_COMMANDS:
			out = run_command(cmd, allow_failure=True)
			if out:
				interp = cmd[0] if cmd[0] != 'python' else sys.executable
				_record(_parse_pip_list(out), interp)
				break

		# ``--user`` site of the active interpreter — fills gaps when the
		# main listing came back empty.
		if not merged:
			out = run_command(
				[sys.executable, '-m', 'pip', 'list', '--format=json', '--user'],
				allow_failure=True,
			)
			_record(_parse_pip_list(out), sys.executable)

	return merged


def scan() -> List[AppInfo]:
	"""Return PIP packages discoverable in the current Python context."""
	merged = _collect_pip_packages()
	apps: List[AppInfo] = []
	for name, meta in merged.items():
		apps.append(
			AppInfo(
				name=name,
				source='PIP',
				version=meta.get('version', 'unknown'),
				app_id=name,
				install_path=meta.get('interpreter') or '',
			)
		)
	return apps
