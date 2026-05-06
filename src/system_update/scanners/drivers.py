"""Scan Windows driver packages via ``pnputil /enum-drivers``."""

from __future__ import annotations

import platform
import re
from typing import Dict, List

from system_update.models import AppInfo
from system_update.scanners._versions import clean_version
from system_update.utils import run_command


def _parse_driver_blocks(output: str) -> List[Dict[str, str]]:
	"""Parse localized-ish ``pnputil`` blocks by accepting ``key : value`` rows."""
	drivers: List[Dict[str, str]] = []
	current: Dict[str, str] = {}
	for raw_line in output.splitlines():
		line = raw_line.strip()
		if not line:
			if current:
				drivers.append(current)
				current = {}
			continue
		if ':' not in line:
			continue
		key, value = line.split(':', 1)
		normalized = re.sub(r'[^a-z0-9]+', '_', key.lower()).strip('_')
		current[normalized] = value.strip()
	if current:
		drivers.append(current)
	return drivers


def scan() -> List[AppInfo]:
	"""Return installed driver packages; empty list on non-Windows."""
	if platform.system() != 'Windows':
		return []

	output = run_command(['pnputil', '/enum-drivers'], allow_failure=True)
	apps: List[AppInfo] = []
	for item in _parse_driver_blocks(output or ''):
		published_name = item.get('published_name', '')
		provider = item.get('driver_package_provider', '')
		driver_class = item.get('class_name', '')
		version = clean_version(item.get('driver_version', ''), default='')
		name = provider or published_name
		if not name or not version:
			continue
		apps.append(
			AppInfo(
				name=name,
				source='drivers',
				version=version,
				app_id=published_name or None,
				install_path=driver_class or None,
			)
		)
	return apps
