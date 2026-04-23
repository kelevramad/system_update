"""Scan Scoop-managed packages via ``scoop list``."""

from __future__ import annotations

from typing import List

from system_update.models import AppInfo
from system_update.utils import run_command


def scan() -> List[AppInfo]:
	"""Skip Scoop's header/divider lines and emit one :class:`AppInfo` per row."""
	apps: List[AppInfo] = []
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
			name, version = parts[0], parts[1]
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
