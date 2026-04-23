"""Scan globally installed PNPM packages via ``pnpm list -g --json``."""

from __future__ import annotations

import json
from typing import List

from system_update.models import AppInfo
from system_update.utils import run_command


def scan() -> List[AppInfo]:
	"""Return top-level PNPM global packages; tolerates array or object JSON."""
	apps: List[AppInfo] = []
	output = run_command(['pnpm', 'list', '-g', '--depth=0', '--json'], allow_failure=True)
	if not output:
		return apps

	try:
		data = json.loads(output)
		data = data[0] if isinstance(data, list) and data else data
		if isinstance(data, dict):
			for name, details in data.get('dependencies', {}).items():
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
