"""Check PNPM global package updates via ``pnpm outdated -g --json``."""

from __future__ import annotations

import json
from typing import List

from system_update.models import AppInfo, UpdateStatus
from system_update.utils import run_command


def _apply(apps: List[AppInfo], name: str, latest: str) -> int:
	if not latest:
		return 0
	for app in apps:
		if app.name == name:
			app.latest_version = latest
			app.update_status = UpdateStatus.UPDATE_AVAILABLE
			return 1
	return 0


def check(apps: List[AppInfo]) -> int:
	"""Handle both dict-keyed and list-of-records JSON shapes from PNPM."""
	updates = 0
	output = run_command(['pnpm', 'outdated', '-g', '--json'], allow_failure=True)
	if not output:
		return updates

	try:
		data = json.loads(output)
		if isinstance(data, dict):
			for name, details in data.items():
				updates += _apply(apps, name, details.get('latest', details.get('wanted', '')))
		elif isinstance(data, list):
			for item in data:
				updates += _apply(
					apps, item.get('name', ''), item.get('latest', item.get('wanted', ''))
				)
	except Exception:
		pass

	return updates
