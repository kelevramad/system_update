"""Shared helper for Bun/Yarn checkers — both resolve versions via ``npm info``."""

from __future__ import annotations

from typing import List

from system_update.models import AppInfo, UpdateStatus
from system_update.utils import run_command


def check_via_npm_info(apps: List[AppInfo]) -> int:
	"""Look up the latest version of each app in the NPM registry."""
	updates = 0
	for app in apps:
		output = run_command(['npm', 'info', app.name, 'version'], allow_failure=True)
		if not output:
			continue
		latest = output.strip()
		if latest and latest != app.version and 'ERR' not in latest:
			app.latest_version = latest
			app.update_status = UpdateStatus.UPDATE_AVAILABLE
			updates += 1
	return updates
