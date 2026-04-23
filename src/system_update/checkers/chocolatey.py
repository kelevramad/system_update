"""Check Chocolatey updates via ``choco outdated``."""

from __future__ import annotations

from typing import List

from system_update.models import AppInfo, UpdateStatus
from system_update.utils import run_command


def check(apps: List[AppInfo]) -> int:
	"""Parse ``name|version|latest`` rows from ``choco outdated --limit-output``."""
	updates = 0
	output = run_command(['choco', 'outdated', '--limit-output'], allow_failure=True)
	if not output:
		return updates

	for line in output.splitlines():
		parts = line.split('|')
		if len(parts) >= 3:
			for app in apps:
				if app.name == parts[0]:
					app.latest_version = parts[2]
					app.update_status = UpdateStatus.UPDATE_AVAILABLE
					updates += 1

	return updates
