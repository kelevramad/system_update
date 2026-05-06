"""Check PowerShell module updates through PowerShellGet."""

from __future__ import annotations

from typing import List

from system_update.models import AppInfo, UpdateStatus
from system_update.utils import run_command


def _ps_single_quote(value: str) -> str:
	return "'" + value.replace("'", "''") + "'"


def check(apps: List[AppInfo]) -> int:
	"""Use ``Find-Module`` to compare installed modules with repository versions."""
	updates = 0
	for app in apps:
		output = run_command(
			[
				'powershell',
				'-NoProfile',
				'-Command',
				f'(Find-Module -Name {_ps_single_quote(app.name)} -ErrorAction SilentlyContinue).Version',
			],
			allow_failure=True,
		)
		latest = (output or '').strip().splitlines()[0].strip() if output else ''
		if latest and latest != app.version:
			app.latest_version = latest
			app.update_status = UpdateStatus.UPDATE_AVAILABLE
			updates += 1
		else:
			app.update_status = UpdateStatus.UP_TO_DATE
	return updates
