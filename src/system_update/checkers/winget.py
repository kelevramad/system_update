"""Check Winget-managed apps against ``winget upgrade``."""

from __future__ import annotations

from typing import List

from system_update.checkers._winget_upgrade import get_upgrade_rows
from system_update.models import AppInfo, UpdateStatus


def check(apps: List[AppInfo]) -> int:
	"""Match ``apps`` against Winget's upgrade table by ``app_id``; mutate in place."""
	updates = 0
	for row in get_upgrade_rows():
		app_id = row.get('id', '')
		latest = row.get('available', '')
		if not app_id or not latest:
			continue
		for app in apps:
			if app.app_id and app.app_id.lower() == app_id.lower():
				app.latest_version = latest
				app.update_status = UpdateStatus.UPDATE_AVAILABLE
				updates += 1

	return updates
