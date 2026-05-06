"""Check Registry-installed apps by cross-referencing ``winget upgrade`` output."""

from __future__ import annotations

from typing import List

from system_update.checkers._winget_upgrade import get_upgrade_rows
from system_update.models import AppInfo, UpdateStatus


def _mark_all_up_to_date(apps: List[AppInfo]) -> None:
	for app in apps:
		app.update_status = UpdateStatus.UP_TO_DATE


def check(apps: List[AppInfo]) -> int:
	"""Build a name→latest map from ``winget upgrade`` and apply it to Registry apps."""
	rows = get_upgrade_rows()
	if not rows:
		_mark_all_up_to_date(apps)
		return 0

	upgrade_map: dict = {}
	for row in rows:
		name = row.get('name', '').lower()
		latest = row.get('available', '')
		if name and latest:
			upgrade_map[name] = latest

	updates = 0
	for app in apps:
		latest = upgrade_map.get(app.name.lower())
		if latest:
			app.latest_version = latest
			app.update_status = UpdateStatus.UPDATE_AVAILABLE
			updates += 1
		else:
			app.update_status = UpdateStatus.UP_TO_DATE

	return updates
