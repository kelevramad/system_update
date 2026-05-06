"""Check Microsoft Store/AppX updates through ``winget upgrade``."""

from __future__ import annotations

from typing import List

from system_update.checkers._winget_upgrade import get_upgrade_rows
from system_update.models import AppInfo, UpdateStatus


def _matches(app: AppInfo, row: dict[str, str]) -> bool:
	app_id = (app.app_id or '').lower()
	name = app.name.lower()
	row_id = row.get('id', '').lower()
	row_name = row.get('name', '').lower()
	return bool(
		(app_id and (app_id == row_id or app_id.startswith(row_id) or row_id in app_id))
		or (name and name == row_name)
	)


def _check_winget_rows(apps: List[AppInfo], allowed_sources: set[str] | None) -> int:
	"""Mark packages that appear in Winget's upgrade table."""
	rows = [
		row for row in get_upgrade_rows()
		if allowed_sources is None or row.get('source', '').lower() in allowed_sources
	]
	updates = 0
	for app in apps:
		for row in rows:
			if _matches(app, row) and row.get('available'):
				app.app_id = row.get('id') or app.app_id
				app.latest_version = row['available']
				app.update_status = UpdateStatus.UPDATE_AVAILABLE
				updates += 1
				break
	return updates


def check(apps: List[AppInfo]) -> int:
	"""Mark Store/AppX packages that appear in Winget's Store upgrade table."""
	return _check_winget_rows(apps, {'msstore', 'store'})


def check_msix(apps: List[AppInfo]) -> int:
	"""Mark MSIX packages that appear in Winget's upgrade table."""
	return _check_winget_rows(apps, None)
