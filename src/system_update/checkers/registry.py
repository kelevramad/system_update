"""Check Registry-installed apps by cross-referencing ``winget upgrade`` output."""

from __future__ import annotations

from typing import List

from system_update.models import AppInfo, UpdateStatus
from system_update.utils import run_command


def _mark_all_up_to_date(apps: List[AppInfo]) -> None:
	for app in apps:
		app.update_status = UpdateStatus.UP_TO_DATE


def check(apps: List[AppInfo]) -> int:
	"""Build a name→latest map from ``winget upgrade`` and apply it to Registry apps."""
	output = run_command(
		['winget', 'upgrade', '--accept-source-agreements'], allow_failure=True
	)
	if not output:
		_mark_all_up_to_date(apps)
		return 0

	lines = output.splitlines()
	header_index = next(
		(i for i, line in enumerate(lines) if 'Name' in line and 'Id' in line), -1
	)
	if header_index == -1:
		_mark_all_up_to_date(apps)
		return 0

	header = lines[header_index]
	positions = {
		'id': header.find('Id'),
		'available': header.find('Available'),
		'source': header.find('Source'),
	}

	upgrade_map: dict = {}
	for line in lines[header_index + 2 :]:
		if not line.strip() or positions['available'] == -1:
			continue
		try:
			name = line[0 : positions['id']].strip().lower()
			avail_end = positions['source'] if positions['source'] != -1 else len(line)
			latest = line[positions['available'] : avail_end].strip()
			if name and latest:
				upgrade_map[name] = latest
		except Exception:
			continue

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
