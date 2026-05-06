"""Check Microsoft Store/AppX updates through ``winget upgrade``."""

from __future__ import annotations

import re
from typing import List

from system_update.models import AppInfo, UpdateStatus
from system_update.utils import run_command


def _parse_winget_upgrade_rows(output: str) -> list[dict[str, str]]:
	"""Parse the fixed-width table emitted by ``winget upgrade``."""
	lines = output.splitlines()
	header_index = next((i for i, line in enumerate(lines) if 'Name' in line and 'Id' in line), -1)
	if header_index == -1:
		return []

	header = lines[header_index]
	name_match = re.search(r'Name\s+Id', header)
	if name_match:
		header = header[name_match.start() :]

	positions = {
		'id': header.find('Id'),
		'version': header.find('Version'),
		'available': header.find('Available'),
		'source': header.find('Source'),
	}
	if positions['id'] == -1 or positions['available'] == -1:
		return []

	rows: list[dict[str, str]] = []
	for line in lines[header_index + 1 :]:
		if not line.strip() or set(line.strip()) <= {'-'}:
			continue
		try:
			source_end = len(line)
			avail_end = positions['source'] if positions['source'] != -1 else source_end
			rows.append(
				{
					'name': line[: positions['id']].strip(),
					'id': line[positions['id'] : positions['version']].strip()
					if positions['version'] > 0
					else '',
					'version': line[positions['version'] : positions['available']].strip()
					if positions['version'] > 0
					else '',
					'available': line[positions['available'] : avail_end].strip(),
					'source': line[positions['source'] : source_end].strip()
					if positions['source'] != -1
					else '',
				}
			)
		except Exception:
			continue
	return rows


def _matches(app: AppInfo, row: dict[str, str]) -> bool:
	app_id = (app.app_id or '').lower()
	name = app.name.lower()
	row_id = row.get('id', '').lower()
	row_name = row.get('name', '').lower()
	return bool(
		(app_id and (app_id == row_id or app_id.startswith(row_id) or row_id in app_id))
		or (name and name == row_name)
	)


def check(apps: List[AppInfo]) -> int:
	"""Mark Store/AppX packages that appear in Winget's Store upgrade table."""
	output = run_command(['winget', 'upgrade', '--accept-source-agreements'], allow_failure=True)
	if not output:
		return 0

	rows = [
		row for row in _parse_winget_upgrade_rows(output)
		if row.get('source', '').lower() in {'msstore', 'store'}
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
