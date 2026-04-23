"""Check Winget-managed apps against ``winget upgrade``."""

from __future__ import annotations

import re
from typing import List

from system_update.models import AppInfo, UpdateStatus
from system_update.utils import run_command


def check(apps: List[AppInfo]) -> int:
	"""Match ``apps`` against Winget's upgrade table by ``app_id``; mutate in place."""
	updates = 0
	output = run_command(['winget', 'upgrade', '--accept-source-agreements'], allow_failure=True)
	if not output:
		return updates

	lines = output.splitlines()
	header_index = next((i for i, line in enumerate(lines) if 'Name' in line and 'Id' in line), -1)
	if header_index == -1:
		return updates

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

	for line in lines[header_index + 2 :]:
		if not line.strip():
			continue
		try:
			app_id = (
				line[positions['id'] : positions['version']].strip()
				if positions['version'] > 0
				else ''
			)
			if positions['available'] == -1:
				continue
			avail_end = positions['source'] if positions['source'] != -1 else len(line)
			latest = line[positions['available'] : avail_end].strip()
			if not app_id or not latest:
				continue
			for app in apps:
				if app.app_id and app.app_id.lower() == app_id.lower():
					app.latest_version = latest
					app.update_status = UpdateStatus.UPDATE_AVAILABLE
					updates += 1
		except Exception:
			continue

	return updates
