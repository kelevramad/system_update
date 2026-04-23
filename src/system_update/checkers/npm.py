"""Check NPM global package updates via ``npm outdated -g --json``."""

from __future__ import annotations

import json
from typing import List

from system_update.models import AppInfo, UpdateStatus
from system_update.utils import run_command


def check(apps: List[AppInfo]) -> int:
	"""Walk the NPM outdated JSON map and mutate matching ``apps``."""
	updates = 0
	output = run_command(['npm', 'outdated', '-g', '--json'], allow_failure=True)
	if not output:
		return updates

	try:
		data = json.loads(output)
		for name, details in data.items():
			latest = details.get('latest', '')
			if not latest:
				continue
			for app in apps:
				if app.name == name:
					app.latest_version = latest
					app.update_status = UpdateStatus.UPDATE_AVAILABLE
					updates += 1
	except Exception:
		pass

	return updates
