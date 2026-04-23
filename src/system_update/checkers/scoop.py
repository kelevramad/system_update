"""Check Scoop-managed package updates via ``scoop status``."""

from __future__ import annotations

from typing import List

from system_update.models import AppInfo, UpdateStatus
from system_update.utils import run_command


def check(apps: List[AppInfo]) -> int:
	"""Build a name→latest map from ``scoop status`` and apply it to ``apps``."""
	output = run_command(['scoop', 'status'], allow_failure=True)
	if not output:
		return 0

	update_map: dict = {}
	for line in output.splitlines():
		line = line.strip()
		if not line or line.startswith('---'):
			continue
		parts = line.split()
		if len(parts) < 2:
			continue
		name, version = parts[0], parts[1]
		if len(parts) >= 3:
			latest = parts[2]
			if latest.startswith('(') and latest.endswith(')'):
				latest = latest[1:-1]
			if version != latest:
				update_map[name] = latest
		else:
			update_map[name] = version

	updates = 0
	for app in apps:
		latest = update_map.get(app.name)
		if latest:
			app.latest_version = latest
			app.update_status = UpdateStatus.UPDATE_AVAILABLE
			updates += 1

	return updates
