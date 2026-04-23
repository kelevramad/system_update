"""Check .NET Global Tool updates via ``dotnet tool list -g --outdated``."""

from __future__ import annotations

from typing import List

from system_update.models import AppInfo, UpdateStatus
from system_update.utils import run_command


def check(apps: List[AppInfo]) -> int:
	"""Match outdated ``dotnet`` tools by lowercased name and mutate ``apps`` in place."""
	updates = 0
	output = run_command(['dotnet', 'tool', 'list', '-g', '--outdated'], allow_failure=True)
	if not output:
		return updates

	for line in output.splitlines()[1:]:
		line = line.strip()
		if not line or line.startswith('---') or line.startswith('Package'):
			continue
		parts = line.split()
		if len(parts) < 2:
			continue
		name, latest = parts[0], parts[1]
		for app in apps:
			if app.name.lower() == name.lower():
				app.latest_version = latest
				app.update_status = UpdateStatus.UPDATE_AVAILABLE
				updates += 1
				break

	return updates
