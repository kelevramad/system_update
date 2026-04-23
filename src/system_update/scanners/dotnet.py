"""Scan .NET global tools via ``dotnet tool list -g``."""

from __future__ import annotations

from typing import List

from system_update.models import AppInfo
from system_update.utils import run_command


def scan() -> List[AppInfo]:
	"""Parse the header-then-rows format emitted by ``dotnet tool list``."""
	apps: List[AppInfo] = []
	output = run_command(['dotnet', 'tool', 'list', '-g'], allow_failure=True)
	if not output:
		return apps

	for line in output.splitlines()[1:]:
		line = line.strip()
		if not line or line.startswith('---') or line.startswith('Package'):
			continue
		parts = line.split()
		if len(parts) >= 2 and parts[0] and parts[1]:
			apps.append(
				AppInfo(
					name=parts[0],
					source='dotnet',
					version=parts[1],
					app_id=parts[0],
				)
			)

	return apps
