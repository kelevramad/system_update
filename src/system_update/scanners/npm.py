"""Scan globally installed NPM packages via ``npm list -g --json``."""

from __future__ import annotations

import json
from typing import List

from system_update.models import AppInfo
from system_update.utils import run_command


def scan() -> List[AppInfo]:
	"""Return a list of top-level NPM global packages."""
	apps: List[AppInfo] = []
	output = run_command(
		['npm', 'list', '-g', '--depth=0', '--json', '--silent'], allow_failure=True
	)
	if not output:
		return apps

	try:
		data = json.loads(output)
		for name, details in data.get('dependencies', {}).items():
			apps.append(
				AppInfo(
					name=name,
					source='NPM',
					version=details.get('version', 'N/A'),
					app_id=name,
				)
			)
	except json.JSONDecodeError:
		pass

	return apps
