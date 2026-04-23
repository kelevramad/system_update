"""Scan Yarn global packages via ``yarn global list``."""

from __future__ import annotations

import re
from typing import List

from system_update.models import AppInfo
from system_update.utils import run_command


def scan() -> List[AppInfo]:
	"""Parse ``info "name@version"`` lines from Yarn's global list."""
	apps: List[AppInfo] = []
	output = run_command(['yarn', 'global', 'list'], allow_failure=True)
	if not output:
		return apps

	for line in output.splitlines():
		match = re.match(r'^info "([^@]+)@([^"]+)"', line)
		if match:
			apps.append(
				AppInfo(
					name=match.group(1),
					source='Yarn',
					version=match.group(2),
					app_id=match.group(1),
				)
			)

	return apps
