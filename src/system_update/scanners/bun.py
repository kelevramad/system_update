"""Scan Bun global packages via ``bun pm ls -g``."""

from __future__ import annotations

import re
from typing import List

from system_update.models import AppInfo
from system_update.utils import run_command

_BUN_ROW_RE = re.compile(r'^\s*([^\s@]+)@([^\s]+)')


def scan() -> List[AppInfo]:
	"""Parse ``name@version`` lines from Bun's global package listing."""
	apps: List[AppInfo] = []
	output = run_command(['bun', 'pm', 'ls', '-g'], allow_failure=True)
	if not output:
		return apps

	for line in output.splitlines():
		match = _BUN_ROW_RE.match(line)
		if match:
			apps.append(
				AppInfo(
					name=match.group(1),
					source='Bun',
					version=match.group(2),
					app_id=match.group(1),
				)
			)

	return apps
