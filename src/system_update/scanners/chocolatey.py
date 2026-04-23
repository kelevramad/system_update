"""Scan Chocolatey-managed packages via ``choco list --local-only``."""

from __future__ import annotations

from typing import List

from system_update.models import AppInfo
from system_update.utils import run_command


def scan() -> List[AppInfo]:
	"""Parse pipe-delimited ``choco list`` output."""
	apps: List[AppInfo] = []
	output = run_command(['choco', 'list', '--local-only', '--limit-output'], allow_failure=True)
	if not output:
		return apps

	for line in output.splitlines():
		parts = [p.strip() for p in line.split('|') if p.strip()]
		if len(parts) >= 2:
			apps.append(
				AppInfo(
					name=parts[0],
					source='Chocolatey',
					version=parts[1],
					app_id=parts[0],
				)
			)

	return apps
