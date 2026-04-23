"""Scan Cargo-installed Rust binaries via ``cargo install --list``."""

from __future__ import annotations

import re
from typing import List

from system_update.models import AppInfo
from system_update.utils import run_command


def scan() -> List[AppInfo]:
	"""Parse ``crate v1.2.3:`` header lines from cargo's installed list."""
	apps: List[AppInfo] = []
	output = run_command(['cargo', 'install', '--list'], allow_failure=True)
	if not output:
		return apps

	for line in output.splitlines():
		match = re.match(r'^([^\s]+)\s+v([^\s:]+):', line)
		if match:
			apps.append(
				AppInfo(
					name=match.group(1),
					source='Rust',
					version=match.group(2),
					app_id=match.group(1),
				)
			)

	return apps
