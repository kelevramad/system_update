"""Scan Visual Studio Code extensions."""

from __future__ import annotations

from typing import List

from system_update.models import AppInfo
from system_update.utils import run_command


def scan() -> List[AppInfo]:
	"""Return VS Code extensions reported by ``code --list-extensions``."""
	output = run_command(
		['code', '--list-extensions', '--show-versions'],
		allow_failure=True,
	)
	apps: List[AppInfo] = []
	for line in (output or '').splitlines():
		line = line.strip()
		if not line or '@' not in line:
			continue
		extension_id, version = line.rsplit('@', 1)
		if not extension_id or not version:
			continue
		apps.append(
			AppInfo(
				name=extension_id,
				source='vsextensions',
				version=version,
				app_id=extension_id,
			)
		)
	return apps
