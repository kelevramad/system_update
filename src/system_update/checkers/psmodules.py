"""Check PowerShell module updates through PowerShellGet."""

from __future__ import annotations

from typing import List

from system_update.models import AppInfo, UpdateStatus
from system_update.scanners._json import parse_json_items
from system_update.scanners._versions import clean_version
from system_update.utils import run_command


def _ps_single_quote(value: str) -> str:
	return "'" + value.replace("'", "''") + "'"


def _find_modules_script(apps: List[AppInfo]) -> str:
	names = ', '.join(_ps_single_quote(app.name) for app in apps)
	return f"""
$ProgressPreference = 'SilentlyContinue'
$names = @({names})
Find-Module -Name $names -ErrorAction SilentlyContinue |
    ForEach-Object {{
        [PSCustomObject]@{{
            Name = $_.Name
            Version = $_.Version.ToString()
        }}
    }} |
    ConvertTo-Json -Compress
"""


def check(apps: List[AppInfo]) -> int:
	"""Use one bounded ``Find-Module`` call to compare repository versions."""
	if not apps:
		return 0

	output = run_command(
		['powershell', '-NoProfile', '-Command', _find_modules_script(apps)],
		timeout=45,
		allow_failure=True,
	)
	latest_by_name = {
		str(item.get('Name', '')).casefold(): clean_version(item.get('Version'), default='')
		for item in parse_json_items(output)
		if item.get('Name') and item.get('Version')
	}

	updates = 0
	for app in apps:
		latest = latest_by_name.get(app.name.casefold(), '')
		if latest and latest != app.version:
			app.latest_version = latest
			app.update_status = UpdateStatus.UPDATE_AVAILABLE
			updates += 1
		else:
			app.update_status = UpdateStatus.UP_TO_DATE
	return updates
