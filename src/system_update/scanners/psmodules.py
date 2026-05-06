"""Scan installed PowerShell modules."""

from __future__ import annotations

import platform
from typing import List

from system_update.models import AppInfo
from system_update.scanners._json import parse_json_items
from system_update.scanners._versions import clean_version
from system_update.utils import run_command

_PS_SCRIPT = r"""
$modules = @()
if (Get-Command Get-InstalledModule -ErrorAction SilentlyContinue) {
    $modules = Get-InstalledModule -ErrorAction SilentlyContinue |
        Select-Object Name, Version, InstalledLocation
}
if (-not $modules -or $modules.Count -eq 0) {
    $modules = Get-Module -ListAvailable |
        Group-Object Name |
        ForEach-Object { $_.Group | Sort-Object Version -Descending | Select-Object -First 1 } |
        Select-Object Name, Version, ModuleBase
}
$modules | ConvertTo-Json -Depth 2
"""


def scan() -> List[AppInfo]:
	"""Return installed PowerShell modules from PowerShellGet or module paths."""
	if platform.system() != 'Windows':
		return []

	output = run_command(['powershell', '-NoProfile', '-Command', _PS_SCRIPT], allow_failure=True)
	if not output:
		return []

	apps: List[AppInfo] = []
	for item in parse_json_items(output):
		name = item.get('Name')
		version = clean_version(item.get('Version'), default='')
		if not name or not version:
			continue
		apps.append(
			AppInfo(
				name=name,
				source='psmodules',
				version=version,
				app_id=name,
				install_path=item.get('InstalledLocation') or item.get('ModuleBase'),
			)
		)
	return apps
