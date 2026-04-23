"""Scan Windows Registry uninstall keys for installed applications."""

from __future__ import annotations

import json
import platform
from typing import List

from system_update.models import AppInfo
from system_update.utils import run_command

_PS_SCRIPT = """
$paths = @(
    'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
    'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
    'HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
)
Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -and $_.DisplayVersion -and !$_.SystemComponent } |
    Select-Object @{n='Name';e={$_.DisplayName}},
                 @{n='Version';e={$_.DisplayVersion}},
                 @{n='InstallLocation';e={$_.InstallLocation}} |
    ConvertTo-Json
"""


def scan() -> List[AppInfo]:
	"""Query HKLM/HKCU uninstall hives; returns ``[]`` on non-Windows platforms."""
	if platform.system() != 'Windows':
		return []

	apps: List[AppInfo] = []
	output = run_command(['powershell', '-NoProfile', '-Command', _PS_SCRIPT], allow_failure=True)
	if not output:
		return apps

	try:
		data = json.loads(output)
		data = [data] if isinstance(data, dict) else data
		for item in data:
			apps.append(
				AppInfo(
					name=item['Name'],
					source='Registry',
					version=item['Version'],
					install_path=item.get('InstallLocation'),
				)
			)
	except Exception:
		pass

	return apps
