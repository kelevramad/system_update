"""Scan Windows services and their executable file versions."""

from __future__ import annotations

import json
import platform
from typing import List

from system_update.models import AppInfo
from system_update.utils import run_command

_PS_SCRIPT = r"""
Get-CimInstance Win32_Service |
    Where-Object { $_.Name -and $_.PathName } |
    ForEach-Object {
        $rawPath = $_.PathName
        $exe = $rawPath
        if ($rawPath -match '^"([^"]+)"') {
            $exe = $Matches[1]
        } else {
            $exe = ($rawPath -split '\s+')[0]
        }
        $version = ''
        if ($exe -and (Test-Path $exe)) {
            $version = (Get-Item $exe).VersionInfo.FileVersion
        }
        [PSCustomObject]@{
            Name = $_.DisplayName
            ServiceName = $_.Name
            Version = $version
            State = $_.State
            StartMode = $_.StartMode
            Path = $exe
        }
    } |
    ConvertTo-Json -Depth 2
"""


def scan() -> List[AppInfo]:
	"""Return Windows services with executable versions when available."""
	if platform.system() != 'Windows':
		return []

	output = run_command(['powershell', '-NoProfile', '-Command', _PS_SCRIPT], allow_failure=True)
	if not output:
		return []

	apps: List[AppInfo] = []
	try:
		data = json.loads(output)
		items = [data] if isinstance(data, dict) else data
		for item in items:
			name = item.get('Name') or item.get('ServiceName')
			version = item.get('Version') or 'unknown'
			if not name:
				continue
			apps.append(
				AppInfo(
					name=name,
					source='services',
					version=version,
					app_id=item.get('ServiceName'),
					install_path=item.get('Path'),
				)
			)
	except (TypeError, json.JSONDecodeError):
		return []
	return apps
