"""Scan Windows services and their executable file versions."""

from __future__ import annotations

import platform
from typing import List

from system_update.models import AppInfo
from system_update.scanners._json import parse_json_items
from system_update.scanners._versions import clean_version
from system_update.utils import run_command

_PS_SCRIPT = r"""
function Resolve-ServiceExecutablePath {
    param([string]$PathName)

    if ([string]::IsNullOrWhiteSpace($PathName)) {
        return ''
    }

    $expanded = [Environment]::ExpandEnvironmentVariables($PathName.Trim())
    if ($expanded -match '^"([^"]+)"') {
        return $Matches[1]
    }
    if ($expanded -match '^(.+?\.exe)(?:\s+.*)?$') {
        return $Matches[1].Trim()
    }

    return ($expanded -split '\s+')[0]
}

Get-CimInstance Win32_Service |
    Where-Object { $_.Name -and $_.PathName } |
    ForEach-Object {
        $exe = Resolve-ServiceExecutablePath $_.PathName
        $version = ''
        if ($exe -and (Test-Path -LiteralPath $exe)) {
            $version = (Get-Item -LiteralPath $exe).VersionInfo.FileVersion
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
	for item in parse_json_items(output):
		name = item.get('Name') or item.get('ServiceName')
		version = clean_version(item.get('Version'))
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
	return apps
