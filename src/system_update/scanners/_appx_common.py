"""Shared helper for AppX/MSIX scanners — both query ``Get-AppxPackage``."""

from __future__ import annotations

import platform
from typing import List

from system_update.models import AppInfo
from system_update.scanners._json import parse_json_items
from system_update.utils import run_command


def scan_appx_variant(signature_match: str, source: str) -> List[AppInfo]:
	"""Return AppxPackages whose ``SignatureKind`` comparison matches ``signature_match``.

	``signature_match`` is a literal PowerShell comparison fragment, e.g.
	``"-eq 'Store'"`` for Store-signed apps or ``"-ne 'Store'"`` for MSIX sideloads.
	"""
	if platform.system() != 'Windows':
		return []

	ps_script = f"""
Get-AppxPackage |
    Where-Object {{ $_.IsFramework -eq $false -and $_.SignatureKind {signature_match} }} |
    Select-Object Name, Version, PackageFullName, InstallLocation |
    ConvertTo-Json -Depth 1
"""

	apps: List[AppInfo] = []
	output = run_command(['powershell', '-NoProfile', '-Command', ps_script], allow_failure=True)
	if not output:
		return apps

	for item in parse_json_items(output):
		name = item.get('Name')
		version = item.get('Version')
		if not name or not version:
			continue
		apps.append(
			AppInfo(
				name=name,
				version=str(version),
				source=source,
				app_id=item.get('PackageFullName'),
				install_path=item.get('InstallLocation', ''),
			)
		)

	return apps
