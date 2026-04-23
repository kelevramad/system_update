"""Scan Winget-managed packages via ``winget list``."""

from __future__ import annotations

import re
from typing import List

from system_update.models import AppInfo, UpdateStatus
from system_update.utils import run_command


def scan() -> List[AppInfo]:
	"""Parse ``winget list`` tabular output into :class:`AppInfo` records."""
	apps: List[AppInfo] = []
	output = run_command(['winget', 'list', '--accept-source-agreements'], allow_failure=True)
	if not output:
		return apps

	lines = output.splitlines()
	header_index = next(
		(
			i
			for i, line in enumerate(lines)
			if 'Name' in line and 'Id' in line and 'Version' in line
		),
		-1,
	)
	if header_index == -1:
		return apps

	header = lines[header_index]
	name_match = re.search(r'Name\s+Id', header)
	if name_match:
		header = header[name_match.start() :]

	positions = {
		'name': 0,
		'id': header.find('Id'),
		'version': header.find('Version'),
		'available': header.find('Available'),
		'source': header.find('Source'),
	}

	for line in lines[header_index + 2 :]:
		if not line.strip():
			continue
		try:
			name = line[0 : max(positions['id'], 0)].strip()
			app_id = (
				line[positions['id'] : positions['version']].strip()
				if positions['version'] > 0
				else ''
			)
			version_end = (
				positions['available']
				if positions['available'] != -1
				else positions['source']
				if positions['source'] != -1
				else len(line)
			)
			version = (
				line[positions['version'] : version_end].strip()
				if positions['version'] != -1
				else ''
			)
			if not name or not app_id or not version:
				continue
			apps.append(
				AppInfo(
					name=name,
					source='Winget',
					version=version,
					app_id=app_id,
					update_status=UpdateStatus.UNKNOWN,
				)
			)
		except Exception:
			continue

	return apps
