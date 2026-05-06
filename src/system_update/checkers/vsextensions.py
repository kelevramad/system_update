"""Check VS Code extension updates through the Visual Studio Marketplace."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import List

from system_update.models import AppInfo, UpdateStatus

_MARKETPLACE_URL = 'https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery'
_API_VERSION = '7.2-preview.1'


def _latest_marketplace_version(extension_id: str) -> str:
	"""Return the latest Marketplace version for ``publisher.name`` extension ids."""
	if '.' not in extension_id:
		return ''
	publisher, name = extension_id.split('.', 1)
	payload = {
		'filters': [
			{
				'criteria': [
					{'filterType': 7, 'value': name},
					{'filterType': 8, 'value': publisher},
				],
				'pageNumber': 1,
				'pageSize': 1,
				'sortBy': 0,
				'sortOrder': 0,
			}
		],
		'assetTypes': [],
		'flags': 0x1,
	}
	data = json.dumps(payload).encode('utf-8')
	request = urllib.request.Request(
		f'{_MARKETPLACE_URL}?api-version={_API_VERSION}',
		data=data,
		headers={
			'Accept': 'application/json;api-version=3.0-preview.1',
			'Content-Type': 'application/json',
			'User-Agent': 'system-update-cli',
		},
		method='POST',
	)
	try:
		with urllib.request.urlopen(request, timeout=10) as response:
			body = json.loads(response.read().decode('utf-8'))
	except (OSError, urllib.error.URLError, json.JSONDecodeError):
		return ''

	results = body.get('results') or []
	extensions = results[0].get('extensions') if results else []
	versions = extensions[0].get('versions') if extensions else []
	return versions[0].get('version', '') if versions else ''


def check(apps: List[AppInfo]) -> int:
	"""Compare installed VS Code extensions with Marketplace latest versions."""
	updates = 0
	for app in apps:
		latest = _latest_marketplace_version(app.app_id or app.name)
		if latest and latest != app.version:
			app.latest_version = latest
			app.update_status = UpdateStatus.UPDATE_AVAILABLE
			updates += 1
		else:
			app.update_status = UpdateStatus.UP_TO_DATE
	return updates
