"""Intelligent caching of scan results — JSON file with timestamp validation."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

from system_update.models import AppInfo, UpdateStatus

logger = logging.getLogger(__name__)


class CacheManager:
	"""JSON-backed cache of scanned :class:`AppInfo` records.

	The cache file contains a ``timestamp`` and a list of serialized apps; it
	is considered valid for ``duration_hours`` after creation. Bypassed by
	passing ``--no-cache`` on the CLI.
	"""

	def __init__(self, cache_file: Path, duration_hours: int = 2) -> None:
		self.cache_file = cache_file
		self.duration = timedelta(hours=duration_hours)

	def is_valid(self) -> bool:
		"""Return True if the cache file exists and is younger than ``duration``."""
		if not self.cache_file.exists():
			return False
		try:
			with open(self.cache_file, 'r', encoding='utf-8') as f:
				data = json.load(f)
				cache_time = datetime.fromisoformat(data.get('timestamp', '').replace('Z', ''))
				return datetime.now() - cache_time < self.duration
		except Exception:
			return False

	def load(self) -> Optional[List[AppInfo]]:
		"""Load cached apps, rebuilding :class:`AppInfo` instances from camelCase JSON."""
		if not self.is_valid():
			return None
		try:
			with open(self.cache_file, 'r', encoding='utf-8') as f:
				data = json.load(f)
				apps: List[AppInfo] = []
				for item in data.get('apps', []):
					source_raw = item.get('source', '')
					source_normalized = (
						source_raw.upper()
						if source_raw in ('npm', 'pnpm', 'pip')
						else source_raw.capitalize()
					)
					latest = item.get('latestVersion', '')
					if latest == '-':
						latest = ''
					apps.append(
						AppInfo(
							name=item.get('name'),
							source=source_normalized,
							version=item.get('version'),
							latest_version=latest,
							app_id=item.get('appId'),
							update_status=UpdateStatus(item.get('status', 'unknown')),
							scan_time=datetime.fromisoformat(
								item.get('scanTime', datetime.now().isoformat()).replace('Z', '')
							),
						)
					)
				return apps
		except Exception as e:
			logger.warning(f'Failed to load cache: {e}')
			return None

	def save(self, apps: List[AppInfo]) -> None:
		"""Serialize ``apps`` to disk with a current-time ``timestamp`` header."""
		try:
			data = {
				'timestamp': datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
				'version': '1.0.1',
				'totalApps': len(apps),
				'apps': [app.to_dict() for app in apps],
			}
			with open(self.cache_file, 'w', encoding='utf-8') as f:
				json.dump(data, f, indent=2)
		except Exception as e:
			logger.error(f'Failed to save cache: {e}')

	def clear(self) -> None:
		"""Delete the cache file if it exists."""
		if self.cache_file.exists():
			self.cache_file.unlink()
