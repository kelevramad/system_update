"""Intelligent caching of scan results — JSON file with timestamp validation."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set

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

	def expires_at(self) -> Optional[datetime]:
		"""Return the absolute datetime when the cache expires, or ``None``."""
		if not self.cache_file.exists():
			return None
		try:
			with open(self.cache_file, 'r', encoding='utf-8') as f:
				data = json.load(f)
			cache_time = datetime.fromisoformat(data.get('timestamp', '').replace('Z', ''))
			return cache_time + self.duration
		except Exception:
			return None

	def time_remaining(self) -> Optional[str]:
		"""Return a compact ``Hh Mm`` (or ``Mm Ss``) string until expiry, or ``None``."""
		expiry = self.expires_at()
		if expiry is None:
			return None
		delta = expiry - datetime.now()
		secs = int(delta.total_seconds())
		if secs <= 0:
			return 'expired'
		h, rem = divmod(secs, 3600)
		m, s = divmod(rem, 60)
		if h:
			return f'{h}h {m}m'
		if m:
			return f'{m}m {s}s'
		return f'{s}s'

	def load(self) -> Optional[List[AppInfo]]:
		"""Load cached apps, rebuilding :class:`AppInfo` instances from camelCase JSON."""
		if not self.is_valid():
			return None
		try:
			with open(self.cache_file, 'r', encoding='utf-8') as f:
				data = json.load(f)
				apps: List[AppInfo] = []
				for item in data.get('apps', []):
					# Preserve the stored (lowercase) source verbatim so that
					# filter/merge comparisons stay case-consistent with fresh
					# scanner output. source_badge() lowercases for display
					# anyway, so no capitalization is required here.
					source_normalized = str(item.get('source', '') or '').lower()
					latest = item.get('latestVersion', '')
					if latest == '-':
						latest = ''
					app = AppInfo(
						name=item.get('name'),
						source=source_normalized,
						version=item.get('version'),
						latest_version=latest,
						app_id=item.get('appId'),
						update_status=UpdateStatus(item.get('status', 'unknown')),
						scan_time=datetime.fromisoformat(
							item.get('scanTime', datetime.now().isoformat()).replace('Z', '')
						),
						error_msg=item.get('errorMsg'),
						install_path=item.get('installPath'),
						security_findings=list(item.get('securityFindings') or []),
					)
					apps.append(app)
				return apps
		except Exception as e:
			logger.warning(f'Failed to load cache: {e}')
			return None

	def load_sources(self) -> List[str]:
		"""Return the ``sources`` array stored at the top of the cache, or []."""
		if not self.is_valid():
			return []
		try:
			with open(self.cache_file, 'r', encoding='utf-8') as f:
				data = json.load(f)
				return list(data.get('sources') or [])
		except Exception:
			return []

	def load_pip_context(self) -> Dict[str, object]:
		"""Return the pip interpreter recorded when pip was last scanned.

		Empty dict if the cache pre-dates this metadata or has no pip entries.
		Used by the orchestrator to detect when the user's environment has
		switched between venv and system Python — in which case the cached
		pip data is stale and pip should be rescanned.
		"""
		if not self.cache_file.exists():
			return {}
		try:
			with open(self.cache_file, 'r', encoding='utf-8') as f:
				data = json.load(f)
			ctx = data.get('pip_context') or {}
			return {
				'interpreter': str(ctx.get('interpreter', '')),
				'in_venv': bool(ctx.get('in_venv', False)),
			}
		except Exception:
			return {}

	def save(
		self,
		apps: List[AppInfo],
		pip_interpreter: str = '',
		pip_in_venv: bool = False,
	) -> None:
		"""Serialize ``apps`` to disk with timestamp + sources + pip context.

		``pip_interpreter`` / ``pip_in_venv`` are only meaningful when the scan
		included pip — they let a future load detect that the user has switched
		between venv and system Python.
		"""
		try:
			sources_seen: List[str] = []
			seen: Set[str] = set()
			has_pip = False
			for app in apps:
				key = app.source.lower()
				if key and key not in seen:
					seen.add(key)
					sources_seen.append(key)
				if key == 'pip':
					has_pip = True

			data = {
				'timestamp': datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
				'version': '1.0.3',
				'totalApps': len(apps),
				'sources': sorted(sources_seen),
				'apps': [app.to_dict() for app in apps],
			}
			if has_pip and pip_interpreter:
				data['pip_context'] = {
					'interpreter': pip_interpreter,
					'in_venv': pip_in_venv,
				}
			with open(self.cache_file, 'w', encoding='utf-8') as f:
				json.dump(data, f, indent=2)
		except Exception as e:
			logger.error(f'Failed to save cache: {e}')

	def clear(self) -> None:
		"""Delete the cache file if it exists."""
		if self.cache_file.exists():
			self.cache_file.unlink()
