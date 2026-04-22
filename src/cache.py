import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from .models import AppInfo, UpdateStatus

logger = logging.getLogger(__name__)


class CacheManager:
	def __init__(self, cache_file: Path, duration_hours: int):
		self.cache_file = cache_file
		self.duration_hours = duration_hours
		self.duration = datetime.timedelta(hours=duration_hours)

	def is_valid(self) -> bool:
		"""Check if cache is still valid."""
		if not self.cache_file.exists():
			return False
		try:
			with open(self.cache_file, 'r', encoding='utf-8') as f:
				data = json.load(f)
				cache_time = datetime.fromisoformat(data.get('timestamp', '').replace('Z', ''))
				return datetime.now() - cache_time < self.duration
		except Exception:
			return False

	def load(self) -> tuple:
		"""Load cached applications with type safety."""
		if not self.is_valid():
			return None, None
		try:
			with open(self.cache_file, 'r', encoding='utf-8') as f:
				data = json.load(f)
				apps = []
				for item in data.get('apps', []):
					mapped_item = {
						'name': item.get('name'),
						'source': item.get('source', '').capitalize()
						if item.get('source') not in ['npm', 'pnpm', 'pip']
						else item.get('source').upper(),
						'version': item.get('version'),
						'latest_version': item.get('latestVersion', ''),
						'app_id': item.get('appId'),
						'update_status': UpdateStatus(item.get('status', 'unknown')),
						'scan_time': datetime.fromisoformat(
							item.get('scanTime', datetime.now().isoformat()).replace('Z', '')
						),
						'security_findings': item.get('securityFindings', []),
					}
					if mapped_item['latest_version'] == '-':
						mapped_item['latest_version'] = ''
					apps.append(AppInfo(**mapped_item))
				cached_sources = data.get('sources')
				return apps, cached_sources
		except Exception as e:
			logger.warning(f'Failed to load cache: {e}')
			return None, None

	def save(self, apps: List[AppInfo], sources: Optional[List[str]] = None):
		"""Save applications to cache with metadata."""
		try:
			data = {
				'timestamp': datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
				'version': '1.0.1',
				'totalApps': len(apps),
				'sources': sources,
				'apps': [app.to_dict() for app in apps],
			}
			with open(self.cache_file, 'w', encoding='utf-8') as f:
				json.dump(data, f, indent=2)
		except Exception as e:
			logger.error(f'Failed to save cache: {e}')

	def clear(self):
		"""Clear cache file."""
		if self.cache_file.exists():
			self.cache_file.unlink()
