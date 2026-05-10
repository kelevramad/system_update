"""Intelligent caching of scan results — JSON file with timestamp validation."""

from __future__ import annotations

import json
import logging
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set

from system_update.models import AppInfo, UpdateStatus
from system_update.utils import parse_iso_utc, secure_write

logger = logging.getLogger(__name__)

CACHE_VERSION = '1.2.0'
_DEFAULT_STORAGE_FIELDS = (
	'name',
	'source',
	'version',
	'latestVersion',
	'appId',
	'status',
	'scanTime',
	'errorMsg',
	'installPath',
	'securityFindings',
)


def _app_cache_key(app: AppInfo) -> str:
	return f'{(app.source or "").lower()}|{(app.name or "").lower()}|{app.app_id or ""}'


def _item_cache_key(item: Dict) -> str:
	return (
		f'{str(item.get("source", "") or "").lower()}|'
		f'{str(item.get("name", "") or "").lower()}|'
		f'{item.get("appId") or ""}'
	)


def _delta_value(item: Dict, key: str) -> str:
	value = item.get(key)
	if key == 'latestVersion' and value in (None, '', '-'):
		return ''
	return str(value or '')


class CacheManager:
	"""JSON-backed cache of scanned :class:`AppInfo` records.

	The cache file contains a ``timestamp`` and a list of serialized apps; it
	is considered valid for ``duration_hours`` after creation. Bypassed by
	passing ``--no-cache`` on the CLI.
	"""

	def __init__(self, cache_file: Path, duration_hours: int = 2) -> None:
		self.cache_file = cache_file
		self.duration = timedelta(hours=duration_hours)
		self._hot_packages: OrderedDict[str, AppInfo] = OrderedDict()
		self.hot_cache_max_items = 512
		self.delta_enabled = True
		self.prune_after_days = 14
		self.storage_fields: Sequence[str] = _DEFAULT_STORAGE_FIELDS
		self.omit_empty_fields = True

	def _read_raw(self, *, require_valid: bool = False) -> Optional[Dict]:
		"""Read raw cache JSON, optionally requiring at least one fresh source."""
		if not self.cache_file.exists():
			return None
		try:
			data = json.loads(self.cache_file.read_text(encoding='utf-8'))
			if require_valid and not self.is_valid(data):
				return None
			return data
		except Exception as e:
			logger.warning(f'Failed to read cache: {e}')
			return None

	def is_valid(self, data: Optional[Dict] = None) -> bool:
		"""Return True if the cache file exists and is younger than ``duration``."""
		try:
			data = data or self._read_raw()
			if not data:
				return False
			cache_time = parse_iso_utc(data.get('timestamp', ''))
			if datetime.now(timezone.utc) - cache_time < self.duration:
				return True
			return any(self.is_source_valid(source, data) for source in data.get('sources') or [])
		except Exception:
			return False

	def is_source_valid(self, source: str, data: Optional[Dict] = None) -> bool:
		"""Return True if ``source`` has fresh per-source cache metadata."""
		try:
			data = data or self._read_raw()
			if not data:
				return False
			source_key = source.lower()
			metadata = data.get('source_metadata') or {}
			raw = (metadata.get(source_key) or {}).get('timestamp') or data.get('timestamp', '')
			if not raw:
				return False
			cache_time = parse_iso_utc(str(raw))
			duration_hours = (metadata.get(source_key) or {}).get('duration_hours')
			duration = timedelta(hours=duration_hours) if duration_hours else self.duration
			return datetime.now(timezone.utc) - cache_time < duration
		except Exception:
			return False

	def stale_sources(self, sources: Iterable[str]) -> Set[str]:
		"""Return requested sources that are absent or stale in the cache."""
		data = self._read_raw()
		cached_sources = {str(s).lower() for s in (data or {}).get('sources') or []}
		return {
			source.lower()
			for source in sources
			if source.lower() not in cached_sources or not self.is_source_valid(source, data)
		}

	def expires_at(self) -> Optional[datetime]:
		"""Return the absolute datetime when the cache expires, or ``None``."""
		try:
			data = self._read_raw()
			if not data:
				return None
			cache_time = parse_iso_utc(data.get('timestamp', ''))
			return cache_time + self.duration
		except Exception:
			return None

	def time_remaining(self) -> Optional[str]:
		"""Return a compact ``Hh Mm`` (or ``Mm Ss``) string until expiry, or ``None``."""
		expiry = self.expires_at()
		if expiry is None:
			return None
		delta = expiry - datetime.now(timezone.utc)
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
		data = self._read_raw(require_valid=True)
		if data is None:
			return None
		try:
			apps: List[AppInfo] = []
			for item in data.get('apps', []):
				app = self._app_from_dict(item)
				apps.append(app)
				self._remember_hot_package(app)
			return apps
		except Exception as e:
			logger.warning(f'Failed to load cache: {e}')
			return None

	def load_fresh_sources(self, sources: Iterable[str]) -> List[AppInfo]:
		"""Load cached apps only for requested sources whose source metadata is fresh."""
		data = self._read_raw()
		if not data:
			return []
		requested = {source.lower() for source in sources}
		fresh = {source for source in requested if self.is_source_valid(source, data)}
		apps = []
		for item in data.get('apps', []):
			source = str(item.get('source', '') or '').lower()
			if source in fresh:
				app = self._app_from_dict(item)
				apps.append(app)
				self._remember_hot_package(app)
		return apps

	def load_sources(self) -> List[str]:
		"""Return the ``sources`` array stored at the top of the cache, or []."""
		data = self._read_raw(require_valid=True)
		return list((data or {}).get('sources') or [])

	def load_source_metadata(self) -> Dict[str, Dict]:
		"""Return per-source cache metadata."""
		data = self._read_raw()
		return dict((data or {}).get('source_metadata') or {})

	def last_delta(self) -> Dict:
		"""Return the most recent delta-cache record, if any."""
		data = self._read_raw()
		return dict((data or {}).get('lastDelta') or {})

	def get_hot_package(self, source: str, name: str, app_id: str = '') -> Optional[AppInfo]:
		"""Return a package from the bounded in-process LRU cache."""
		key = f'{source.lower()}|{name.lower()}|{app_id}'
		app = self._hot_packages.get(key)
		if app is not None:
			self._hot_packages.move_to_end(key)
		return app

	def hot_cache_size(self) -> int:
		"""Return the number of packages currently held in the LRU cache."""
		return len(self._hot_packages)

	def load_pip_context(self) -> Dict[str, object]:
		"""Return the pip interpreter recorded when pip was last scanned.

		Empty dict if the cache pre-dates this metadata or has no pip entries.
		Used by the orchestrator to detect when the user's environment has
		switched between venv and system Python — in which case the cached
		pip data is stale and pip should be rescanned.
		"""
		try:
			data = self._read_raw() or {}
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
		refreshed_sources: Optional[Set[str]] = None,
	) -> None:
		"""Serialize ``apps`` to disk with timestamp + sources + pip context.

		``pip_interpreter`` / ``pip_in_venv`` are only meaningful when the scan
		included pip — they let a future load detect that the user has switched
		between venv and system Python.
		"""
		try:
			previous = self._read_raw() or {}
			now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
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

			refreshed = {s.lower() for s in (refreshed_sources or seen)}
			source_metadata = dict(previous.get('source_metadata') or {})
			for source in refreshed:
				source_metadata[source] = {
					'timestamp': now,
					'package_count': sum(1 for app in apps if app.source.lower() == source),
					'duration_hours': self.duration.total_seconds() / 3600,
				}
			for source in set(source_metadata) - seen:
				source_metadata.pop(source, None)

			data = {
				'timestamp': now,
				'version': CACHE_VERSION,
				'totalApps': len(apps),
				'sources': sorted(sources_seen),
				'source_metadata': source_metadata,
				'apps': [self._app_to_cache_dict(app) for app in apps],
			}
			if self.delta_enabled:
				delta = self._build_delta(previous.get('apps', []), apps)
				deltas = list(previous.get('deltas') or [])
				deltas.append(delta)
				data['lastDelta'] = delta
				data['deltas'] = self._prune_deltas(deltas)
			if has_pip and pip_interpreter:
				data['pip_context'] = {
					'interpreter': pip_interpreter,
					'in_venv': pip_in_venv,
				}
			data = self._prune_data(data, now)
			self._write_raw(data)
			for app in apps:
				self._remember_hot_package(app)
		except Exception as e:
			logger.error(f'Failed to save cache: {e}')

	def clear(self) -> None:
		"""Delete the cache file if it exists."""
		if self.cache_file.exists():
			self.cache_file.unlink()
		self._hot_packages.clear()

	def _write_raw(self, data: Dict) -> None:
		# Hardening 1.4.1 — atomic write with 0o600 / icacls so package
		# inventory (which can include hostnames + paths) is not readable
		# by other local users.
		secure_write(
			self.cache_file,
			json.dumps(data, indent=2, ensure_ascii=False) + '\n',
		)

	def _app_to_cache_dict(self, app: AppInfo) -> Dict:
		full = app.to_dict()
		allowed = set(self.storage_fields or _DEFAULT_STORAGE_FIELDS)
		allowed.update({'name', 'source', 'version'})
		item = {key: value for key, value in full.items() if key in allowed}
		if not self.omit_empty_fields:
			return item
		return {
			key: value
			for key, value in item.items()
			if value not in (None, '', [], {}) and not (key == 'latestVersion' and value == '-')
		}

	@staticmethod
	def _app_from_dict(item: Dict) -> AppInfo:
		source_normalized = str(item.get('source', '') or '').lower()
		latest = item.get('latestVersion', '')
		if latest == '-':
			latest = ''
		return AppInfo(
			name=str(item.get('name') or ''),
			source=source_normalized,
			version=str(item.get('version') or ''),
			latest_version=latest,
			app_id=item.get('appId'),
			update_status=UpdateStatus(item.get('status', 'unknown')),
			# AppInfo.scan_time is naive-UTC by convention (matches the
			# naive default from datetime.now()). parse_iso_utc gives an
			# aware datetime; strip the tzinfo at the boundary so the
			# downstream API surface is unchanged.
			scan_time=parse_iso_utc(
				item.get('scanTime') or datetime.now(timezone.utc).isoformat()
			).replace(tzinfo=None),
			error_msg=item.get('errorMsg'),
			install_path=item.get('installPath'),
			security_findings=list(item.get('securityFindings') or []),
		)

	def _remember_hot_package(self, app: AppInfo) -> None:
		key = _app_cache_key(app)
		self._hot_packages[key] = app
		self._hot_packages.move_to_end(key)
		while len(self._hot_packages) > self.hot_cache_max_items:
			self._hot_packages.popitem(last=False)

	@staticmethod
	def _build_delta(previous_apps: List[Dict], current_apps: List[AppInfo]) -> Dict:
		previous = {_item_cache_key(item): item for item in previous_apps}
		current = {_app_cache_key(app): app.to_dict() for app in current_apps}
		added = sorted(set(current) - set(previous))
		removed = sorted(set(previous) - set(current))
		updated = sorted(
			key
			for key in set(current) & set(previous)
			if _delta_value(current[key], 'version') != _delta_value(previous[key], 'version')
			or _delta_value(current[key], 'latestVersion') != _delta_value(
				previous[key], 'latestVersion'
			)
			or _delta_value(current[key], 'status') != _delta_value(previous[key], 'status')
		)
		return {
			'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
			'added': added,
			'updated': updated,
			'removed': removed,
			'counts': {
				'added': len(added),
				'updated': len(updated),
				'removed': len(removed),
			},
		}

	def _prune_deltas(self, deltas: List[Dict]) -> List[Dict]:
		kept = []
		cutoff = datetime.now(timezone.utc) - timedelta(days=self.prune_after_days)
		for delta in deltas:
			try:
				raw = str(delta.get('timestamp', ''))
				if raw and parse_iso_utc(raw) < cutoff:
					continue
			except Exception:
				continue
			kept.append(delta)
		return kept[-20:]

	def _prune_data(self, data: Dict, now: str) -> Dict:
		if self.prune_after_days <= 0:
			data['totalApps'] = len(data.get('apps') or [])
			return data
		cutoff = datetime.now(timezone.utc) - timedelta(days=self.prune_after_days)
		metadata = dict(data.get('source_metadata') or {})
		pruned_sources = set()
		for source, meta in list(metadata.items()):
			try:
				raw = str((meta or {}).get('timestamp') or now)
				if parse_iso_utc(raw) < cutoff:
					pruned_sources.add(str(source).lower())
					metadata.pop(source, None)
			except Exception:
				pruned_sources.add(str(source).lower())
				metadata.pop(source, None)

		if pruned_sources:
			data['apps'] = [
				app for app in data.get('apps', [])
				if str(app.get('source', '') or '').lower() not in pruned_sources
			]
			data['sources'] = [
				source for source in data.get('sources', [])
				if str(source).lower() not in pruned_sources
			]
		data['source_metadata'] = metadata
		data['totalApps'] = len(data.get('apps') or [])
		return data
