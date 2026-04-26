"""Data sharing — import, merge, and cloud-sync of scan data.

Implements enhancement section 5.4:
    5.4.1 — Import Scan Data (load AppInfo lists from JSON / CSV)
    5.4.2 — Merge Scans      (combine multiple scans, dedup by source|name|version)
    5.4.3 — Cloud Sync       (push/pull cache to a file path or HTTP endpoint)

Cloud sync intentionally avoids vendor SDKs. Two backends are supported:

* ``file`` — write/read the cache JSON to any path. Pointing this at a
  cloud-synced folder (OneDrive / Dropbox / Google Drive / iCloud / a
  network share) is the easiest cross-device sync setup.
* ``http`` — ``PUT`` to upload, ``GET`` to download. An optional
  ``Authorization`` header can be configured.

Config block (``~/.system_update/config.json``)::

    {
      "cloud_sync": {
        "enabled": false,
        "type": "file" | "http",
        "target": "/path/to/folder/or/https://host/cache",
        "auth_header": "Bearer ...",   # http only, optional
        "filename": "system_update_cache.json"  # file only, optional
      }
    }
"""

from __future__ import annotations

import csv
import json
import logging
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from system_update.models import AppInfo, UpdateStatus

logger = logging.getLogger(__name__)


# ─── 5.4.1 — Import scan data ──────────────────────────────────────────────


def _appinfo_from_dict(data: Dict) -> AppInfo:
	"""Reconstruct an :class:`AppInfo` from cache/JSON-export keys (camelCase)."""
	status_raw = data.get('status') or data.get('update_status') or 'unknown'
	try:
		status = UpdateStatus(status_raw)
	except ValueError:
		status = UpdateStatus.UNKNOWN

	scan_time_raw = data.get('scanTime') or data.get('scan_time')
	if scan_time_raw:
		try:
			scan_time = datetime.fromisoformat(str(scan_time_raw).rstrip('Z'))
		except Exception:
			scan_time = datetime.now()
	else:
		scan_time = datetime.now()

	latest = data.get('latestVersion') or data.get('latest_version') or ''
	if latest == '-':
		latest = ''

	return AppInfo(
		name=str(data.get('name', '')),
		source=str(data.get('source', '')),
		version=str(data.get('version', '') or ''),
		latest_version=str(latest or ''),
		app_id=data.get('appId') or data.get('app_id'),
		update_status=status,
		scan_time=scan_time,
		error_msg=data.get('errorMsg') or data.get('error_msg'),
		install_path=data.get('installPath') or data.get('install_path'),
		security_findings=list(
			data.get('securityFindings') or data.get('security_findings') or []
		),
	)


def import_from_json(path: Path) -> List[AppInfo]:
	"""Load ``AppInfo`` list from a JSON file.

	Accepts either:
	* a list of package dicts (export format), or
	* an object containing a ``packages`` / ``apps`` / ``items`` key.
	"""
	data = json.loads(path.read_text(encoding='utf-8'))
	if isinstance(data, dict):
		for key in ('packages', 'apps', 'items', 'data'):
			if isinstance(data.get(key), list):
				data = data[key]
				break
	if not isinstance(data, list):
		raise ValueError(
			f'JSON file {path} does not contain a package list'
		)
	apps: List[AppInfo] = []
	for item in data:
		if not isinstance(item, dict):
			continue
		try:
			apps.append(_appinfo_from_dict(item))
		except Exception as e:
			logger.warning(f'Skipping malformed entry in {path}: {e}')
	return apps


def import_from_csv(path: Path) -> List[AppInfo]:
	"""Load ``AppInfo`` list from a CSV file (header row required)."""
	apps: List[AppInfo] = []
	with path.open('r', encoding='utf-8', newline='') as f:
		reader = csv.DictReader(f)
		for row in reader:
			# Normalize keys — accept the column names produced by export_csv
			# as well as snake_case variants.
			normalized = {
				'name': row.get('Name') or row.get('name'),
				'source': row.get('Source') or row.get('source'),
				'version': row.get('Version') or row.get('version'),
				'latestVersion': row.get('Latest') or row.get('latest_version'),
				'appId': row.get('AppId') or row.get('app_id'),
				'status': row.get('Status') or row.get('status'),
				'installPath': row.get('InstallPath') or row.get('install_path'),
			}
			if not normalized['name']:
				continue
			try:
				apps.append(_appinfo_from_dict(normalized))
			except Exception as e:
				logger.warning(f'Skipping malformed CSV row in {path}: {e}')
	return apps


def import_apps(path: str) -> List[AppInfo]:
	"""Auto-detect file type and dispatch to the right importer.

	Selection rules (first match wins): suffix ``.json`` → JSON, ``.csv`` →
	CSV, anything else attempts JSON first then CSV.
	"""
	p = Path(path).expanduser()
	if not p.is_file():
		raise FileNotFoundError(f'Import file not found: {path}')
	suffix = p.suffix.lower()
	if suffix == '.json':
		return import_from_json(p)
	if suffix == '.csv':
		return import_from_csv(p)
	# Best effort: try JSON, fall back to CSV.
	try:
		return import_from_json(p)
	except Exception:
		return import_from_csv(p)


# ─── 5.4.2 — Merge scans ───────────────────────────────────────────────────


def merge_apps(
	*sources: Iterable[AppInfo],
	prefer: str = 'latest',
) -> List[AppInfo]:
	"""Combine multiple ``AppInfo`` iterables into a single deduplicated list.

	Dedup key: ``source|name|version`` (case-insensitive) — same key the cache
	uses internally.

	``prefer``:
	    * ``'latest'`` — pick the entry with the most recent ``scan_time``
	    * ``'first'``  — keep the first occurrence (preserves caller order)
	    * ``'security'`` — prefer the entry that has security findings
	"""
	merged: Dict[str, AppInfo] = {}
	for batch in sources:
		for app in batch:
			key = f'{(app.source or "").lower()}|{(app.name or "").lower()}|{app.version or ""}'
			existing = merged.get(key)
			if existing is None:
				merged[key] = app
				continue
			if prefer == 'first':
				continue
			if prefer == 'security':
				if app.security_findings and not existing.security_findings:
					merged[key] = app
				continue
			# 'latest' (default)
			if app.scan_time and (
				not existing.scan_time or app.scan_time > existing.scan_time
			):
				merged[key] = app
	return sorted(merged.values(), key=lambda a: f'{a.source}{a.name}')


# ─── 5.4.3 — Cloud sync ────────────────────────────────────────────────────


_DEFAULT_CLOUD_FILENAME = 'system_update_cache.json'


def _cloud_config(settings: Dict) -> Dict:
	cfg = dict((settings or {}).get('cloud_sync', {}) or {})
	if not cfg:
		raise ValueError(
			'Cloud sync not configured. Add a cloud_sync block to '
			'~/.system_update/config.json (type=file|http, target=...).'
		)
	if not cfg.get('target'):
		raise ValueError('cloud_sync.target is required')
	cfg.setdefault('type', 'file')
	cfg.setdefault('filename', _DEFAULT_CLOUD_FILENAME)
	return cfg


def _http_request(
	url: str, method: str, body: Optional[bytes], auth: Optional[str]
) -> bytes:
	headers = {'User-Agent': 'SystemUpdateCLI', 'Content-Type': 'application/json'}
	if auth:
		headers['Authorization'] = auth
	req = urllib.request.Request(url, data=body, method=method, headers=headers)
	with urllib.request.urlopen(req, timeout=30) as response:
		return response.read()


def cloud_push(local_cache: Path, settings: Dict) -> Tuple[str, int]:
	"""Upload ``local_cache`` to the configured cloud target. Returns (target, bytes)."""
	cfg = _cloud_config(settings)
	if not local_cache.is_file():
		raise FileNotFoundError(f'Cache file missing: {local_cache}')
	payload = local_cache.read_bytes()

	if cfg['type'] == 'file':
		dest = Path(cfg['target']).expanduser()
		dest.mkdir(parents=True, exist_ok=True)
		out = dest / cfg['filename']
		out.write_bytes(payload)
		return (str(out), len(payload))

	if cfg['type'] == 'http':
		_http_request(cfg['target'], 'PUT', payload, cfg.get('auth_header'))
		return (cfg['target'], len(payload))

	raise ValueError(f'Unknown cloud_sync.type: {cfg["type"]!r}')


def cloud_pull(local_cache: Path, settings: Dict) -> Tuple[str, int]:
	"""Download remote cache and overwrite ``local_cache``. Returns (source, bytes)."""
	cfg = _cloud_config(settings)
	local_cache.parent.mkdir(parents=True, exist_ok=True)

	if cfg['type'] == 'file':
		src = Path(cfg['target']).expanduser() / cfg['filename']
		if not src.is_file():
			raise FileNotFoundError(f'Remote cache not found: {src}')
		payload = src.read_bytes()
		local_cache.write_bytes(payload)
		return (str(src), len(payload))

	if cfg['type'] == 'http':
		payload = _http_request(cfg['target'], 'GET', None, cfg.get('auth_header'))
		local_cache.write_bytes(payload)
		return (cfg['target'], len(payload))

	raise ValueError(f'Unknown cloud_sync.type: {cfg["type"]!r}')


def cloud_status(local_cache: Path, settings: Dict) -> Dict:
	"""Return a small dict describing the configured target + local cache state."""
	cfg = _cloud_config(settings)
	stat: Dict = {
		'type': cfg['type'],
		'target': cfg['target'],
		'enabled': bool(cfg.get('enabled', False)),
	}
	if local_cache.is_file():
		s = local_cache.stat()
		stat['local_cache_size'] = s.st_size
		stat['local_cache_mtime'] = datetime.fromtimestamp(s.st_mtime).isoformat()
	else:
		stat['local_cache_size'] = 0
		stat['local_cache_mtime'] = None
	if cfg['type'] == 'file':
		remote = Path(cfg['target']).expanduser() / cfg['filename']
		if remote.is_file():
			s = remote.stat()
			stat['remote_size'] = s.st_size
			stat['remote_mtime'] = datetime.fromtimestamp(s.st_mtime).isoformat()
		else:
			stat['remote_size'] = 0
			stat['remote_mtime'] = None
	return stat


__all__ = [
	'import_apps',
	'import_from_json',
	'import_from_csv',
	'merge_apps',
	'cloud_push',
	'cloud_pull',
	'cloud_status',
]
