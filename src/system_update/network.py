"""Shared HTTP JSON client with rate limiting and response caching."""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_DEFAULT_CACHE_FILE = Path.home() / '.system_update' / 'api_cache.json'
_CACHE_VERSION = '1.0'
_LOCK = threading.RLock()
_LAST_REQUEST_BY_HOST: Dict[str, float] = {}
_RESPONSE_CACHE: Dict[str, Dict[str, Any]] = {}
_CACHE_LOADED = False

# Hardening 1.3.1 — only HTTP/HTTPS schemes are allowed. ``urllib`` will
# happily open ``file://`` and ``ftp://`` URLs by default, which means a
# user-supplied or config-supplied URL pointing at e.g. a local file
# would be silently fetched and treated as an API response. Restrict at
# two layers: validate the scheme up front *and* build a custom opener
# that has no FileHandler / FTPHandler installed, so even a 30x redirect
# to ``file://`` cannot escape the allowlist.
_ALLOWED_SCHEMES = frozenset({'http', 'https'})


def _build_safe_opener() -> 'urllib.request.OpenerDirector':
	"""Custom OpenerDirector that only knows how to handle HTTP/HTTPS."""
	opener = urllib.request.OpenerDirector()
	opener.add_handler(urllib.request.HTTPHandler())
	opener.add_handler(urllib.request.HTTPSHandler())
	opener.add_handler(urllib.request.HTTPDefaultErrorHandler())
	opener.add_handler(urllib.request.HTTPRedirectHandler())
	opener.add_handler(urllib.request.HTTPErrorProcessor())
	# Note: no FileHandler, no FTPHandler, no DataHandler.
	return opener


_SAFE_OPENER = _build_safe_opener()


class UnsafeUrlError(ValueError):
	"""Raised when a URL's scheme falls outside the allowlist."""


def _validate_url(url: str) -> None:
	"""Refuse non-HTTP(S) URLs before any network call.

	Hardening 1.3.1: ``urllib.request.urlopen`` accepts ``file://`` /
	``ftp://`` / ``data:`` schemes, which would let a hostile or
	misconfigured URL coerce the CLI into reading local files or talking
	to internal services. Reject anything that isn't ``http``/``https``
	with an empty netloc.
	"""
	parsed = urllib.parse.urlparse(url)
	scheme = (parsed.scheme or '').lower()
	if scheme not in _ALLOWED_SCHEMES:
		raise UnsafeUrlError(
			f'Refusing non-HTTP URL (scheme={scheme!r}): only http/https are allowed'
		)
	if not parsed.netloc:
		raise UnsafeUrlError(f'Refusing URL with no host: {url!r}')

_SETTINGS = {
	'enabled': True,
	'cache_enabled': True,
	'cache_ttl_seconds': 3600,
	'rate_limit_seconds': 0.2,
	'timeout_seconds': 10,
	'cache_file': _DEFAULT_CACHE_FILE,
}


def configure_network(settings: Optional[Dict[str, Any]] = None, config_dir: str | Path | None = None) -> None:
	"""Configure the shared network helper from application settings."""
	settings = settings or {}
	cache_file = settings.get('cache_file')
	if not cache_file and config_dir:
		cache_file = Path(config_dir) / 'api_cache.json'

	with _LOCK:
		_SETTINGS['enabled'] = bool(settings.get('enabled', True))
		_SETTINGS['cache_enabled'] = bool(settings.get('cache_enabled', True))
		_SETTINGS['cache_ttl_seconds'] = _positive_number(
			settings.get('cache_ttl_seconds'), 3600
		)
		_SETTINGS['rate_limit_seconds'] = _positive_number(
			settings.get('rate_limit_seconds'), 0.2, allow_zero=True
		)
		_SETTINGS['timeout_seconds'] = _positive_number(settings.get('timeout_seconds'), 10)
		_SETTINGS['cache_file'] = Path(cache_file or _DEFAULT_CACHE_FILE)
		_reset_cache_locked()


def fetch_json(
	url: str,
	*,
	method: str = 'GET',
	payload: Optional[Dict[str, Any]] = None,
	headers: Optional[Dict[str, str]] = None,
	timeout: Optional[float] = None,
	cache_ttl: Optional[float] = None,
	use_cache: bool = True,
) -> Any:
	"""Fetch JSON over HTTP with host rate limiting and persistent response caching."""
	method = method.upper()
	if not _SETTINGS.get('enabled', True):
		raise RuntimeError('Network access is disabled by configuration')
	_validate_url(url)
	body = None
	if payload is not None:
		body = json.dumps(payload, sort_keys=True).encode('utf-8')

	key = _cache_key(method, url, body)
	ttl = _positive_number(cache_ttl, _SETTINGS['cache_ttl_seconds'], allow_zero=True)
	if use_cache and _SETTINGS['cache_enabled']:
		cached = _cache_get(key, ttl)
		if cached is not None:
			return cached

	host = urllib.parse.urlparse(url).netloc.lower()
	_rate_limit(host)

	request_headers = {'User-Agent': 'SystemUpdateCLI', 'Accept': 'application/json'}
	if body is not None:
		request_headers['Content-Type'] = 'application/json'
	if headers:
		request_headers.update(headers)

	req = urllib.request.Request(url, data=body, method=method, headers=request_headers)
	request_timeout = _positive_number(timeout, _SETTINGS['timeout_seconds'])
	# Use the http-only opener so a 30x redirect to file:// is refused too.
	with _SAFE_OPENER.open(req, timeout=request_timeout) as response:
		data = json.loads(response.read().decode('utf-8'))

	if use_cache and _SETTINGS['cache_enabled']:
		_cache_set(key, data)
	return data


def clear_response_cache() -> None:
	"""Clear in-memory and on-disk API response cache."""
	with _LOCK:
		_reset_cache_locked()
		try:
			Path(_SETTINGS['cache_file']).unlink(missing_ok=True)
		except OSError:
			logger.debug('Failed to remove API cache', exc_info=True)


def _positive_number(value: Any, default: float, allow_zero: bool = False) -> float:
	try:
		num = float(value)
	except (TypeError, ValueError):
		return default
	if num < 0 or (num == 0 and not allow_zero):
		return default
	return num


def _cache_key(method: str, url: str, body: bytes | None) -> str:
	digest = hashlib.sha256()
	digest.update(method.encode('utf-8'))
	digest.update(b'\0')
	digest.update(url.encode('utf-8'))
	digest.update(b'\0')
	if body:
		digest.update(body)
	return digest.hexdigest()


def _rate_limit(host: str) -> None:
	delay = float(_SETTINGS.get('rate_limit_seconds') or 0)
	if not host or delay <= 0:
		return
	with _LOCK:
		now = time.monotonic()
		wait = delay - (now - _LAST_REQUEST_BY_HOST.get(host, 0.0))
		if wait > 0:
			time.sleep(wait)
		_LAST_REQUEST_BY_HOST[host] = time.monotonic()


def _cache_get(key: str, ttl: float) -> Any:
	_load_cache()
	now = time.time()
	with _LOCK:
		entry = _RESPONSE_CACHE.get(key)
		if not entry:
			return None
		if ttl <= 0 or now - float(entry.get('timestamp', 0)) <= ttl:
			return entry.get('data')
		_RESPONSE_CACHE.pop(key, None)
	return None


def _cache_set(key: str, data: Any) -> None:
	_load_cache()
	with _LOCK:
		_RESPONSE_CACHE[key] = {'timestamp': time.time(), 'data': data}
		_prune_cache_locked()
		_save_cache_locked()


def _load_cache() -> None:
	global _CACHE_LOADED
	with _LOCK:
		if _CACHE_LOADED:
			return
		_CACHE_LOADED = True
		cache_file = Path(_SETTINGS['cache_file'])
		try:
			raw = json.loads(cache_file.read_text(encoding='utf-8'))
			if raw.get('version') == _CACHE_VERSION and isinstance(raw.get('responses'), dict):
				_RESPONSE_CACHE.update(raw['responses'])
		except Exception:
			logger.debug('API response cache unavailable', exc_info=True)


def _save_cache_locked() -> None:
	cache_file = Path(_SETTINGS['cache_file'])
	try:
		cache_file.parent.mkdir(parents=True, exist_ok=True)
		cache_file.write_text(
			json.dumps(
				{
					'version': _CACHE_VERSION,
					'timestamp': time.time(),
					'responses': _RESPONSE_CACHE,
				},
				indent=2,
			),
			encoding='utf-8',
		)
	except OSError:
		logger.debug('Failed to write API response cache', exc_info=True)


def _prune_cache_locked() -> None:
	ttl = float(_SETTINGS.get('cache_ttl_seconds') or 0)
	if ttl <= 0:
		return
	cutoff = time.time() - ttl
	for key, entry in list(_RESPONSE_CACHE.items()):
		if float(entry.get('timestamp', 0)) < cutoff:
			_RESPONSE_CACHE.pop(key, None)


def _reset_cache_locked() -> None:
	global _CACHE_LOADED
	_CACHE_LOADED = False
	_RESPONSE_CACHE.clear()
	_LAST_REQUEST_BY_HOST.clear()
