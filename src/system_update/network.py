"""Shared HTTP JSON client with rate limiting and response caching."""

from __future__ import annotations

import hashlib
import json
import logging
import random
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

from system_update.utils import data_dir

logger = logging.getLogger(__name__)

_DEFAULT_CACHE_FILE = data_dir() / 'api_cache.json'
_CACHE_VERSION = '1.0'
_LOCK = threading.RLock()
_RESPONSE_CACHE: Dict[str, Dict[str, Any]] = {}

# Hardening 2.1.2 — per-host rate limiter.
#
# The previous implementation held a process-global RLock for the entire
# duration of `time.sleep(wait)`, which serialized every HTTP call across
# every host through one queue and defeated the worker pool. Each host
# now gets its own small lock plus a "next allowed" timestamp; we
# *reserve* the slot inside the per-host lock and then sleep outside it,
# so threads targeting different hosts run in parallel.
_HOST_LIMITERS_LOCK = threading.Lock()
_HOST_LIMITERS: Dict[str, '_HostLimiter'] = {}


class _HostLimiter:
	"""Per-host rate-limit state. Lock serializes only the timestamp swap."""

	__slots__ = ('lock', 'next_allowed')

	def __init__(self) -> None:
		self.lock = threading.Lock()
		self.next_allowed: float = 0.0


def _get_host_limiter(host: str) -> _HostLimiter:
	"""Return the per-host limiter, creating it on first use."""
	# Fast path — already registered.
	limiter = _HOST_LIMITERS.get(host)
	if limiter is not None:
		return limiter
	with _HOST_LIMITERS_LOCK:
		# Double-checked pattern: another thread may have raced us.
		limiter = _HOST_LIMITERS.get(host)
		if limiter is None:
			limiter = _HostLimiter()
			_HOST_LIMITERS[host] = limiter
		return limiter
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
	# Hardening 4.6 — retry policy for transient HTTP errors.
	'retry_max_attempts': 3,
	'retry_base_seconds': 0.5,
	'retry_max_seconds': 30.0,
}


_RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})


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
		_SETTINGS['retry_max_attempts'] = int(
			_positive_number(settings.get('retry_max_attempts'), 3, allow_zero=True)
		)
		_SETTINGS['retry_base_seconds'] = _positive_number(
			settings.get('retry_base_seconds'), 0.5, allow_zero=True
		)
		_SETTINGS['retry_max_seconds'] = _positive_number(
			settings.get('retry_max_seconds'), 30.0
		)
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
	data = _open_with_retry(req, request_timeout)

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
	"""Per-host rate limiter — sleep happens outside the lock.

	1. Acquire the per-host lock briefly to compute ``wait`` and reserve
	   the next slot (``next_allowed = now + wait``).
	2. Release the lock.
	3. Sleep for ``wait`` seconds.

	Threads hitting *different* hosts contend on neither lock and run
	in parallel. Threads hitting the *same* host still serialize on the
	per-host slot reservation, but the slow ``time.sleep`` happens
	without holding the lock so the next caller can already update the
	reservation while the current one is waiting.
	"""
	delay = float(_SETTINGS.get('rate_limit_seconds') or 0)
	if not host or delay <= 0:
		return
	limiter = _get_host_limiter(host)
	with limiter.lock:
		now = time.monotonic()
		wait = limiter.next_allowed - now
		if wait < 0:
			wait = 0.0
		# Reserve the slot before releasing the lock so concurrent callers
		# stack up rather than dogpiling the same wakeup time.
		limiter.next_allowed = now + max(wait, 0.0) + delay
	if wait > 0:
		time.sleep(wait)


def _open_with_retry(req: 'urllib.request.Request', timeout: float) -> Any:
	"""Open ``req`` with retry/backoff on transient HTTP errors.

	Hardening 4.6 — retries on 429, 5xx, and connection errors with
	exponential backoff + jitter, honoring ``Retry-After`` headers when
	present. 4xx errors other than 429 fail immediately. The total
	attempt count (initial + retries) is bounded by
	``network.retry_max_attempts``.
	"""
	max_attempts = max(1, int(_SETTINGS.get('retry_max_attempts') or 1))
	base = float(_SETTINGS.get('retry_base_seconds') or 0.5)
	cap = float(_SETTINGS.get('retry_max_seconds') or 30.0)

	last_exc: Optional[BaseException] = None
	for attempt in range(max_attempts):
		try:
			# Use the http-only opener so a 30x redirect to file:// is refused too.
			with _SAFE_OPENER.open(req, timeout=timeout) as response:
				return json.loads(response.read().decode('utf-8'))
		except urllib.error.HTTPError as exc:
			last_exc = exc
			if exc.code not in _RETRY_STATUSES or attempt + 1 >= max_attempts:
				raise
			delay = _retry_after_seconds(exc) or _backoff(attempt, base, cap)
			logger.info(
				'HTTP %s on %s — retry %d/%d after %.2fs',
				exc.code, req.full_url, attempt + 1, max_attempts - 1, delay,
			)
			time.sleep(delay)
		except (urllib.error.URLError, TimeoutError, OSError) as exc:
			last_exc = exc
			if attempt + 1 >= max_attempts:
				raise
			delay = _backoff(attempt, base, cap)
			logger.info(
				'Network error on %s (%s) — retry %d/%d after %.2fs',
				req.full_url, exc, attempt + 1, max_attempts - 1, delay,
			)
			time.sleep(delay)
	# Defensive — loop always returns or raises above.
	if last_exc is not None:
		raise last_exc
	raise RuntimeError('retry loop exited without result')


def _retry_after_seconds(exc: 'urllib.error.HTTPError') -> Optional[float]:
	"""Parse a ``Retry-After`` header into seconds, if sane.

	Supports the integer-seconds form. HTTP-date form is ignored — the
	exponential backoff is a safe fallback.
	"""
	try:
		header = exc.headers.get('Retry-After') if exc.headers else None
	except Exception:
		header = None
	if not header:
		return None
	try:
		secs = float(str(header).strip())
		if secs < 0:
			return None
		cap = float(_SETTINGS.get('retry_max_seconds') or 30.0)
		return min(secs, cap)
	except (TypeError, ValueError):
		return None


def _backoff(attempt: int, base: float, cap: float) -> float:
	"""Exponential backoff with jitter, capped at ``cap`` seconds."""
	delay = base * (2 ** attempt)
	delay = min(delay, cap)
	jitter = random.uniform(0, base)
	return min(delay + jitter, cap)


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
	from system_update.utils import secure_write

	cache_file = Path(_SETTINGS['cache_file'])
	try:
		secure_write(
			cache_file,
			json.dumps(
				{
					'version': _CACHE_VERSION,
					'timestamp': time.time(),
					'responses': _RESPONSE_CACHE,
				},
				indent=2,
			),
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
	# Drop per-host limiters so the next configure_network() call starts
	# from a clean slate (used in tests via configure_network()).
	with _HOST_LIMITERS_LOCK:
		_HOST_LIMITERS.clear()
