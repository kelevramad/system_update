import json
from unittest.mock import patch

import pytest

from system_update import AppInfo, UpdateStatus
from system_update.network import UnsafeUrlError, configure_network, fetch_json
from system_update.security import osv


class _Response:
	def __init__(self, payload):
		self.payload = payload

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc, tb):
		return False

	def read(self):
		return json.dumps(self.payload).encode('utf-8')


def test_fetch_json_caches_responses(tmp_path):
	configure_network(
		{
			'cache_enabled': True,
			'cache_ttl_seconds': 60,
			'rate_limit_seconds': 0,
			'cache_file': tmp_path / 'api_cache.json',
		}
	)

	import system_update.network as net
	with patch.object(net._SAFE_OPENER, 'open', return_value=_Response({'ok': True})) as urlopen:
		assert fetch_json('https://example.test/api') == {'ok': True}
		assert fetch_json('https://example.test/api') == {'ok': True}

	urlopen.assert_called_once()


def test_fetch_json_rate_limits_per_host(tmp_path):
	configure_network(
		{
			'cache_enabled': False,
			'rate_limit_seconds': 1,
			'cache_file': tmp_path / 'api_cache.json',
		}
	)

	import system_update.network as net
	# Hardening 2.1.2 — _rate_limit now reads the clock once per call
	# (the slot is reserved inside the per-host lock; the sleep happens
	# afterwards). Two same-host calls 0.25s apart should sleep 0.75s.
	with (
		patch('system_update.network.time.monotonic', side_effect=[10.0, 10.25]),
		patch('system_update.network.time.sleep') as sleep,
		patch.object(net._SAFE_OPENER, 'open', return_value=_Response({'ok': True})),
	):
		fetch_json('https://example.test/one')
		fetch_json('https://example.test/two')

	sleep.assert_called_once_with(0.75)


def test_osv_uses_batch_query_api():
	apps = [
		AppInfo(name='demo', source='npm', version='1.0.0'),
		AppInfo(name='requests', source='pip', version='2.0.0'),
	]
	payload = {
		'results': [
			{'vulns': [{'id': 'OSV-1', 'summary': 'bad', 'database_specific': {'severity': 'HIGH'}}]},
			{'vulns': []},
		]
	}

	with patch('system_update.security.osv.fetch_json', return_value=payload) as fetch:
		vulns = osv.check(apps)

	fetch.assert_called_once()
	args, kwargs = fetch.call_args
	assert args[0] == 'https://api.osv.dev/v1/querybatch'
	assert kwargs['method'] == 'POST'
	assert len(kwargs['payload']['queries']) == 2
	assert vulns[0]['cve'] == 'OSV-1'
	assert apps[0].update_status == UpdateStatus.VULNERABLE


# ─── Hardening 1.3.1 — scheme allowlist ──────────────────────────────────


@pytest.mark.parametrize('bad_url', [
	'file:///etc/passwd',
	'file://C:/Windows/System32/drivers/etc/hosts',
	'ftp://example.test/x',
	'data:text/plain;base64,SGVsbG8=',
	'gopher://example.test/x',
	'',
])
def test_fetch_json_rejects_non_http_schemes(bad_url, tmp_path):
	configure_network({
		'cache_enabled': False,
		'rate_limit_seconds': 0,
		'cache_file': tmp_path / 'api_cache.json',
	})
	with pytest.raises(UnsafeUrlError):
		fetch_json(bad_url)


def test_fetch_json_rejects_url_without_host(tmp_path):
	configure_network({
		'cache_enabled': False,
		'rate_limit_seconds': 0,
		'cache_file': tmp_path / 'api_cache.json',
	})
	with pytest.raises(UnsafeUrlError):
		fetch_json('http:///no-host')


def test_safe_opener_does_not_register_file_handler():
	"""Defense-in-depth: even a 30x to file:// can't escape the allowlist."""
	import system_update.network as net
	from urllib.request import FileHandler, FTPHandler

	# ``handlers`` is a list at runtime even though it's not on the typed
	# OpenerDirector public surface. Use getattr to keep pyright happy.
	handlers = getattr(net._SAFE_OPENER, 'handlers', [])
	for handler in handlers:
		assert not isinstance(handler, FileHandler), 'FileHandler must not be installed'
		assert not isinstance(handler, FTPHandler), 'FTPHandler must not be installed'


# ─── Hardening 2.1.2 — cross-host parallelism ────────────────────────────


def test_rate_limit_does_not_serialize_across_hosts(tmp_path):
	"""Two calls to *different* hosts must not share a limiter — neither
	should sleep when the per-host slot is free.

	The previous implementation used one process-global lock + sleep,
	which queued every host through one wait. The fix gives each host
	its own limiter, so the second host call returns immediately even
	while the first host's wakeup is pending.
	"""
	configure_network({
		'cache_enabled': False,
		'rate_limit_seconds': 1.0,
		'cache_file': tmp_path / 'api_cache.json',
	})

	import system_update.network as net
	# Both calls happen at t=10. The first call to host A reserves t=11
	# but does not need to sleep (slot was free). The first call to host
	# B is independent — also no sleep. Net: zero sleeps.
	with (
		patch('system_update.network.time.monotonic', side_effect=[10.0, 10.0]),
		patch('system_update.network.time.sleep') as sleep,
		patch.object(net._SAFE_OPENER, 'open', return_value=_Response({'ok': True})),
	):
		fetch_json('https://host-a.test/x')
		fetch_json('https://host-b.test/y')

	sleep.assert_not_called()


def test_rate_limit_releases_lock_before_sleeping(tmp_path):
	"""Sleep must not be called while the per-host lock is held.

	Spy on ``time.sleep`` and assert the host lock is *not* held while it
	runs. The previous implementation held a global lock during sleep,
	which serialized everything.
	"""
	configure_network({
		'cache_enabled': False,
		'rate_limit_seconds': 1.0,
		'cache_file': tmp_path / 'api_cache.json',
	})

	import system_update.network as net
	limiter = net._get_host_limiter('lock-check.test')

	captured = {'lock_held_during_sleep': True}

	def fake_sleep(_):
		# acquire(blocking=False) returns False if the lock is held.
		acquired = limiter.lock.acquire(blocking=False)
		captured['lock_held_during_sleep'] = not acquired
		if acquired:
			limiter.lock.release()

	# Warm up the limiter so the next call needs to wait.
	limiter.next_allowed = 1_000_000.0  # far future

	with (
		patch('system_update.network.time.monotonic', return_value=999_999.5),
		patch('system_update.network.time.sleep', side_effect=fake_sleep),
		patch.object(net._SAFE_OPENER, 'open', return_value=_Response({'ok': True})),
	):
		fetch_json('https://lock-check.test/x')

	assert captured['lock_held_during_sleep'] is False, (
		'sleep ran while the per-host lock was held — the fix is incomplete'
	)
