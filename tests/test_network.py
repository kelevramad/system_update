import json
from unittest.mock import patch

from system_update import AppInfo, UpdateStatus
from system_update.network import configure_network, fetch_json
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

	with patch('system_update.network.urllib.request.urlopen', return_value=_Response({'ok': True})) as urlopen:
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

	with (
		patch('system_update.network.time.monotonic', side_effect=[10.0, 10.0, 10.25, 11.0]),
		patch('system_update.network.time.sleep') as sleep,
		patch('system_update.network.urllib.request.urlopen', return_value=_Response({'ok': True})),
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
