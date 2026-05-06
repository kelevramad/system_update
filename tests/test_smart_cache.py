import gzip
import json
from datetime import datetime, timedelta
from unittest.mock import patch

from rich.console import Console

import system_update.app as app_module
from system_update import AppInfo, CacheManager, SystemUpdateApp, UpdateStatus


def _read_cache_json(path):
	raw = path.read_bytes()
	if raw.startswith(b'\x1f\x8b'):
		raw = gzip.decompress(raw)
	return json.loads(raw.decode('utf-8'))


def test_cache_records_per_source_metadata(tmp_path):
	cache = CacheManager(tmp_path / 'cache.json', duration_hours=2)
	apps = [
		AppInfo(name='Git', source='winget', version='1.0'),
		AppInfo(name='Requests', source='pip', version='2.0'),
	]

	cache.save(apps, refreshed_sources={'winget', 'pip'})

	metadata = cache.load_source_metadata()
	assert set(metadata) == {'winget', 'pip'}
	assert metadata['winget']['package_count'] == 1
	assert cache.stale_sources({'winget', 'pip'}) == set()


def test_cache_stale_sources_uses_source_metadata(tmp_path):
	cache_file = tmp_path / 'cache.json'
	cache = CacheManager(cache_file, duration_hours=2)
	cache.save([AppInfo(name='Git', source='winget', version='1.0')], refreshed_sources={'winget'})

	data = _read_cache_json(cache_file)
	old = (datetime.now() - timedelta(hours=3)).isoformat()
	data['source_metadata']['winget']['timestamp'] = old
	cache_file.write_bytes(gzip.compress(json.dumps(data).encode('utf-8')))

	assert cache.stale_sources({'winget', 'npm'}) == {'winget', 'npm'}


def test_delta_cache_tracks_added_updated_removed(tmp_path):
	cache = CacheManager(tmp_path / 'cache.json')
	cache.save(
		[
			AppInfo(name='Git', source='winget', version='1.0'),
			AppInfo(name='Old', source='npm', version='1.0'),
		]
	)
	cache.save(
		[
			AppInfo(
				name='Git',
				source='winget',
				version='1.1',
				update_status=UpdateStatus.UPDATE_AVAILABLE,
			),
			AppInfo(name='New', source='pip', version='2.0'),
		]
	)

	delta = cache.last_delta()
	assert delta['counts'] == {'added': 1, 'updated': 1, 'removed': 1}
	assert any('pip|new' in item for item in delta['added'])
	assert any('winget|git' in item for item in delta['updated'])
	assert any('npm|old' in item for item in delta['removed'])


def test_cache_is_compressed_and_loads_roundtrip(tmp_path):
	cache_file = tmp_path / 'cache.json'
	cache = CacheManager(cache_file)

	cache.save([AppInfo(name='Git', source='winget', version='1.0')])

	assert cache_file.read_bytes().startswith(b'\x1f\x8b')
	loaded = cache.load()
	assert loaded is not None
	assert loaded[0].name == 'Git'


def test_cache_prunes_old_source_data(tmp_path):
	cache_file = tmp_path / 'cache.json'
	cache = CacheManager(cache_file)
	cache.prune_after_days = 1
	cache.compression_enabled = False
	old = (datetime.now() - timedelta(days=3)).isoformat()
	payload = {
		'timestamp': old,
		'version': '1.1.0',
		'totalApps': 1,
		'sources': ['winget'],
		'source_metadata': {
			'winget': {'timestamp': old, 'package_count': 1, 'duration_hours': 2},
		},
		'apps': [AppInfo(name='Old', source='winget', version='1.0').to_dict()],
		'deltas': [{'timestamp': old, 'added': [], 'updated': [], 'removed': []}],
	}
	cache_file.write_text(json.dumps(payload), encoding='utf-8')

	cache.save(
		[
			AppInfo(name='Old', source='winget', version='1.0'),
			AppInfo(name='New', source='npm', version='1.0'),
		],
		refreshed_sources={'npm'},
	)

	data = _read_cache_json(cache_file)
	assert data['sources'] == ['npm']
	assert data['totalApps'] == 1
	assert data['apps'][0]['source'] == 'npm'
	assert len(data['deltas']) == 1
	assert data['deltas'][0]['counts']['added'] == 1


def test_cache_selective_storage_omits_unrequested_fields(tmp_path):
	cache_file = tmp_path / 'cache.json'
	cache = CacheManager(cache_file)
	cache.compression_enabled = False
	cache.storage_fields = ['name', 'source', 'version', 'status']

	cache.save(
		[
			AppInfo(
				name='Git',
				source='winget',
				version='1.0',
				app_id='Git.Git',
				install_path='C:/Git',
			)
		]
	)

	item = _read_cache_json(cache_file)['apps'][0]
	assert set(item) == {'name', 'source', 'version', 'status'}
	assert cache.load()[0].app_id is None


def test_selective_storage_does_not_create_false_delta_updates(tmp_path):
	cache = CacheManager(tmp_path / 'cache.json')
	cache.storage_fields = ['name', 'source', 'version', 'status']

	apps = [AppInfo(name='Git', source='winget', version='1.0')]
	cache.save(apps)
	cache.save(apps)

	assert cache.last_delta()['counts'] == {'added': 0, 'updated': 0, 'removed': 0}


def test_lru_hot_package_cache_evicts_oldest(tmp_path):
	cache = CacheManager(tmp_path / 'cache.json')
	cache.hot_cache_max_items = 2

	cache.save(
		[
			AppInfo(name='A', source='pip', version='1'),
			AppInfo(name='B', source='pip', version='1'),
			AppInfo(name='C', source='pip', version='1'),
		]
	)

	assert cache.hot_cache_size() == 2
	assert cache.get_hot_package('pip', 'A') is None
	assert cache.get_hot_package('pip', 'C').name == 'C'


def test_app_prefetch_starts_background_refresh(tmp_path):
	app = SystemUpdateApp()
	app.history_db.close()
	app.config.config_dir = tmp_path
	app.cache_mgr = CacheManager(tmp_path / 'cache.json')
	app.cache_mgr.save([AppInfo(name='Git', source='winget', version='1.0')])
	app.settings.setdefault('cache', {})['prefetch_enabled'] = True
	app.settings['cache']['prefetch_threshold_minutes'] = 180

	with patch('system_update.app.threading.Thread') as thread_cls:
		app._maybe_prefetch_cache(
			[AppInfo(name='Git', source='winget', version='1.0')],
			{'winget'},
		)

	thread_cls.assert_called_once()
	thread_cls.return_value.start.assert_called_once()


def test_partial_cache_message_shows_hits_and_missing(monkeypatch, tmp_path):
	app = SystemUpdateApp()
	app.history_db.close()
	app.config.config_dir = tmp_path
	app.cache_mgr = CacheManager(tmp_path / 'cache.json')
	app.scan_system = lambda source: [AppInfo(name='Lib', source=source, version='1.0')]
	app.checker.check_all_updates = lambda apps, max_workers=None: None
	app.security.check_all = lambda apps, advisory_file: []
	console = Console(record=True, width=160)
	monkeypatch.setattr(app_module, 'console', console)

	app._scan_missing_and_merge(
		[AppInfo(name='Git', source='winget', version='1.0')],
		{'npm'},
	)

	output = console.export_text()
	assert 'cached source(s): 📦 winget' in output
	assert 'Scanning missing source(s): 📚 npm' in output
	assert 'Cache updated' in output
	assert 'expires' in output
	assert 'in ' in output
