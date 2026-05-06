import json
from datetime import datetime, timedelta
from unittest.mock import patch

from rich.console import Console

import system_update.app as app_module
from system_update import AppInfo, CacheManager, SystemUpdateApp, UpdateStatus


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

	data = json.loads(cache_file.read_text(encoding='utf-8'))
	old = (datetime.now() - timedelta(hours=3)).isoformat()
	data['source_metadata']['winget']['timestamp'] = old
	cache_file.write_text(json.dumps(data), encoding='utf-8')

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
