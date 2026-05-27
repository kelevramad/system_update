import json
from argparse import Namespace
from datetime import datetime, timedelta
from unittest.mock import patch

from rich.console import Console

import system_update.app as app_module
from system_update import AppInfo, CacheManager, SystemUpdateApp, UpdateStatus


def _read_cache_json(path):
	return json.loads(path.read_text(encoding='utf-8'))


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


def test_cache_writes_readable_json_and_loads_roundtrip(tmp_path):
	cache_file = tmp_path / 'cache.json'
	cache = CacheManager(cache_file)

	cache.save([AppInfo(name='Git', source='winget', version='1.0')])

	raw = cache_file.read_bytes()
	assert not raw.startswith(b'\x1f\x8b')
	assert cache_file.read_text(encoding='utf-8').startswith('{\n')
	loaded = cache.load()
	assert loaded is not None
	assert loaded[0].name == 'Git'


def test_cache_prunes_old_source_data(tmp_path):
	cache_file = tmp_path / 'cache.json'
	cache = CacheManager(cache_file)
	cache.prune_after_days = 1
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

	loaded_data = _read_cache_json(cache_file)
	assert loaded_data is not None
	item = loaded_data['apps'][0]
	assert set(item) == {'name', 'source', 'version', 'status'}
	cache_apps = cache.load()
	assert cache_apps is not None
	assert cache_apps[0].app_id is None


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
	hot_c = cache.get_hot_package('pip', 'C')
	assert hot_c is not None
	assert hot_c.name == 'C'


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


def test_batch_update_result_refreshes_scoped_cache_without_dropping_other_sources(tmp_path):
	app = SystemUpdateApp()
	app.history_db.close()
	app.config.config_dir = tmp_path
	app.cache_mgr = CacheManager(tmp_path / 'cache.json')
	app._configure_cache_manager()

	app.cache_mgr.save(
		[
			AppInfo(
				name='Git',
				source='winget',
				version='1.0',
				latest_version='2.0',
				app_id='Git.Git',
				update_status=UpdateStatus.UPDATE_AVAILABLE,
			),
			AppInfo(name='Requests', source='pip', version='2.31.0'),
		],
		refreshed_sources={'winget', 'pip'},
	)

	apps = [
		AppInfo(
			name='Git',
			source='winget',
			version='1.0',
			latest_version='2.0',
			app_id='Git.Git',
			update_status=UpdateStatus.UPDATE_AVAILABLE,
		)
	]
	before = app._update_cache_state(apps)
	apps[0].version = '2.0'
	apps[0].latest_version = ''
	apps[0].update_status = UpdateStatus.UP_TO_DATE

	app._save_cache_after_updates(
		apps,
		Namespace(source='winget', dry_run=False),
		before,
	)

	loaded = app.cache_mgr.load()
	assert loaded is not None
	by_source = {item.source: item for item in loaded}
	assert by_source['winget'].version == '2.0'
	assert by_source['winget'].latest_version == ''
	assert by_source['winget'].update_status == UpdateStatus.UP_TO_DATE
	assert by_source['pip'].name == 'Requests'


def test_batch_update_result_refreshes_full_cache(tmp_path):
	app = SystemUpdateApp()
	app.history_db.close()
	app.config.config_dir = tmp_path
	app.cache_mgr = CacheManager(tmp_path / 'cache.json')
	app._configure_cache_manager()

	apps = [
		AppInfo(
			name='Git',
			source='winget',
			version='1.0',
			latest_version='2.0',
			app_id='Git.Git',
			update_status=UpdateStatus.UPDATE_AVAILABLE,
		),
		AppInfo(
			name='Requests',
			source='pip',
			version='2.31.0',
			latest_version='2.32.0',
			update_status=UpdateStatus.UPDATE_AVAILABLE,
		),
	]
	before = app._update_cache_state(apps)
	for item in apps:
		item.version = item.latest_version
		item.latest_version = ''
		item.update_status = UpdateStatus.UP_TO_DATE

	app._save_cache_after_updates(
		apps,
		Namespace(source=None, dry_run=False),
		before,
	)

	loaded = app.cache_mgr.load()
	assert loaded is not None
	assert {item.name: item.version for item in loaded} == {
		'Git': '2.0',
		'Requests': '2.32.0',
	}
	assert all(item.latest_version == '' for item in loaded)
	assert all(item.update_status == UpdateStatus.UP_TO_DATE for item in loaded)


def test_batch_update_result_dry_run_does_not_refresh_cache(tmp_path):
	app = SystemUpdateApp()
	app.history_db.close()
	app.config.config_dir = tmp_path
	app.cache_mgr = CacheManager(tmp_path / 'cache.json')
	app._configure_cache_manager()

	app.cache_mgr.save(
		[
			AppInfo(
				name='Git',
				source='winget',
				version='1.0',
				latest_version='2.0',
				update_status=UpdateStatus.UPDATE_AVAILABLE,
			)
		],
		refreshed_sources={'winget'},
	)
	apps = [
		AppInfo(
			name='Git',
			source='winget',
			version='1.0',
			latest_version='2.0',
			update_status=UpdateStatus.UPDATE_AVAILABLE,
		)
	]
	before = app._update_cache_state(apps)
	apps[0].version = '2.0'
	apps[0].latest_version = ''
	apps[0].update_status = UpdateStatus.UP_TO_DATE

	app._save_cache_after_updates(
		apps,
		Namespace(source=None, dry_run=True),
		before,
	)

	loaded = app.cache_mgr.load()
	assert loaded is not None
	assert loaded[0].version == '1.0'
	assert loaded[0].latest_version == '2.0'
	assert loaded[0].update_status == UpdateStatus.UPDATE_AVAILABLE


def test_partial_cache_message_shows_hits_and_missing(monkeypatch, tmp_path):
	app = SystemUpdateApp()
	app.history_db.close()
	app.config.config_dir = tmp_path
	app.cache_mgr = CacheManager(tmp_path / 'cache.json')
	app.scan_system = lambda source: [AppInfo(name='Lib', source=source or '', version='1.0')]  # type: ignore[method-assign]
	app.checker.check_all_updates = lambda apps, max_workers=None, extra_checkers=None: None  # type: ignore[method-assign]
	app.security.check_all = lambda apps, advisory_file, extra_checkers=None: []  # type: ignore[method-assign]
	console = Console(record=True, width=160)
	monkeypatch.setattr(app_module, 'console', console)

	app._scan_missing_and_merge(
		[AppInfo(name='Git', source='winget', version='1.0')],
		{'npm'},
	)

	output = console.export_text()
	assert 'cached source(s): 📦 winget' in output
	assert 'Scanning missing source(s): 📚 npm' in output
	assert '⏱  Scanning sources completed in ' in output
	assert '⏱  Checking for updates completed in ' in output
	assert '⏱  Checking security vulnerabilities completed in ' in output
	assert 'Scanning sources completed in ' in output
	assert 'Checking for updates completed in ' in output
	assert 'Checking security vulnerabilities completed in ' in output
	assert 'Cache updated' in output
	assert 'expires' in output
	assert 'in ' in output


# ─── Hardening 4.3 — memoized cache reads ─────────────────────────────────


def test_cache_memoizes_raw_reads_by_mtime(tmp_path):
	"""Sequential is_valid + is_source_valid + load must only re-parse once."""
	import system_update.cache as cache_module

	cache = CacheManager(tmp_path / 'cache.json')
	cache.save([AppInfo(name='Git', source='winget', version='1.0')])

	calls = {'n': 0}
	original_loads = cache_module.json.loads

	def counting_loads(*args, **kwargs):
		calls['n'] += 1
		return original_loads(*args, **kwargs)

	with patch.object(cache_module.json, 'loads', side_effect=counting_loads):
		assert cache.is_valid() is True
		assert cache.is_source_valid('winget') is True
		loaded = cache.load()

	assert loaded is not None
	assert calls['n'] == 1, 'is_valid + is_source_valid + load must share a single parse'


def test_cache_memoization_invalidates_on_external_mtime_change(tmp_path):
	"""External file modification (mtime bump) re-reads from disk."""
	import os
	import system_update.cache as cache_module

	cache_file = tmp_path / 'cache.json'
	cache = CacheManager(cache_file)
	cache.save([AppInfo(name='Git', source='winget', version='1.0')])
	cache.is_valid()  # prime the memo

	stat = cache_file.stat()
	os.utime(cache_file, (stat.st_atime, stat.st_mtime + 1))

	calls = {'n': 0}
	original_loads = cache_module.json.loads

	def counting_loads(*args, **kwargs):
		calls['n'] += 1
		return original_loads(*args, **kwargs)

	with patch.object(cache_module.json, 'loads', side_effect=counting_loads):
		cache.is_valid()

	assert calls['n'] == 1, 'mtime change must invalidate the memo'


# ─── Hardening 5.2 — cache.is_source_valid coverage ──────────────────────


def test_is_source_valid_returns_true_for_fresh_entry(tmp_path):
	cache = CacheManager(tmp_path / 'cache.json', duration_hours=2)
	cache.save(
		[AppInfo(name='Git', source='winget', version='1.0')],
		refreshed_sources={'winget'},
	)
	assert cache.is_source_valid('winget') is True


def test_is_source_valid_returns_false_for_expired_entry(tmp_path):
	cache_file = tmp_path / 'cache.json'
	cache = CacheManager(cache_file, duration_hours=2)
	cache.save(
		[AppInfo(name='Git', source='winget', version='1.0')],
		refreshed_sources={'winget'},
	)

	data = json.loads(cache_file.read_text(encoding='utf-8'))
	old = (datetime.now() - timedelta(hours=5)).isoformat()
	data['source_metadata']['winget']['timestamp'] = old
	cache_file.write_text(json.dumps(data), encoding='utf-8')

	# Force a fresh read past the mtime-memoized payload.
	cache._raw_cache = None
	cache._raw_cache_mtime = None
	assert cache.is_source_valid('winget') is False


def test_is_source_valid_falls_back_to_cache_level_timestamp_for_absent_source(tmp_path):
	"""When a source has no per-source metadata, the cache-level timestamp
	is consulted instead. ``stale_sources`` separately checks that the
	source is actually present in ``data['sources']``."""
	cache = CacheManager(tmp_path / 'cache.json', duration_hours=2)
	cache.save(
		[AppInfo(name='Git', source='winget', version='1.0')],
		refreshed_sources={'winget'},
	)
	assert cache.is_source_valid('npm') is True
	# But ``stale_sources`` still flags 'npm' because it isn't in the cache.
	assert 'npm' in cache.stale_sources({'npm'})


def test_is_source_valid_returns_false_when_cache_missing(tmp_path):
	cache = CacheManager(tmp_path / 'cache.json', duration_hours=2)
	# No save() — file does not exist.
	assert cache.is_source_valid('winget') is False


def test_cache_memoization_invalidates_after_write(tmp_path):
	"""Writing through the cache must drop the memo so readers see fresh data."""
	cache = CacheManager(tmp_path / 'cache.json')
	cache.save([AppInfo(name='Git', source='winget', version='1.0')])
	cache.load()  # prime

	cache.save([AppInfo(name='Other', source='npm', version='2.0')])
	loaded = cache.load()
	assert loaded is not None
	assert any(app.name == 'Other' for app in loaded)
