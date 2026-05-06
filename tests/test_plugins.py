from argparse import Namespace
from unittest.mock import patch

from system_update import AppInfo, NotificationManager, SystemConfig, SystemUpdateApp, UpdateStatus
from system_update.checkers import check_all_updates
from system_update.plugins import load_plugins, updater_map


def _write_plugin(path):
	path.write_text(
		"""
PLUGIN_NAME = 'sample'


def scan_demo():
	return [
		{
			'name': 'demo-package',
			'version': '1.0.0',
		}
	]


def check_demo(apps):
	for app in apps:
		app.latest_version = '1.1.0'
		app.update_status = 'update_available'
	return len(apps)


def update_demo(app):
	app.version = app.latest_version or app.version
	app.latest_version = ''
	return True


def notify_demo(event, title, message, payload, config):
	config.settings.setdefault('plugin_events', []).append(
		[event, title, message, payload.get('updates', 0)]
	)


def register_plugin(registry, context):
	registry.register_scanner('demo', scan_demo, 'Demo scanner')
	registry.register_checker('demo', check_demo, 'Demo checker')
	registry.register_updater('demo', update_demo, 'Demo updater')
	registry.register_notifier('demo-notify', notify_demo, 'Demo notifier')
""",
		encoding='utf-8',
	)


def test_load_plugins_registers_scanners_and_notifiers(tmp_path):
	plugin_dir = tmp_path / '.system_update' / 'plugins'
	plugin_dir.mkdir(parents=True)
	_write_plugin(plugin_dir / 'sample_plugin.py')

	with patch('pathlib.Path.home', return_value=tmp_path):
		config = SystemConfig()
		registry = load_plugins(config)

	assert 'demo' in registry.scanners
	assert registry.scanners['demo'].description == 'Demo scanner'
	assert 'demo' in registry.checkers
	assert registry.checkers['demo'].description == 'Demo checker'
	assert 'demo' in registry.updaters
	assert registry.updaters['demo'].description == 'Demo updater'
	assert 'demo-notify' in registry.notifiers
	assert registry.errors == []


def test_app_scan_system_uses_plugin_source(tmp_path):
	plugin_dir = tmp_path / '.system_update' / 'plugins'
	plugin_dir.mkdir(parents=True)
	_write_plugin(plugin_dir / 'sample_plugin.py')

	with patch('pathlib.Path.home', return_value=tmp_path):
		app = SystemUpdateApp()
		app.settings['sources'] = {name: False for name in app.settings['sources']}
		apps = app.scan_system('demo')

	assert [a.name for a in apps] == ['demo-package']
	assert apps[0].source == 'demo'
	assert apps[0].latest_version == ''


def test_plugin_checker_runs_during_update_check(tmp_path):
	plugin_dir = tmp_path / '.system_update' / 'plugins'
	plugin_dir.mkdir(parents=True)
	_write_plugin(plugin_dir / 'sample_plugin.py')

	with patch('pathlib.Path.home', return_value=tmp_path):
		app = SystemUpdateApp()
		apps = app.scan_system('demo')
		count = check_all_updates(apps, extra_checkers={'demo': app.plugins.checkers['demo'].check})

	assert count == 1
	assert apps[0].latest_version == '1.1.0'
	assert apps[0].update_status == UpdateStatus.UPDATE_AVAILABLE


def test_plugin_updater_runs_during_update_execution(tmp_path):
	plugin_dir = tmp_path / '.system_update' / 'plugins'
	plugin_dir.mkdir(parents=True)
	_write_plugin(plugin_dir / 'sample_plugin.py')

	with patch('pathlib.Path.home', return_value=tmp_path):
		app = SystemUpdateApp()
		apps = app.scan_system('demo')
		check_all_updates(apps, extra_checkers={'demo': app.plugins.checkers['demo'].check})
		result = app.executor.execute_updates(apps, extra_updaters=updater_map(app.plugins))

	assert result is None
	assert apps[0].version == '1.1.0'
	assert apps[0].latest_version == ''
	assert apps[0].update_status == UpdateStatus.UP_TO_DATE


def test_partitioned_source_filter_accepts_plugin_source(tmp_path):
	plugin_dir = tmp_path / '.system_update' / 'plugins'
	plugin_dir.mkdir(parents=True)
	_write_plugin(plugin_dir / 'sample_plugin.py')

	args = Namespace(
		source='demo',
		exclude=None,
		update_source=None,
		update_all=False,
		dry_run=False,
		yes=True,
		no_cache=True,
		clear_cache=False,
		profile=None,
		profile_export=None,
		profile_import=None,
		save_config=False,
		format='json',
		theme=None,
		icons=False,
		interactive=False,
		show_all=True,
		notify=False,
		export=None,
		output=None,
		html_template=None,
		html_logo=None,
		html_title=None,
		html_company=None,
		package=None,
		version=None,
		history=False,
		history_package=None,
		history_trends=False,
		history_stale=0,
		report=None,
		report_output=None,
		dependency_graph=None,
		graph_output=None,
		import_files=None,
		merge_with_cache=False,
		list_plugins=False,
		cloud_sync=None,
		schedule=None,
		snapshot=None,
		rollback=None,
		remote=None,
		debug=False,
		log=False,
	)

	with patch('pathlib.Path.home', return_value=tmp_path):
		app = SystemUpdateApp()
		app.run(args)


def test_plugin_notifier_receives_update_event(tmp_path):
	plugin_dir = tmp_path / '.system_update' / 'plugins'
	plugin_dir.mkdir(parents=True)
	_write_plugin(plugin_dir / 'sample_plugin.py')

	with patch('pathlib.Path.home', return_value=tmp_path):
		config = SystemConfig()
		manager = NotificationManager(config)
		manager.plugin_registry = load_plugins(config)
		manager.notify_updates_available(2, vulnerable_count=1, force=True)

	assert config.settings['plugin_events'][0][:3] == [
		'updates_available',
		'🚀 System Update',
		'🔔 2 updates\n🔥 1 security vulnerabilities!',
	]
	assert config.settings['plugin_events'][0][3] == 2


def test_scanner_dict_source_defaults_to_plugin_source(tmp_path):
	plugin_dir = tmp_path / '.system_update' / 'plugins'
	plugin_dir.mkdir(parents=True)
	_write_plugin(plugin_dir / 'sample_plugin.py')

	with patch('pathlib.Path.home', return_value=tmp_path):
		app = SystemUpdateApp()
		apps = app.scan_system('demo')

	assert all(isinstance(app, AppInfo) for app in apps)
	assert apps[0].source == 'demo'
