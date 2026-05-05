from argparse import Namespace
from unittest.mock import patch

from system_update import AppInfo, NotificationManager, SystemConfig, SystemUpdateApp
from system_update.plugins import load_plugins


def _write_plugin(path):
	path.write_text(
		"""
PLUGIN_NAME = 'sample'


def scan_demo():
	return [
		{
			'name': 'demo-package',
			'version': '1.0.0',
			'latestVersion': '1.1.0',
			'status': 'update_available',
		}
	]


def notify_demo(event, title, message, payload, config):
	config.settings.setdefault('plugin_events', []).append(
		[event, title, message, payload.get('updates', 0)]
	)


def register_plugin(registry, context):
	registry.register_scanner('demo', scan_demo, 'Demo scanner')
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
	assert apps[0].latest_version == '1.1.0'


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
