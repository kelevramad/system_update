from argparse import Namespace
from unittest.mock import patch

import pytest

from system_update import AppInfo, NotificationManager, SystemConfig, SystemUpdateApp, UpdateStatus
from system_update.checkers import check_all_updates
from system_update.plugins import load_plugins, updater_map


@pytest.fixture(autouse=True)
def _opt_in_plugins(monkeypatch):
	"""Hardening 1.2.1 default-disables plugin loading.

	Existing tests assume plugins load — wrap ``SystemConfig.__init__`` so
	every freshly-constructed config has ``plugins.enabled=true`` for the
	duration of the test, without touching the real defaults dict.
	"""
	from system_update.config import SystemConfig as _SC

	original_init = _SC.__init__

	def _patched_init(self, *args, **kwargs):
		original_init(self, *args, **kwargs)
		plugins = self.settings.setdefault('plugins', {})
		plugins['enabled'] = True

	monkeypatch.setattr(_SC, '__init__', _patched_init)
	# Ensure the kill switch is off between tests.
	import system_update.plugins as _pmod

	monkeypatch.setattr(_pmod, '_PLUGIN_KILL_SWITCH', False)
	yield


def _write_plugin(path):
	"""Write a plugin that follows the standardized contract.

	Mirrors the user-facing ``demo_plugin.py`` template:
	* returns typed ``AppInfo`` objects with explicit ``source``,
	* uses the ``UpdateStatus`` enum (not raw strings),
	* filters on ``app.source`` in checker/updater,
	* records notifier events via ``context.data_dir`` so the test can
	  assert on them without poking ``config.settings`` internals.
	"""
	path.write_text(
		"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, List, Optional

from system_update.models import AppInfo, UpdateStatus
from system_update.plugins import PluginContext, PluginRegistry

PLUGIN_NAME = 'sample'
SOURCE = 'demo'


def scan_demo() -> Iterable[AppInfo]:
	return [
		AppInfo(
			name='demo-package',
			source=SOURCE,
			version='1.0.0',
			update_status=UpdateStatus.UNKNOWN,
		),
	]


def check_demo(apps: List[AppInfo]) -> int:
	count = 0
	for app in apps:
		if app.source != SOURCE:
			continue
		app.latest_version = '1.1.0'
		app.update_status = UpdateStatus.UPDATE_AVAILABLE
		count += 1
	return count


def update_demo(app: AppInfo) -> bool:
	if app.source != SOURCE:
		return False
	app.version = app.latest_version or app.version
	app.latest_version = ''
	app.update_status = UpdateStatus.UP_TO_DATE
	return True


_LOG_PATH: Optional[Path] = None


def notify_demo(event, title, message, payload, config) -> None:
	# Record the event in two places so tests can pick whichever shape
	# is more convenient: a tuple list on config.settings (for
	# in-process inspection) and a one-line append to the log file
	# under context.data_dir (for IO-shaped assertions).
	config.settings.setdefault('plugin_events', []).append(
		[event, title, message, payload.get('updates', 0)]
	)
	if _LOG_PATH is not None:
		try:
			_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
			with _LOG_PATH.open('a', encoding='utf-8') as fh:
				fh.write(f'{event}|{title}|{message!r}|{payload!r}\\n')
		except OSError:
			pass


def register_plugin(registry: PluginRegistry, context: PluginContext) -> None:
	global _LOG_PATH
	_LOG_PATH = context.data_dir / 'demo_plugin_events.log'
	registry.register_scanner(SOURCE, scan_demo, 'Demo scanner')
	registry.register_checker(SOURCE, check_demo, 'Demo checker')
	registry.register_updater(SOURCE, update_demo, 'Demo updater')
	registry.register_notifier('demo-log', notify_demo, 'Demo notifier')
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
	assert 'demo-log' in registry.notifiers
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


# ─── Hardening 1.2.1 — security controls ─────────────────────────────────


def test_plugins_default_disabled_does_not_load(tmp_path, monkeypatch):
	"""Without ``plugins.enabled=true`` the loader is a no-op."""
	plugin_dir = tmp_path / '.system_update' / 'plugins'
	plugin_dir.mkdir(parents=True)
	_write_plugin(plugin_dir / 'sample_plugin.py')

	# Defeat the autouse opt-in fixture to assert the real default.
	from system_update.config import SystemConfig as _SC
	from system_update import config as _cfg_mod
	monkeypatch.setattr(_SC, '__init__', _cfg_mod.SystemConfig.__init__)

	with patch('pathlib.Path.home', return_value=tmp_path):
		config = SystemConfig()
		# Force the real default: no override.
		config.settings.get('plugins', {}).pop('enabled', None)
		registry = load_plugins(config)

	assert registry.scanners == {}
	assert registry.checkers == {}
	assert registry.notifiers == {}


def test_no_plugins_kill_switch_short_circuits_loader(tmp_path):
	"""``disable_plugin_loading()`` must skip even an explicitly enabled config."""
	plugin_dir = tmp_path / '.system_update' / 'plugins'
	plugin_dir.mkdir(parents=True)
	_write_plugin(plugin_dir / 'sample_plugin.py')

	from system_update import plugins as _pmod

	with patch('pathlib.Path.home', return_value=tmp_path):
		config = SystemConfig()
		_pmod.disable_plugin_loading()
		try:
			registry = load_plugins(config)
		finally:
			_pmod._PLUGIN_KILL_SWITCH = False

	assert registry.scanners == {}


def test_world_writable_plugin_dir_is_refused(tmp_path, monkeypatch):
	"""POSIX dirs writable by group or others must not be loaded."""
	import platform
	import stat

	if platform.system() == 'Windows':
		pytest.skip('POSIX-only permission check')

	plugin_dir = tmp_path / '.system_update' / 'plugins'
	plugin_dir.mkdir(parents=True)
	_write_plugin(plugin_dir / 'sample_plugin.py')
	# Make the directory world-writable.
	plugin_dir.chmod(plugin_dir.stat().st_mode | stat.S_IWOTH)

	with patch('pathlib.Path.home', return_value=tmp_path):
		config = SystemConfig()
		registry = load_plugins(config)

	assert registry.scanners == {}
	assert any(
		'unsafe permissions' in err.error.lower() for err in registry.errors
	), registry.errors


def test_sha256_allowlist_skips_unlisted_plugin(tmp_path):
	"""Plugins not in ``allowed.sha256`` must not be loaded."""
	plugin_dir = tmp_path / '.system_update' / 'plugins'
	plugin_dir.mkdir(parents=True)
	_write_plugin(plugin_dir / 'sample_plugin.py')
	# Allowlist with a wrong digest → plugin rejected.
	(plugin_dir / 'allowed.sha256').write_text(
		'00' * 32 + '  sample_plugin.py\n', encoding='utf-8',
	)

	with patch('pathlib.Path.home', return_value=tmp_path):
		config = SystemConfig()
		registry = load_plugins(config)

	assert registry.scanners == {}
	assert any('sha256' in err.error.lower() for err in registry.errors)


def test_sha256_allowlist_loads_matching_plugin(tmp_path):
	"""Plugins with a correct digest in ``allowed.sha256`` load normally."""
	import hashlib

	plugin_dir = tmp_path / '.system_update' / 'plugins'
	plugin_dir.mkdir(parents=True)
	plugin_path = plugin_dir / 'sample_plugin.py'
	_write_plugin(plugin_path)
	digest = hashlib.sha256(plugin_path.read_bytes()).hexdigest()
	(plugin_dir / 'allowed.sha256').write_text(
		f'{digest}  sample_plugin.py\n', encoding='utf-8',
	)

	with patch('pathlib.Path.home', return_value=tmp_path):
		config = SystemConfig()
		registry = load_plugins(config)

	assert 'demo' in registry.scanners


def test_require_hash_allowlist_refuses_when_missing(tmp_path):
	"""``require_hash_allowlist=true`` and no manifest → no load, clear error."""
	plugin_dir = tmp_path / '.system_update' / 'plugins'
	plugin_dir.mkdir(parents=True)
	_write_plugin(plugin_dir / 'sample_plugin.py')

	with patch('pathlib.Path.home', return_value=tmp_path):
		config = SystemConfig()
		config.settings['plugins']['require_hash_allowlist'] = True
		registry = load_plugins(config)

	assert registry.scanners == {}
	assert any('require_hash_allowlist' in err.error for err in registry.errors)


# ─── Standardized plugin contract ────────────────────────────────────────


def test_checker_filters_by_source(tmp_path):
	"""Standardized plugin must not mutate apps owned by other sources."""
	plugin_dir = tmp_path / '.system_update' / 'plugins'
	plugin_dir.mkdir(parents=True)
	_write_plugin(plugin_dir / 'sample_plugin.py')

	with patch('pathlib.Path.home', return_value=tmp_path):
		config = SystemConfig()
		registry = load_plugins(config)

	foreign = AppInfo(name='other', source='winget', version='1.0')
	mine = AppInfo(name='demo-package', source='demo', version='1.0.0',
		update_status=UpdateStatus.UNKNOWN)
	check = registry.checkers['demo'].check
	count = check([foreign, mine])

	assert count == 1
	# Foreign app untouched.
	assert foreign.latest_version == ''
	assert foreign.update_status == UpdateStatus.UNKNOWN
	# Mine updated.
	assert mine.latest_version == '1.1.0'
	assert mine.update_status == UpdateStatus.UPDATE_AVAILABLE


def test_updater_marks_up_to_date_after_install(tmp_path):
	"""Standardized updater clears latest_version and sets UP_TO_DATE."""
	plugin_dir = tmp_path / '.system_update' / 'plugins'
	plugin_dir.mkdir(parents=True)
	_write_plugin(plugin_dir / 'sample_plugin.py')

	with patch('pathlib.Path.home', return_value=tmp_path):
		config = SystemConfig()
		registry = load_plugins(config)

	app = AppInfo(name='demo-package', source='demo', version='1.0.0',
		latest_version='1.1.0', update_status=UpdateStatus.UPDATE_AVAILABLE)
	ok = registry.updaters['demo'].update(app)

	assert ok is True
	assert app.version == '1.1.0'
	assert app.latest_version == ''
	assert app.update_status == UpdateStatus.UP_TO_DATE


def test_updater_refuses_foreign_source(tmp_path):
	"""Defensive: updater must return False for apps it doesn't own."""
	plugin_dir = tmp_path / '.system_update' / 'plugins'
	plugin_dir.mkdir(parents=True)
	_write_plugin(plugin_dir / 'sample_plugin.py')

	with patch('pathlib.Path.home', return_value=tmp_path):
		config = SystemConfig()
		registry = load_plugins(config)

	foreign = AppInfo(name='other', source='winget', version='1.0',
		latest_version='2.0', update_status=UpdateStatus.UPDATE_AVAILABLE)
	assert registry.updaters['demo'].update(foreign) is False
	# Foreign app untouched.
	assert foreign.version == '1.0'
	assert foreign.latest_version == '2.0'


def test_notifier_writes_event_log_under_data_dir(tmp_path):
	"""Standardized notifier appends to ``<data_dir>/demo_plugin_events.log``."""
	plugin_dir = tmp_path / '.system_update' / 'plugins'
	plugin_dir.mkdir(parents=True)
	_write_plugin(plugin_dir / 'sample_plugin.py')

	with patch('pathlib.Path.home', return_value=tmp_path):
		config = SystemConfig()
		manager = NotificationManager(config)
		manager.plugin_registry = load_plugins(config)
		manager.notify_updates_available(3, vulnerable_count=0, force=True)

	log_path = tmp_path / '.system_update' / 'demo_plugin_events.log'
	assert log_path.is_file()
	body = log_path.read_text(encoding='utf-8')
	assert 'updates_available' in body
	assert "'updates': 3" in body or "'updates':3" in body
