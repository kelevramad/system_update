"""Tests for snapshot storage + rollback (6.2)."""

from __future__ import annotations

from pathlib import Path
from argparse import Namespace
from unittest.mock import patch

import pytest

from system_update.app import SystemUpdateApp
from system_update import app as app_module
from system_update.executors.commands import (
	build_rollback_command,
	build_update_command,
	supports_rollback,
)
from system_update.models import AppInfo, UpdateStatus
from system_update.snapshots import (
	SnapshotPackage,
	SnapshotStore,
	build_snapshot_packages,
	capture_pre_update,
)


# ─── Store ─────────────────────────────────────────────────────────────────


@pytest.fixture
def store(tmp_path: Path):
	s = SnapshotStore(tmp_path / 'history.db')
	yield s
	s.close()


def _pkg(name='git', source='winget', before='1.0', after='2.0', success=True):
	return SnapshotPackage(
		name=name, source=source, app_id=name,
		version_before=before, version_after=after, success=success,
	)


def test_record_persists_header_and_packages(store: SnapshotStore):
	snap_id = store.record(
		[_pkg('git'), _pkg('node', 'npm', '20.0', '20.5')],
		label='test batch', command='system-update --update-all',
	)
	assert snap_id

	snap = store.get(snap_id)
	assert snap is not None
	assert snap.id == snap_id
	assert snap.label == 'test batch'
	assert snap.command.startswith('system-update')
	assert snap.package_count == 2
	assert snap.success_count == 2
	assert {p.name for p in snap.packages} == {'git', 'node'}


def test_record_counts_failures(store: SnapshotStore):
	snap_id = store.record([
		_pkg('a', success=True),
		_pkg('b', success=False),
		_pkg('c', success=False),
	])
	snap = store.get(snap_id)
	assert snap is not None
	assert snap.package_count == 3
	assert snap.success_count == 1


def test_list_snapshots_orders_newest_first(store: SnapshotStore):
	import time

	a = store.record([_pkg('a')], label='first')
	time.sleep(1)  # snapshot ids include seconds — avoid collision
	b = store.record([_pkg('b')], label='second')
	rows = store.list_snapshots()
	assert rows[0].id == b
	assert rows[1].id == a


def test_list_snapshots_respects_limit(store: SnapshotStore):
	import time

	for i in range(3):
		store.record([_pkg(f'p{i}')])
		time.sleep(1)
	assert len(store.list_snapshots(limit=2)) == 2


def test_get_with_last_returns_newest(store: SnapshotStore):
	import time

	store.record([_pkg('a')])
	time.sleep(1)
	last_id = store.record([_pkg('b')], label='latest')
	snap = store.get('last')
	assert snap is not None
	assert snap.id == last_id


def test_get_unknown_id_returns_none(store: SnapshotStore):
	assert store.get('nope-9999') is None


def test_delete_removes_snapshot_and_packages(store: SnapshotStore):
	snap_id = store.record([_pkg('a'), _pkg('b')])
	assert store.delete(snap_id) is True
	assert store.get(snap_id) is None
	# Verify the packages were cascaded.
	conn = store._connect()
	cur = conn.execute(
		'SELECT COUNT(*) FROM snapshot_packages WHERE snapshot_id = ?',
		(snap_id,),
	)
	assert cur.fetchone()[0] == 0


def test_delete_unknown_returns_false(store: SnapshotStore):
	assert store.delete('nope') is False


# ─── Pre/post helpers ──────────────────────────────────────────────────────


def test_capture_pre_update_extracts_versions():
	apps = [
		AppInfo(name='git', source='winget', version='1.0',
		        latest_version='2.0', app_id='Git.Git'),
		AppInfo(name='lodash', source='npm', version='4.17.20',
		        latest_version='4.17.21'),
	]
	pre = capture_pre_update(apps)
	assert pre[0]['version_before'] == '1.0'
	assert pre[0]['version_target'] == '2.0'
	assert pre[0]['app_id'] == 'Git.Git'
	assert pre[1]['source'] == 'npm'


def test_build_snapshot_packages_marks_success_correctly():
	pre = [
		{'name': 'git', 'source': 'winget', 'app_id': 'Git.Git',
		 'version_before': '1.0', 'version_target': '2.0'},
		{'name': 'lodash', 'source': 'npm', 'app_id': None,
		 'version_before': '4.17.20', 'version_target': '4.17.21'},
	]
	results = {'winget|git': True, 'npm|lodash': False}
	rows = build_snapshot_packages(pre, results)
	assert rows[0].success is True
	assert rows[0].version_after == '2.0'
	assert rows[1].success is False
	# Failed update keeps version_before as version_after.
	assert rows[1].version_after == rows[1].version_before == '4.17.20'


# ─── Rollback command builders ─────────────────────────────────────────────


@pytest.mark.parametrize('source,expected_token', [
	('Winget', 'winget'),
	('Chocolatey', 'choco'),
	('NPM', 'npm'),
	('PNPM', 'pnpm'),
	('Bun', 'bun'),
	('Yarn', 'yarn'),
	('PIP', 'pip'),
])
def test_rollback_supported_sources(source, expected_token):
	assert supports_rollback(source) is True
	app = AppInfo(
		name='pkg', source=source, version='2.0',
		latest_version='1.0', app_id='pkg.id',
	)
	cmd = build_rollback_command(app)
	assert cmd is not None
	assert any(expected_token in token for token in cmd)
	# Version must appear somewhere in the command.
	assert any('1.0' in str(token) for token in cmd)


@pytest.mark.parametrize('source', ['PATH', 'Scoop', 'dotnet', 'Rust'])
def test_rollback_unsupported_sources(source):
	assert supports_rollback(source) is False
	app = AppInfo(name='pkg', source=source, version='2.0', latest_version='1.0')
	assert build_rollback_command(app) is None


def test_rollback_returns_none_without_target_version():
	app = AppInfo(name='pkg', source='Winget', version='2.0',
	              latest_version='', app_id='pkg.id')
	assert build_rollback_command(app) is None


def test_rollback_winget_uses_app_id():
	app = AppInfo(name='Git', source='Winget', version='2.41.0',
	              latest_version='2.40.0', app_id='Git.Git')
	cmd = build_rollback_command(app)
	assert cmd is not None
	assert '--id' in cmd
	assert 'Git.Git' in cmd
	assert '-v' in cmd
	assert '2.40.0' in cmd
	assert '--force' in cmd


def test_rollback_chocolatey_includes_allow_downgrade():
	app = AppInfo(name='git', source='Chocolatey', version='2.41.0',
	              latest_version='2.40.0')
	cmd = build_rollback_command(app)
	assert cmd is not None
	assert '--allow-downgrade' in cmd
	assert 'git' in cmd
	assert '2.40.0' in cmd


def test_rollback_pip_uses_force_reinstall():
	app = AppInfo(name='requests', source='PIP', version='2.31.0',
	              latest_version='2.30.0')
	cmd = build_rollback_command(app)
	assert cmd is not None
	assert 'pip' in cmd
	assert any('requests==2.30.0' in t for t in cmd)
	assert '--force-reinstall' in cmd


@pytest.mark.parametrize(
	'source,name,app_id,latest,expected',
	[
		('NPM', 'pkg', 'pkg', '2.0.0', ['npm', 'install', '-g', 'pkg@2.0.0']),
		('PNPM', 'pkg', 'pkg', '2.0.0', ['pnpm', 'add', '-g', 'pkg@2.0.0']),
		('Bun', 'pkg', 'pkg', '2.0.0', ['bun', 'add', '-g', 'pkg@2.0.0']),
		('Yarn', 'pkg', 'pkg', '2.0.0', ['yarn', 'global', 'add', 'pkg@2.0.0']),
	],
)
def test_node_builders_share_update_and_rollback_shape(source, name, app_id, latest, expected):
	app = AppInfo(name=name, source=source, version='1.0.0',
	              latest_version=latest, app_id=app_id)
	assert build_update_command(app) == expected
	assert build_rollback_command(app) == expected


def test_executor_commands_have_no_rollback_suffix_builders():
	source = Path(__file__).parents[1] / 'src' / 'system_update' / 'executors' / 'commands.py'
	assert '_rb(' not in source.read_text(encoding='utf-8')


def test_update_command_accepts_lowercase_cached_source():
	app = AppInfo(
		name='Pygments',
		source='pip',
		version='2.18.0',
		latest_version='2.20.0',
	)
	cmd = build_update_command(app)
	assert cmd is not None
	assert any('Pygments==2.20.0' in t for t in cmd)


# ─── execute_rollback wiring ───────────────────────────────────────────────


def test_execute_rollback_skips_unsupported_sources():
	from system_update.executors import execute_rollback

	pkgs = [
		_pkg('node', source='PATH', before='20.0'),  # unsupported
		_pkg('git', source='Winget', before='1.0'),  # supported
	]
	with patch(
		'system_update.executors.run_command', return_value='ok',
	) as mock_run:
		execute_rollback(pkgs, dry_run=False)
	# run_command called only for the supported entry.
	assert mock_run.call_count == 1


def test_execute_rollback_dry_run_does_not_invoke_run_command():
	from system_update.executors import execute_rollback

	pkgs = [_pkg('git', source='Winget', before='1.0')]
	with patch('system_update.executors.run_command') as mock_run:
		execute_rollback(pkgs, dry_run=True)
	mock_run.assert_not_called()


def test_execute_rollback_skips_missing_version_before():
	from system_update.executors import execute_rollback

	pkgs = [_pkg('git', source='Winget', before='', after='2.0')]
	with patch('system_update.executors.run_command') as mock_run:
		execute_rollback(pkgs, dry_run=False)
	mock_run.assert_not_called()


# ─── execute_updates → snapshot integration ───────────────────────────────


def test_execute_updates_records_snapshot_when_store_provided(tmp_path):
	from system_update.executors import execute_updates

	store = SnapshotStore(tmp_path / 'history.db')
	apps = [
		AppInfo(name='git', source='Winget', version='1.0',
		        latest_version='2.0', app_id='Git.Git'),
	]
	with patch('system_update.executors.run_command', return_value='ok'):
		snap_id = execute_updates(
			apps, dry_run=False,
			snapshot_store=store, snapshot_label='unit-test',
		)
	assert snap_id is not None
	snap = store.get(snap_id)
	assert snap is not None
	assert snap.label == 'unit-test'
	assert snap.packages[0].version_before == '1.0'
	assert snap.packages[0].version_after == '2.0'
	assert snap.packages[0].success is True


def test_execute_updates_skips_snapshot_in_dry_run(tmp_path):
	from system_update.executors import execute_updates

	store = SnapshotStore(tmp_path / 'history.db')
	apps = [AppInfo(name='git', source='Winget', version='1.0',
	                latest_version='2.0', app_id='Git.Git')]
	snap_id = execute_updates(apps, dry_run=True, snapshot_store=store)
	assert snap_id is None
	assert store.list_snapshots() == []


def test_single_package_update_records_snapshot(tmp_path):
	app = SystemUpdateApp()
	app.history_db.close()
	app.config.config_dir = tmp_path
	apps = [
		AppInfo(
			name='Pygments',
			source='PIP',
			version='2.18.0',
			latest_version='2.19.1',
		),
	]
	args = Namespace(
		package='Pygments',
		source=None,
		version=None,
		dry_run=False,
		yes=True,
	)

	with patch('system_update.executors.run_command', return_value='ok') as mock_run:
		app._handle_single_update(apps, args)

	mock_run.assert_called_once()
	with SnapshotStore(tmp_path / 'history.db') as store:
		snap = store.get('last')
	assert snap is not None
	assert snap.label == 'package:Pygments'
	assert snap.packages[0].name == 'Pygments'
	assert snap.packages[0].version_before == '2.18.0'
	assert snap.packages[0].version_after == '2.19.1'


def test_single_package_update_refreshes_cache(tmp_path):
	from system_update.cache import CacheManager

	app = SystemUpdateApp()
	app.history_db.close()
	app.config.config_dir = tmp_path
	app.cache_mgr = CacheManager(tmp_path / 'cache.json')
	apps = [
		AppInfo(
			name='Pygments',
			source='PIP',
			version='2.18.0',
			latest_version='2.19.1',
			update_status=UpdateStatus.UPDATE_AVAILABLE,
		),
	]
	args = Namespace(
		package='Pygments',
		source=None,
		version=None,
		dry_run=False,
		yes=True,
	)

	with patch('system_update.executors.run_command', return_value='ok'):
		app._handle_single_update(apps, args)

	loaded = app.cache_mgr.load()
	assert loaded is not None
	assert loaded[0].name == 'Pygments'
	assert loaded[0].version == '2.19.1'
	assert loaded[0].latest_version == ''
	assert loaded[0].update_status == UpdateStatus.UP_TO_DATE


def test_single_package_update_prompts_without_yes(tmp_path, capsys):
	app = SystemUpdateApp()
	app.history_db.close()
	app.config.config_dir = tmp_path
	apps = [
		AppInfo(
			name='Pygments',
			source='PIP',
			version='2.18.0',
			latest_version='2.19.1',
		),
	]
	args = Namespace(
		package='Pygments',
		source=None,
		version=None,
		dry_run=False,
		yes=False,
	)

	with (
		patch('system_update.app._confirm_default_no', return_value=False) as mock_confirm,
		patch('system_update.executors.run_command') as mock_run,
	):
		app._handle_single_update(apps, args)

	mock_confirm.assert_called_once()
	mock_run.assert_not_called()
	output = capsys.readouterr().out
	assert 'Package queued for update' in output
	assert 'Pygments' in output
	assert 'Cancelled.' in output
	with SnapshotStore(tmp_path / 'history.db') as store:
		assert store.list_snapshots() == []


def test_confirm_default_no_renders_yN_and_defaults_to_no():
	with patch('system_update.app.Prompt.ask', return_value='n') as mock_prompt:
		assert app_module._confirm_default_no('Proceed?') is False

	mock_prompt.assert_called_once()
	_, kwargs = mock_prompt.call_args
	assert '\\[y/N]' in mock_prompt.call_args.args[0]
	assert kwargs['default'] == 'n'
	assert kwargs['show_choices'] is False
	assert kwargs['show_default'] is False


def test_rollback_prints_package_preview_before_execution(tmp_path, capsys):
	app = SystemUpdateApp()
	app.history_db.close()
	app.config.config_dir = tmp_path
	with SnapshotStore(tmp_path / 'history.db') as store:
		snap_id = store.record([
			SnapshotPackage(
				name='Pygments',
				source='pip',
				app_id='Pygments',
				version_before='2.19.2',
				version_after='2.20.0',
				success=True,
			),
		], label='package:Pygments', command='system-update --update-package Pygments')
	args = Namespace(rollback=snap_id, dry_run=False, yes=True)

	with patch('system_update.executors.run_command', return_value='ok'):
		app._handle_rollback(args)

	output = capsys.readouterr().out
	assert 'Packages queued for rollback' in output
	assert 'Pygments' in output
	assert '2.20.0' in output
	assert '2.19.2' in output


def test_update_all_prints_regular_and_security_counts(capsys):
	app = SystemUpdateApp()
	app.history_db.close()
	regular = [
		AppInfo(
			name='regular-one',
			source='PIP',
			version='1.0',
			latest_version='1.1',
			update_status=UpdateStatus.UPDATE_AVAILABLE,
		),
		AppInfo(
			name='regular-two',
			source='PIP',
			version='2.0',
			latest_version='2.1',
			update_status=UpdateStatus.UPDATE_AVAILABLE,
		),
	]
	security = [
		AppInfo(
			name='vulnerable-one',
			source='PIP',
			version='3.0',
			latest_version='3.1',
			update_status=UpdateStatus.VULNERABLE,
		),
	]
	args = Namespace(dry_run=True, yes=True)

	with patch.object(app.executor, 'execute_updates', return_value=None) as mock_exec:
		assert app._print_available_updates_summary(regular, security) == 3
		app._update_all_workflow(regular, security, args)

	output = capsys.readouterr().out
	assert 'Found 3 available updates (2 regular, 1 security/vulnerable)' in output
	assert 'Priority: Updating 1 vulnerable package(s) first' in output
	assert 'Now updating 2 regular package(s)' in output
	assert mock_exec.call_count == 2
	assert mock_exec.call_args_list[0].args[0] == security
	assert mock_exec.call_args_list[1].args[0] == regular


def test_vulnerable_package_without_newer_version_is_not_counted_as_update(capsys):
	from system_update.app import _count_updates

	app = SystemUpdateApp()
	app.history_db.close()
	regular = [
		AppInfo(
			name='psutil',
			source='PIP',
			version='6.1.1',
			latest_version='7.2.2',
			update_status=UpdateStatus.UPDATE_AVAILABLE,
		),
	]
	vulnerable_fixed = [
		AppInfo(
			name='pip',
			source='PIP',
			version='26.1',
			latest_version='26.1',
			update_status=UpdateStatus.VULNERABLE,
			security_findings=[{'severity': 'MEDIUM', 'cve': 'CVE-2026-3219'}],
		),
	]
	args = Namespace(dry_run=True, yes=True)

	assert _count_updates(regular + vulnerable_fixed) == 1
	assert app._print_available_updates_summary(regular, [a for a in vulnerable_fixed if a.has_update]) == 1

	with patch.object(app.executor, 'execute_updates', return_value=None) as mock_exec:
		app._update_all_workflow(regular, vulnerable_fixed, args)

	output = capsys.readouterr().out
	assert 'Found 1 available updates (1 regular, 0 security/vulnerable)' in output
	assert 'Priority: Updating' not in output
	assert 'Now updating 1 regular package(s)' in output
	mock_exec.assert_called_once()
	assert mock_exec.call_args.args[0] == regular


def test_update_all_declining_security_still_offers_regular(capsys):
	app = SystemUpdateApp()
	app.history_db.close()
	regular = [
		AppInfo(
			name='regular-one',
			source='PIP',
			version='1.0',
			latest_version='1.1',
			update_status=UpdateStatus.UPDATE_AVAILABLE,
		),
	]
	security = [
		AppInfo(
			name='vulnerable-one',
			source='PIP',
			version='3.0',
			latest_version='3.1',
			update_status=UpdateStatus.VULNERABLE,
		),
	]
	args = Namespace(dry_run=True, yes=False)

	with (
		patch('system_update.app._confirm_default_no', side_effect=[False, True]) as mock_confirm,
		patch.object(app.executor, 'execute_updates', return_value=None) as mock_exec,
	):
		app._update_all_workflow(regular, security, args)

	output = capsys.readouterr().out
	assert 'Skipped security/vulnerable package updates.' in output
	assert 'Now updating 1 regular package(s)' in output
	assert mock_confirm.call_count == 2
	mock_exec.assert_called_once()
	assert mock_exec.call_args.args[0] == regular


def test_update_all_declining_regular_prints_skip_message(capsys):
	app = SystemUpdateApp()
	app.history_db.close()
	regular = [
		AppInfo(
			name='regular-one',
			source='PIP',
			version='1.0',
			latest_version='1.1',
			update_status=UpdateStatus.UPDATE_AVAILABLE,
		),
	]
	security = [
		AppInfo(
			name='vulnerable-one',
			source='PIP',
			version='3.0',
			latest_version='3.1',
			update_status=UpdateStatus.VULNERABLE,
		),
	]
	args = Namespace(dry_run=True, yes=False)

	with (
		patch('system_update.app._confirm_default_no', side_effect=[False, False]),
		patch.object(app.executor, 'execute_updates', return_value=None) as mock_exec,
	):
		app._update_all_workflow(regular, security, args)

	output = capsys.readouterr().out
	assert 'Skipped security/vulnerable package updates.' in output
	assert 'Skipped regular package updates.' in output
	mock_exec.assert_not_called()


def test_security_table_displays_before_update_prompts():
	app = SystemUpdateApp()
	app.history_db.close()
	events = []
	apps = [
		AppInfo(
			name='regular-one',
			source='PIP',
			version='1.0',
			latest_version='1.1',
			update_status=UpdateStatus.UPDATE_AVAILABLE,
		),
		AppInfo(
			name='vulnerable-one',
			source='PIP',
			version='3.0',
			latest_version='3.1',
			update_status=UpdateStatus.VULNERABLE,
			security_findings=[{'severity': 'HIGH', 'cve': 'CVE-1'}],
		),
	]
	args = Namespace(
		source=None,
		exclude=None,
		update_source=None,
		update_all=True,
		dry_run=True,
		yes=True,
		no_cache=False,
		clear_cache=False,
		profile=None,
		profile_export=None,
		profile_import=None,
		save_config=False,
		format=None,
		theme=None,
		icons=False,
		interactive=False,
		show_all=False,
		notify=False,
		export=None,
		output=None,
		html_template=None,
		html_logo=None,
		html_title=None,
		html_company=None,
		package=None,
		history=False,
		history_package=None,
		history_trends=False,
		history_stale=0,
		report=None,
		import_files=[],
		merge_with_cache=False,
		cloud_sync=None,
		schedule=None,
		rollback=None,
		snapshot=None,
	)

	with (
		patch.object(app.cache_mgr, 'load', return_value=apps),
		patch.object(app.cache_mgr, 'load_sources', return_value=['pip']),
		patch.object(app.ui, 'display_banner'),
		patch.object(app.ui, 'display_summary'),
		patch('system_update.commands.run_cmd.DisplayFormatter.format_table', return_value='table'),
		patch.object(app, '_display_security_table', side_effect=lambda _v: events.append('security')),
		patch.object(app, '_print_available_updates_summary', side_effect=lambda _u, _s: events.append('summary') or 2),
		patch.object(app, '_update_all_workflow', side_effect=lambda _u, _v, _a: events.append('workflow')),
	):
		app.run(args)

	assert events == ['security', 'summary', 'workflow']
