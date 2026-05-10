"""Tests for remote management (6.4)."""

from __future__ import annotations

from pathlib import Path
import time

import pytest

from system_update import remote as remote_mod
from system_update.remote import (
	Inventory,
	RemoteHost,
	RemoteResult,
	aggregate_scans,
	argv_to_display,
	build_debug_argv,
	build_remote_scan_command,
	build_remote_update_command,
	execute_many,
	execute_remote,
	validate_remote_scan_payload,
)
from system_update.app import SystemUpdateApp


# ─── RemoteHost ───────────────────────────────────────────────────────────


def test_remote_host_address_defaults_to_name():
	h = RemoteHost(name='alpha')
	assert h.address == 'alpha'


def test_remote_host_to_from_dict_roundtrip():
	src = {
		'name': 'b', 'address': '10.0.0.5', 'user': 'admin',
		'transport': 'winrs', 'description': 'test',
		'groups': ['ci', 'win'],
	}
	h = RemoteHost.from_dict(src)
	assert h.address == '10.0.0.5'
	assert h.groups == ['ci', 'win']
	out = h.to_dict()
	assert out['name'] == 'b'
	assert out['groups'] == ['ci', 'win']
	# Port omitted from output when unset.
	assert 'port' not in out


# ─── Inventory CRUD ───────────────────────────────────────────────────────


@pytest.fixture
def inv(tmp_path: Path) -> Inventory:
	return Inventory(tmp_path / 'inventory.json')


def test_inventory_add_and_persist(inv: Inventory):
	inv.add(RemoteHost(name='build01', groups=['ci']))
	# Reload from disk to verify persistence.
	other = Inventory(inv.path)
	assert len(other.hosts) == 1
	assert other.hosts[0].name == 'build01'


def test_inventory_add_replaces_existing(inv: Inventory):
	inv.add(RemoteHost(name='build01', address='old'))
	inv.add(RemoteHost(name='BUILD01', address='new'))  # case-insensitive
	assert len(inv.hosts) == 1
	assert inv.hosts[0].address == 'new'


def test_inventory_remove(inv: Inventory):
	inv.add(RemoteHost(name='a'))
	inv.add(RemoteHost(name='b'))
	assert inv.remove('a') is True
	assert inv.remove('a') is False
	assert {h.name for h in inv.hosts} == {'b'}


def test_inventory_by_group(inv: Inventory):
	inv.add(RemoteHost(name='a', groups=['linux']))
	inv.add(RemoteHost(name='b', groups=['windows']))
	inv.add(RemoteHost(name='c', groups=['windows', 'ci']))
	assert {h.name for h in inv.by_group('windows')} == {'b', 'c'}
	assert {h.name for h in inv.by_group('ci')} == {'c'}


def test_inventory_resolve_precedence(inv: Inventory):
	inv.add(RemoteHost(name='a', groups=['x']))
	inv.add(RemoteHost(name='b', groups=['x']))
	inv.add(RemoteHost(name='c', groups=['y']))

	# Single host wins over group.
	out = inv.resolve(host='a', group='x')
	assert [h.name for h in out] == ['a']

	# Group when no host given.
	out = inv.resolve(host=None, group='x')
	assert {h.name for h in out} == {'a', 'b'}

	# Empty filters → all hosts.
	out = inv.resolve(host=None, group=None)
	assert len(out) == 3


def test_inventory_resolve_unknown_host(inv: Inventory):
	inv.add(RemoteHost(name='a'))
	assert inv.resolve(host='nope', group=None) == []


# ─── Command builders ─────────────────────────────────────────────────────


def test_build_remote_scan_command_emits_json_to_stdout():
	cmd = build_remote_scan_command()
	assert 'system-update' in cmd
	assert '--export' in cmd and 'json' in cmd
	assert '--no-cache' in cmd


def test_build_remote_scan_command_appends_extra_args():
	cmd = build_remote_scan_command('--source pip')
	assert '--source' in cmd
	assert 'pip' in cmd


def test_build_remote_update_command():
	cmd = build_remote_update_command()
	assert '--update-all' in cmd
	assert '--yes' in cmd


# ─── execute_remote ───────────────────────────────────────────────────────


class _FakeProc:
	def __init__(self, returncode=0, stdout='', stderr=''):
		self.returncode = returncode
		self.stdout = stdout
		self.stderr = stderr


def test_execute_remote_unsupported_transport():
	r = execute_remote(RemoteHost(name='x', transport='ssh'), 'cmd')
	assert r.ok is False
	assert 'not supported' in r.stderr.lower()


# ─── 1.1.1 — pywinrm transport keeps password off argv ───────────────────


def test_execute_remote_pywinrm_keeps_password_off_argv(monkeypatch):
	"""The pywinrm path must never invoke a subprocess with the password."""
	# Block subprocess entirely so a stray winrs call would fail loudly.
	def explode(*a, **kw):  # pragma: no cover — must not be called
		raise AssertionError('pywinrm transport must not spawn subprocesses')

	monkeypatch.setattr(remote_mod.subprocess, 'run', explode)

	class _Resp:
		status_code = 0
		std_out = b'{"packages":[]}'
		std_err = b''

	class _FakeSession:
		captured = {}

		def __init__(self, endpoint, **kw):
			_FakeSession.captured['endpoint'] = endpoint
			_FakeSession.captured['auth'] = kw.get('auth')

		def run_cmd(self, command):
			_FakeSession.captured['command'] = command
			return _Resp()

	fake_winrm = type('M', (), {'Session': _FakeSession})
	monkeypatch.setitem(__import__('sys').modules, 'winrm', fake_winrm)

	host = RemoteHost(name='build01', address='10.0.0.5', user='DOMAIN\\admin',
		transport='pywinrm')
	r = execute_remote(host, 'system-update --no-cache', password='S3cr3t!')
	assert r.ok
	assert r.parsed == {'packages': []}
	# Endpoint is HTTPS WinRM; password is in the auth tuple, not on argv.
	assert _FakeSession.captured['endpoint'].startswith('https://')
	assert _FakeSession.captured['auth'] == ('DOMAIN\\admin', 'S3cr3t!')


def test_execute_remote_pywinrm_missing_dependency_returns_error(monkeypatch):
	"""When pywinrm isn't installed, fail with an actionable message."""
	import builtins

	real_import = builtins.__import__

	def deny_winrm(name, *args, **kwargs):
		if name == 'winrm':
			raise ImportError('No module named winrm')
		return real_import(name, *args, **kwargs)

	monkeypatch.setattr(builtins, '__import__', deny_winrm)
	# Also drop any pre-imported stub from previous tests.
	import sys
	monkeypatch.delitem(sys.modules, 'winrm', raising=False)

	host = RemoteHost(name='h', transport='pywinrm', user='u')
	r = execute_remote(host, 'cmd', password='secret')
	assert r.ok is False
	assert 'pywinrm is not installed' in r.stderr


def test_winrs_with_password_emits_security_warning(monkeypatch, caplog):
	"""When winrs is used with a password, warn that argv leaks it."""
	import logging as _logging

	# Reset the module-level one-shot guard so the warning fires in this test.
	monkeypatch.setattr(remote_mod, '_WINRS_WARNED', False)

	monkeypatch.setattr(
		remote_mod.subprocess, 'run',
		lambda argv, **kw: _FakeProc(0, ''),
	)
	with caplog.at_level(_logging.WARNING, logger=remote_mod.__name__):
		execute_remote(RemoteHost(name='h', user='u', transport='winrs'), 'cmd',
			password='secret')

	messages = ' '.join(rec.message for rec in caplog.records)
	assert 'visible to other local users' in messages
	assert 'pywinrm' in messages


def test_execute_remote_invokes_winrs(monkeypatch):
	captured = {}

	def fake_run(argv, **kw):
		captured['argv'] = argv
		captured['kwargs'] = kw
		return _FakeProc(0, '{"packages":[]}')

	monkeypatch.setattr(remote_mod.subprocess, 'run', fake_run)
	host = RemoteHost(name='build01', address='10.0.0.5', user='DOMAIN\\admin')
	r = execute_remote(host, 'system-update --export json -o -')
	assert r.ok
	assert r.exit_code == 0
	# winrs argv assembled correctly.
	argv = captured['argv']
	assert argv[0] == 'winrs'
	assert '-r:10.0.0.5' in argv
	assert '-u:DOMAIN\\admin' in argv
	# JSON parsed into ``parsed`` field.
	assert r.parsed == {'packages': []}


def test_execute_remote_password_via_env(monkeypatch):
	monkeypatch.setenv('SYSTEM_UPDATE_REMOTE_PASS', 'secret123')
	captured = {}
	monkeypatch.setattr(
		remote_mod.subprocess, 'run',
		lambda argv, **kw: (captured.update(argv=argv), _FakeProc(0, ''))[1],
	)
	execute_remote(RemoteHost(name='h', user='u'), 'cmd')
	assert any(a == '-p:secret123' for a in captured['argv'])


def test_build_debug_argv_redacts_password(monkeypatch):
	monkeypatch.setenv('SYSTEM_UPDATE_REMOTE_PASS', 'secret123')
	host = RemoteHost(name='build01', user='DOMAIN\\admin')
	argv = build_debug_argv(host, 'system-update --no-cache')
	display = argv_to_display(argv)
	assert '-p:***' in argv
	assert 'secret123' not in display
	assert 'system-update --no-cache' in display


def test_execute_remote_handles_winrs_missing(monkeypatch):
	def raise_fnf(argv, **kw):
		raise FileNotFoundError('no such file')

	monkeypatch.setattr(remote_mod.subprocess, 'run', raise_fnf)
	r = execute_remote(RemoteHost(name='h'), 'cmd')
	assert r.ok is False
	assert 'winrs.exe not found' in r.stderr


def test_execute_remote_handles_timeout(monkeypatch):
	import subprocess as _sp

	def raise_timeout(argv, **kw):
		raise _sp.TimeoutExpired(cmd=argv, timeout=1)

	monkeypatch.setattr(remote_mod.subprocess, 'run', raise_timeout)
	r = execute_remote(RemoteHost(name='h'), 'cmd', timeout=1)
	assert r.ok is False
	assert 'timeout' in r.stderr.lower()


def test_execute_remote_non_json_stdout(monkeypatch):
	monkeypatch.setattr(
		remote_mod.subprocess, 'run',
		lambda argv, **kw: _FakeProc(0, 'plain text output'),
	)
	r = execute_remote(RemoteHost(name='h'), 'cmd')
	assert r.ok and r.parsed is None
	assert 'plain text' in r.stdout


def test_execute_remote_rejects_oversized_json_stdout(monkeypatch):
	monkeypatch.setattr(remote_mod, '_max_response_bytes', lambda: 16)
	monkeypatch.setattr(
		remote_mod.subprocess, 'run',
		lambda argv, **kw: _FakeProc(0, '{"packages":["0123456789"]}'),
	)
	r = execute_remote(RemoteHost(name='h'), 'cmd')
	assert r.ok is False
	assert r.parsed is None
	assert 'exceeded 16 bytes' in r.stderr


def test_execute_remote_malformed_json_stdout_returns_error(monkeypatch):
	monkeypatch.setattr(remote_mod, '_max_response_bytes', lambda: 1024)
	monkeypatch.setattr(
		remote_mod.subprocess, 'run',
		lambda argv, **kw: _FakeProc(0, '{"packages": [}'),
	)
	r = execute_remote(RemoteHost(name='h'), 'cmd')
	assert r.ok is False
	assert r.parsed is None
	assert 'invalid' in r.stderr.lower()


def test_execute_remote_pywinrm_rejects_oversized_json_stdout(monkeypatch):
	monkeypatch.setattr(remote_mod, '_max_response_bytes', lambda: 16)

	class _Resp:
		status_code = 0
		std_out = b'{"packages":["0123456789"]}'
		std_err = b''

	class _FakeSession:
		def __init__(self, *args, **kwargs):
			pass

		def run_cmd(self, command):
			return _Resp()

	fake_winrm = type('M', (), {'Session': _FakeSession})
	monkeypatch.setitem(__import__('sys').modules, 'winrm', fake_winrm)

	r = execute_remote(RemoteHost(name='h', transport='pywinrm'), 'cmd')
	assert r.ok is False
	assert r.parsed is None
	assert 'exceeded 16 bytes' in r.stderr


# ─── execute_many parallel fan-out ────────────────────────────────────────


def test_execute_many_returns_one_result_per_host(monkeypatch):
	monkeypatch.setattr(
		remote_mod, 'execute_remote',
		lambda host, cmd, timeout=600, password='': RemoteResult(
			host=host.name, ok=True, exit_code=0,
		),
	)
	hosts = [RemoteHost(name=n) for n in ['a', 'c', 'b']]
	results = execute_many(hosts, 'cmd')
	# Sorted by name for stable output.
	assert [r.host for r in results] == ['a', 'b', 'c']


def test_execute_many_empty():
	assert execute_many([], 'cmd') == []


def test_execute_many_invokes_on_complete_per_host(monkeypatch):
	"""Live-progress callback fires once per host with the host + result."""
	monkeypatch.setattr(
		remote_mod, 'execute_remote',
		lambda host, cmd, timeout=600, password='': RemoteResult(
			host=host.name, ok=True, exit_code=0, duration=0.1,
		),
	)
	calls = []
	hosts = [RemoteHost(name=n) for n in ['a', 'b', 'c']]
	execute_many(hosts, 'cmd', on_complete=lambda h, r: calls.append((h.name, r.host)))
	assert sorted(c[0] for c in calls) == ['a', 'b', 'c']
	# host parameter and result.host must agree.
	for host_name, result_host in calls:
		assert host_name == result_host


def test_execute_many_invokes_start_and_tick_callbacks(monkeypatch):
	def slow_remote(host, cmd, timeout=600, password=''):
		time.sleep(0.08)
		return RemoteResult(host=host.name, ok=True, exit_code=0)

	monkeypatch.setattr(remote_mod, 'execute_remote', slow_remote)
	started = []
	ticks = []
	results = execute_many(
		[RemoteHost(name='slow')],
		'cmd',
		tick_interval=0.01,
		on_start=lambda h: started.append(h.name),
		on_tick=lambda h, elapsed: ticks.append((h.name, elapsed)),
	)

	assert [r.host for r in results] == ['slow']
	assert started == ['slow']
	assert ticks
	assert ticks[0][0] == 'slow'


def test_execute_many_swallows_callback_exceptions(monkeypatch):
	"""A buggy callback shouldn't break the fan-out."""
	monkeypatch.setattr(
		remote_mod, 'execute_remote',
		lambda host, cmd, timeout=600, password='': RemoteResult(
			host=host.name, ok=True, exit_code=0,
		),
	)

	def _boom(host, result):
		raise RuntimeError('callback bug')

	hosts = [RemoteHost(name='x'), RemoteHost(name='y')]
	results = execute_many(hosts, 'cmd', on_complete=_boom)
	# Despite the callback raising, both hosts ran and produced results.
	assert {r.host for r in results} == {'x', 'y'}


def test_remote_debug_prints_redacted_command_before_completion(monkeypatch, capsys):
	app = SystemUpdateApp()
	app.history_db.close()
	host = RemoteHost(name='build01', address='build01.corp', user='DOMAIN\\admin')

	def fake_execute_many(
		hosts, command, timeout=600, password='', max_workers=4,
		on_start=None, on_tick=None, on_complete=None, **kwargs,
	):
		result = RemoteResult(host='build01', ok=False, exit_code=1, stderr='auth failed')
		if on_start:
			on_start(hosts[0])
		if on_tick:
			on_tick(hosts[0], 12.0)
		if on_complete:
			on_complete(hosts[0], result)
		return [result]

	monkeypatch.setenv('SYSTEM_UPDATE_REMOTE_PASS', 'secret123')
	monkeypatch.setattr(remote_mod, 'execute_many', fake_execute_many)
	app._run_remote_with_progress([host], 'system-update --no-cache', 42, verbose=False, debug=True)

	out = capsys.readouterr().out
	assert 'Remote debug enabled' in out
	assert 'build01.corp' in out
	assert 'winrs' in out
	assert '-p:***' in out
	assert 'secret123' not in out
	assert 'auth failed' in out


# ─── aggregate_scans ──────────────────────────────────────────────────────


def _sample_pkg(name, source='winget', version='1.0', status='update_available'):
	return {
		'name': name, 'source': source, 'version': version, 'status': status,
	}


def test_aggregate_scans_merges_packages():
	results = [
		RemoteResult(
			host='a', ok=True,
			parsed={'packages': [
				_sample_pkg('git', version='1.0'),
				_sample_pkg('node', source='npm', version='20.0'),
			]},
		),
		RemoteResult(
			host='b', ok=True,
			parsed={'packages': [
				_sample_pkg('git', version='1.0'),  # same version → consistent
				_sample_pkg('python', version='3.13'),
			]},
		),
	]
	report = aggregate_scans(results)
	assert report['host_count'] == 2
	assert report['error_count'] == 0
	# git appears on both hosts.
	by_name = {(p['source'], p['name']): p for p in report['package_index']}
	git = by_name[('winget', 'git')]
	assert git['host_count'] == 2
	assert git['consistent'] is True
	assert git['versions'] == ['1.0']
	# node only on host a.
	node = by_name[('npm', 'node')]
	assert node['host_count'] == 1


def test_aggregate_scans_flags_version_inconsistency():
	results = [
		RemoteResult(host='a', ok=True, parsed={'packages': [
			_sample_pkg('git', version='2.40.0'),
		]}),
		RemoteResult(host='b', ok=True, parsed={'packages': [
			_sample_pkg('git', version='2.41.0'),
		]}),
	]
	report = aggregate_scans(results)
	git = report['package_index'][0]
	assert git['consistent'] is False
	assert git['versions'] == ['2.40.0', '2.41.0']


def test_aggregate_scans_collects_errors():
	results = [
		RemoteResult(host='a', ok=False, exit_code=1, stderr='auth failed'),
		RemoteResult(host='b', ok=True, parsed={'packages': []}),
	]
	report = aggregate_scans(results)
	assert report['host_count'] == 1
	assert report['error_count'] == 1
	assert report['errors'][0]['host'] == 'a'
	assert 'auth failed' in report['errors'][0]['stderr']


def test_aggregate_scans_handles_bare_list_payload():
	"""Some exports return a bare list instead of {"packages": [...]}."""
	results = [
		RemoteResult(host='a', ok=True, parsed=[_sample_pkg('git')]),
	]
	report = aggregate_scans(results)
	assert report['package_index'][0]['name'] == 'git'


def test_aggregate_scans_empty_input():
	report = aggregate_scans([])
	assert report.hosts == []
	assert report['host_count'] == 0
	assert report['package_index'] == []


def test_validate_remote_scan_payload_accepts_apps_shape():
	payload = validate_remote_scan_payload({
		'apps': [_sample_pkg('git')],
		'summary': {'total_apps': 1},
		'extra': 'ignored',
	})

	apps = payload.get('apps')
	assert apps is not None
	assert apps[0]['name'] == 'git'
	assert 'extra' not in payload


def test_validate_remote_scan_payload_rejects_missing_name():
	with pytest.raises(ValueError, match='packages\\[0\\]\\.name missing'):
		validate_remote_scan_payload({'packages': [{'source': 'winget'}]})
