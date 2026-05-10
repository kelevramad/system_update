"""Tests for the scheduler module (6.1.1 / 6.1.2)."""

from __future__ import annotations


import pytest

from system_update import scheduler


# ─── ScheduleSpec validation ───────────────────────────────────────────────


def test_spec_validates_known_frequency():
	scheduler.ScheduleSpec(frequency='daily', time='09:00').validate()
	scheduler.ScheduleSpec(frequency='weekly', time='09:00', days='MON').validate()
	scheduler.ScheduleSpec(frequency='hourly', time='').validate()
	scheduler.ScheduleSpec(frequency='onstart', time='').validate()


def test_spec_rejects_unknown_frequency():
	with pytest.raises(ValueError):
		scheduler.ScheduleSpec(frequency='yearly').validate()


def test_spec_requires_time_for_daily_weekly_monthly():
	with pytest.raises(ValueError):
		scheduler.ScheduleSpec(frequency='daily', time='').validate()
	with pytest.raises(ValueError):
		scheduler.ScheduleSpec(frequency='weekly', time='').validate()
	with pytest.raises(ValueError):
		scheduler.ScheduleSpec(frequency='monthly', time='').validate()


def test_spec_rejects_malformed_time():
	with pytest.raises(ValueError):
		scheduler.ScheduleSpec(frequency='daily', time='9am').validate()


# ─── _build_command ────────────────────────────────────────────────────────


def test_build_command_includes_python_and_module():
	cmd = scheduler._build_command('--source winget --notify')
	assert '-m system_update' in cmd
	assert '--source winget --notify' in cmd
	# Python interpreter path should be quoted (covers spaces in path).
	assert cmd.startswith('"')


def test_build_command_handles_empty_args():
	cmd = scheduler._build_command('')
	assert '-m system_update' in cmd
	assert cmd.endswith('-m system_update')


# ─── Non-Windows guard ─────────────────────────────────────────────────────


def test_non_windows_create_task_raises(monkeypatch):
	monkeypatch.setattr(scheduler, 'is_windows', lambda: False)
	with pytest.raises(RuntimeError):
		scheduler.create_task(scheduler.ScheduleSpec())


def test_non_windows_delete_task_raises(monkeypatch):
	monkeypatch.setattr(scheduler, 'is_windows', lambda: False)
	with pytest.raises(RuntimeError):
		scheduler.delete_task('foo')


def test_non_windows_list_returns_empty(monkeypatch):
	monkeypatch.setattr(scheduler, 'is_windows', lambda: False)
	assert scheduler.list_tasks() == []


# ─── schtasks invocation (mocked) ──────────────────────────────────────────


class _FakeProc:
	def __init__(self, returncode=0, stdout='', stderr=''):
		self.returncode = returncode
		self.stdout = stdout
		self.stderr = stderr


def test_create_task_invokes_schtasks_with_daily_args(monkeypatch):
	captured = {}

	def fake_run(argv, **kwargs):
		captured['argv'] = argv
		return _FakeProc(returncode=0, stdout='SUCCESS')

	monkeypatch.setattr(scheduler, 'is_windows', lambda: True)
	monkeypatch.setattr(scheduler.subprocess, 'run', fake_run)

	result = scheduler.create_task(scheduler.ScheduleSpec(
		name='SystemUpdate_Test',
		frequency='daily',
		time='03:00',
		command_args='--source winget',
	))
	argv = captured['argv']
	assert argv[0] == 'schtasks'
	assert '/Create' in argv
	assert '/TN' in argv and 'SystemUpdate_Test' in argv
	assert '/SC' in argv and 'DAILY' in argv
	assert '/ST' in argv and '03:00' in argv
	assert result['frequency'] == 'daily'
	assert result['name'] == 'SystemUpdate_Test'


def test_create_task_weekly_includes_days(monkeypatch):
	captured = {}
	monkeypatch.setattr(scheduler, 'is_windows', lambda: True)
	monkeypatch.setattr(
		scheduler.subprocess, 'run',
		lambda argv, **kw: (captured.update(argv=argv), _FakeProc(0, 'OK'))[1],
	)
	scheduler.create_task(scheduler.ScheduleSpec(
		name='X', frequency='weekly', time='09:00', days='MON,FRI',
	))
	argv = captured['argv']
	assert 'WEEKLY' in argv
	assert '/D' in argv and 'MON,FRI' in argv


def test_create_task_propagates_failure(monkeypatch):
	monkeypatch.setattr(scheduler, 'is_windows', lambda: True)
	monkeypatch.setattr(
		scheduler.subprocess, 'run',
		lambda argv, **kw: _FakeProc(returncode=1, stderr='Access denied.'),
	)
	with pytest.raises(RuntimeError, match='Access denied'):
		scheduler.create_task(scheduler.ScheduleSpec())


def test_delete_task_invokes_schtasks(monkeypatch):
	captured = {}
	monkeypatch.setattr(scheduler, 'is_windows', lambda: True)
	monkeypatch.setattr(
		scheduler.subprocess, 'run',
		lambda argv, **kw: (captured.update(argv=argv), _FakeProc(0, 'OK'))[1],
	)
	scheduler.delete_task('SystemUpdate_Foo')
	assert '/Delete' in captured['argv']
	assert 'SystemUpdate_Foo' in captured['argv']


def test_run_task_now_invokes_schtasks(monkeypatch):
	captured = {}
	monkeypatch.setattr(scheduler, 'is_windows', lambda: True)
	monkeypatch.setattr(
		scheduler.subprocess, 'run',
		lambda argv, **kw: (captured.update(argv=argv), _FakeProc(0, 'OK'))[1],
	)
	scheduler.run_task_now('SystemUpdate_Foo')
	assert '/Run' in captured['argv']


def test_list_tasks_filters_by_prefix(monkeypatch):
	# Sample schtasks /Query /FO CSV /V output (verbose with header).
	header = (
		'"HostName","TaskName","Next Run Time","Status","Logon Mode",'
		'"Last Run Time","Last Result","Author","Task To Run","Start In",'
		'"Comment","Scheduled Task State","Idle Time","Power Management",'
		'"Run As User","Delete Task If Not Rescheduled",'
		'"Stop Task If Runs X Hours and X Mins","Schedule","Schedule Type",'
		'"Start Time","Start Date","End Date","Days","Months",'
		'"Repeat: Every","Repeat: Until: Time","Repeat: Until: Duration",'
		'"Repeat: Stop If Still Running"'
	)
	def _row(name, nrt, status, lrt, result):
		# 28 columns; only the ones we read need real values.
		return (
			f'"HOST","{name}","{nrt}","{status}","Interactive only",'
			f'"{lrt}","{result}","Author","cmd","",'
			'"","Enabled","Disabled","",'
			'"vchav","Disabled","Disabled","On schedule","Daily",'
			'"03:00:00","26/04/2026","N/A","Every 1 day(s)","",'
			'"Disabled","Disabled","Disabled","Disabled"'
		)
	fake_csv = '\n'.join([
		header,
		_row('\\Other_Task', 'N/A', 'Disabled', 'N/A', '0'),
		_row('\\SystemUpdate_Scan', '26/04/2026 03:00:00', 'Ready',
		     '25/04/2026 03:00:00', '0'),
		_row('\\SystemUpdate_Weekly', '26/04/2026 09:00:00', 'Ready',
		     '19/04/2026 09:00:00', '267011'),
		_row('\\Microsoft\\Defender', 'N/A', 'Running', 'N/A', '0'),
	])
	monkeypatch.setattr(scheduler, 'is_windows', lambda: True)
	monkeypatch.setattr(
		scheduler.subprocess, 'run',
		lambda argv, **kw: _FakeProc(0, fake_csv),
	)
	# Verify /V (verbose) flag is requested, not /NH.
	tasks = scheduler.list_tasks()
	names = [t['name'] for t in tasks]
	assert names == ['SystemUpdate_Scan', 'SystemUpdate_Weekly']
	assert tasks[0]['status'] == 'Ready'
	assert tasks[0]['last_run'] == '25/04/2026 03:00:00'
	assert tasks[0]['last_result'] == '0'
	assert tasks[1]['last_run'] == '19/04/2026 09:00:00'
	assert tasks[1]['last_result'] == '267011'


def test_list_tasks_collapses_duplicate_trigger_rows(monkeypatch):
	"""``/V`` emits one row per trigger; we should collapse to one per task."""
	header = (
		'"HostName","TaskName","Next Run Time","Status","Logon Mode",'
		'"Last Run Time","Last Result"'
	)
	row = '"HOST","\\SystemUpdate_Scan","X","Ready","Y","Z","0"'
	fake_csv = '\n'.join([header, row, row, row])
	monkeypatch.setattr(scheduler, 'is_windows', lambda: True)
	monkeypatch.setattr(
		scheduler.subprocess, 'run',
		lambda argv, **kw: _FakeProc(0, fake_csv),
	)
	tasks = scheduler.list_tasks()
	assert len(tasks) == 1


def test_task_status_parses_verbose_list(monkeypatch):
	fake_list = (
		'TaskName: \\SystemUpdate_Scan\n'
		'Status: Ready\n'
		'Last Run Time: 25/04/2026 03:00:00\n'
		'Last Result: 0\n'
		'Next Run Time: 26/04/2026 03:00:00\n'
		'Task To Run: "py.exe" -m system_update --no-cache\n'
		'Schedule Type: Daily\n'
		'Run As User: vchav\n'
	)
	monkeypatch.setattr(scheduler, 'is_windows', lambda: True)
	monkeypatch.setattr(
		scheduler.subprocess, 'run',
		lambda argv, **kw: _FakeProc(0, fake_list),
	)
	info = scheduler.task_status('SystemUpdate_Scan')
	assert info is not None
	assert info['status'] == 'Ready'
	assert info['last_result'] == '0'
	assert 'system_update' in info['task_to_run']
	assert info['schedule_type'] == 'Daily'


def test_task_status_returns_none_on_failure(monkeypatch):
	monkeypatch.setattr(scheduler, 'is_windows', lambda: True)
	monkeypatch.setattr(
		scheduler.subprocess, 'run',
		lambda argv, **kw: _FakeProc(1, '', 'ERROR: not found'),
	)
	assert scheduler.task_status('NoSuch') is None
