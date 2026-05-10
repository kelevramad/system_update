from argparse import Namespace

from system_update.commands.remote_cmd import RemoteCommand
from system_update.commands.schedule_cmd import ScheduleCommand
from system_update.commands.scan_cmd import ScanCommand
from system_update.commands.snapshot_cmd import SnapshotCommand


class _Ctx:
	def __init__(self):
		self.calls = []

	def _handle_remote(self, args):
		self.calls.append(('remote', args))

	def _handle_schedule(self, args):
		self.calls.append(('schedule', args))

	def _handle_snapshot(self, args):
		self.calls.append(('snapshot', args))

	def scan_system(self, source):
		self.calls.append(('scan', source))
		return []


def test_remote_command_executes_without_system_update_app():
	args = Namespace(remote='list')
	ctx = _Ctx()

	assert RemoteCommand().execute(args, ctx) == 0
	assert ctx.calls == [('remote', args)]


def test_snapshot_command_executes_without_system_update_app():
	args = Namespace(snapshot='list')
	ctx = _Ctx()

	assert SnapshotCommand().execute(args, ctx) == 0
	assert ctx.calls == [('snapshot', args)]


def test_schedule_command_executes_without_system_update_app():
	args = Namespace(schedule='list')
	ctx = _Ctx()

	assert ScheduleCommand().execute(args, ctx) == 0
	assert ctx.calls == [('schedule', args)]


def test_scan_command_executes_without_system_update_app():
	args = Namespace(source='pip')
	ctx = _Ctx()

	assert ScanCommand().execute(args, ctx) == 0
	assert ctx.calls == [('scan', 'pip')]
