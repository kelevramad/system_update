from argparse import Namespace
from unittest.mock import MagicMock, patch
from pathlib import Path
import tempfile

from system_update.commands.remote_cmd import RemoteCommand
from system_update.commands.schedule_cmd import ScheduleCommand
from system_update.commands.scan_cmd import ScanCommand
from system_update.commands.snapshot_cmd import SnapshotCommand


def test_remote_command_executes_without_system_update_app():
	args = Namespace(remote='list')
	ctx = MagicMock()

	# RemoteCommand with list action does not touch app_ctx at all
	assert RemoteCommand().execute(args, ctx) == 0


def test_snapshot_command_executes_without_system_update_app():
	args = Namespace(snapshot='list')
	ctx = MagicMock()
	with tempfile.TemporaryDirectory() as tmpdir:
		ctx.config.config_dir = Path(tmpdir)
		assert SnapshotCommand().execute(args, ctx) == 0


def test_schedule_command_executes_without_system_update_app():
	args = Namespace(schedule='list')
	ctx = MagicMock()

	# ScheduleCommand with list action calls scheduler.list_tasks()
	with patch('system_update.scheduler.list_tasks', return_value=[]):
		assert ScheduleCommand().execute(args, ctx) == 0


def test_scan_command_executes_without_system_update_app():
	args = Namespace(source='pip')
	ctx = MagicMock()
	ctx.scan_system.return_value = []

	assert ScanCommand().execute(args, ctx) == 0
	ctx.scan_system.assert_called_once_with('pip')
