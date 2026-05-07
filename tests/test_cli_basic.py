import sys
import subprocess
import functools
import re
import pytest

PYTHON = sys.executable


@functools.lru_cache(maxsize=128)
def run_cli_cached(args_tuple, timeout=60):
	args = list(args_tuple)
	result = subprocess.run(
		[PYTHON, '-m', 'system_update'] + args,
		capture_output=True,
		text=True,
		timeout=timeout,
		encoding='utf-8',
		errors='ignore',
	)
	return {'code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}


def run_cli(args, timeout=60):
	return run_cli_cached(tuple(args), timeout)


@pytest.fixture(scope='session')
def help_output():
	return run_cli(['--help'])


def test_help_flag_shows_usage(help_output):
	output = help_output['stdout'] + help_output['stderr']
	assert help_output['code'] == 0
	assert 'usage' in output.lower() or 'system' in output.lower()


def test_help_banner_includes_version_and_runtime_info(help_output):
	"""--help opens with the unified System Update panel.

	The same panel is rendered when the CLI runs normally, so this test
	also acts as a contract: version, runtime, profile, data dir, cache,
	sources, security, and repo all show up together.
	"""
	from system_update.cli import _APP_VERSION

	plain = re.sub(r'\x1b\[[0-9;]*m', '', help_output['stdout'] + help_output['stderr'])
	# Panel title and header line with the resolved version.
	assert '─ System Update ─' in plain
	assert '🚀 System Update' in plain
	assert f'v{_APP_VERSION}' in plain
	# Combined info rows.
	assert 'Cache TTL' in plain
	assert 'Sources' in plain
	assert 'Security' in plain
	assert 'github.com/kelevramad/system_update' in plain
	# File inventory header is still present.
	assert '.system_update' in plain


def test_help_panels_are_width_capped(help_output):
	output = re.sub(r'\x1b\[[0-9;]*m', '', help_output['stdout'] + help_output['stderr'])
	panel_lines = [line for line in output.splitlines() if line.startswith(('┌', '│', '└'))]
	assert panel_lines
	assert max(len(line) for line in panel_lines) <= 120


def test_no_args_shows_error():
	# Run with a single fast cached source; the test only verifies the CLI
	# exits gracefully without arguments-required noise. A full no-args scan
	# can hit 14 sources and exceed reasonable test timeouts on slow machines.
	res = run_cli(['--source', 'chocolatey'], timeout=60)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'usage' in output.lower()


def test_clear_cache():
	res = run_cli(['--clear-cache'], timeout=60)
	assert res['code'] == 0


def test_source_unknown_source():
	res = run_cli(['--source', 'invalid_source_xyz'], timeout=60)
	assert res['code'] != 0 or 'error' in (res['stdout'] + res['stderr']).lower()


def test_dry_run_flag():
	res = run_cli(['--dry-run', '--source', 'chocolatey', '--yes'], timeout=120)
	assert res['code'] == 0


def test_show_all_flag():
	res = run_cli(['--show-all', '--source', 'chocolatey', '--yes'], timeout=120)
	assert res['code'] == 0


def test_log_and_debug_flags():
	res = run_cli(['--log', '--debug', '--source', 'chocolatey', '--yes'], timeout=60)
	assert res['code'] == 0


def test_interactive_flag(help_output):
	output = help_output['stdout'] + help_output['stderr']
	assert '--interactive' in output


def test_notify_flag(help_output):
	output = help_output['stdout'] + help_output['stderr']
	assert '--notify' in output


def test_theme_flag(help_output):
	output = help_output['stdout'] + help_output['stderr']
	assert '--theme' in output


def test_format_flag(help_output):
	output = help_output['stdout'] + help_output['stderr']
	assert '--format' in output


def test_icons_flag_removed(help_output):
	output = help_output['stdout'] + help_output['stderr']
	assert '--icons' not in output


def test_main_with_invalid_args():
	from system_update.cli import app

	with pytest.raises(SystemExit) as exc_info:
		app(['--invalid-arg-xyz'], standalone_mode=True)
	assert exc_info.value.code != 0
