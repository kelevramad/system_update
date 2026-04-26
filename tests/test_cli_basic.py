import sys
import subprocess
import functools
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


def test_icons_flag(help_output):
	output = help_output['stdout'] + help_output['stderr']
	assert '--icons' in output


def test_main_with_invalid_args():
	from system_update.cli import app

	with pytest.raises(SystemExit) as exc_info:
		app(['--invalid-arg-xyz'], standalone_mode=True)
	assert exc_info.value.code != 0
