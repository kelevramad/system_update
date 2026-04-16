import os
import sys
import pytest
import subprocess
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).parent.parent / 'system_update.py'
PYTHON = sys.executable


def run_cli(args, timeout=60):
	result = subprocess.run(
		[PYTHON, str(SCRIPT)] + args,
		capture_output=True,
		text=True,
		timeout=timeout,
		encoding='utf-8',
		errors='ignore',
	)
	return {
		'code': result.returncode,
		'stdout': result.stdout,
		'stderr': result.stderr,
	}


def test_help_flag_shows_usage():
	res = run_cli(['--help'])
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0
	assert 'usage' in output.lower() or 'system' in output.lower()


def test_no_args_shows_error():
	res = run_cli([])
	output = res['stdout'] + res['stderr']
	assert res['code'] != 0 or 'system' in output.lower()


def test_include_winget():
	res = run_cli(['--include', 'winget', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_include_chocolatey():
	res = run_cli(['--include', 'chocolatey', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_include_npm():
	res = run_cli(['--include', 'npm', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_include_pnpm():
	res = run_cli(['--include', 'pnpm', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_include_pip():
	res = run_cli(['--include', 'pip', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_include_path():
	res = run_cli(['--include', 'path', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_include_registry():
	res = run_cli(['--include', 'registry', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_include_rust():
	res = run_cli(['--include', 'rust', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_include_scoop():
	res = run_cli(['--include', 'scoop', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_include_dotnet():
	res = run_cli(['--include', 'dotnet', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_dry_run_flag():
	res = run_cli(['--dry-run', '--include', 'path'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_show_all_flag():
	res = run_cli(['--show-all', '--include', 'path', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_export_json():
	with tempfile.TemporaryDirectory() as tmpdir:
		output_file = os.path.join(tmpdir, 'export.json')
		res = run_cli(
			['--export', 'json', '--output', output_file, '--include', 'path'], timeout=90
		)
		assert os.path.exists(output_file) or res['code'] == 0


def test_export_csv():
	with tempfile.TemporaryDirectory() as tmpdir:
		output_file = os.path.join(tmpdir, 'export.csv')
		res = run_cli(['--export', 'csv', '--output', output_file, '--include', 'path'], timeout=90)
		assert os.path.exists(output_file) or res['code'] == 0


def test_clear_cache():
	res = run_cli(['--clear-cache'])
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0
	assert 'cache' in output.lower() or 'clear' in output.lower()


def test_include_unknown_source():
	res = run_cli(['--include', 'unknown_source_xyz'])
	output = res['stdout'] + res['stderr']
	assert res['code'] != 0 or 'source' in output.lower()


def test_include_multiple_sources():
	res = run_cli(['--include', 'winget,npm', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_log_flag():
	res = run_cli(['--log', '--include', 'path', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_debug_flag():
	res = run_cli(['--debug', '--include', 'path', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()
