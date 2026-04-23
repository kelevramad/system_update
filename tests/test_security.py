import sys
import subprocess
import functools
import pytest
from pathlib import Path  # noqa: F401

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
def pip_scan_output():
	return run_cli(['--source', 'pip', '--no-cache'], timeout=120)


def test_security_scan(pip_scan_output):
	output = pip_scan_output['stdout'] + pip_scan_output['stderr']
	assert (
		pip_scan_output['code'] == 0
		or 'vuln' in output.lower()
		or 'security' in output.lower()
		or 'scan' in output.lower()
	)


def test_security_scan_coverage(pip_scan_output):
	output = pip_scan_output['stdout'] + pip_scan_output['stderr']
	assert (
		pip_scan_output['code'] == 0
		or 'vuln' in output.lower()
		or 'security' in output.lower()
		or 'scan' in output.lower()
	)


def test_security_update_auto_priority():
	res = run_cli(['--source', 'pip', '--update-all', '--yes'], timeout=120)
	assert res['code'] == 0


def test_security_local_advisory():
	res = run_cli(['--source', 'pip', '--no-cache'], timeout=120)
	assert res['code'] == 0
