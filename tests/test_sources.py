import sys
import subprocess
import functools
import pytest
from pathlib import Path

SCRIPT = Path(__file__).parent.parent / 'system_update.py'
PYTHON = sys.executable

@functools.lru_cache(maxsize=128)
def run_cli_cached(args_tuple, timeout=60):
    args = list(args_tuple)
    result = subprocess.run(
        [PYTHON, str(SCRIPT)] + args,
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
def choco_scan_output():
    return run_cli(['--source', 'chocolatey', '--no-cache'], timeout=120)

@pytest.fixture(scope='session')
def pip_scan_output():
    return run_cli(['--source', 'pip', '--no-cache'], timeout=120)

@pytest.mark.parametrize('source', ['winget', 'npm', 'chocolatey'])
def test_source_scan(source):
    res = run_cli(['--source', source], timeout=120)
    assert res['code'] == 0

def test_source_chocolatey(choco_scan_output):
    assert choco_scan_output['code'] == 0

def test_source_pip(pip_scan_output):
    assert pip_scan_output['code'] == 0

def test_source_multiple_sources():
    res = run_cli(['--source', 'chocolatey,pip', '--no-cache'], timeout=180)
    assert res['code'] == 0