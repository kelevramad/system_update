"""Global test fixtures.

Rewires ``run_command`` in every scanner/checker/executor/security submodule
so it proxies through ``system_update.run_command``. That means tests can
patch a single target (``@patch('system_update.run_command')``) and have the
mock apply everywhere, instead of the patch silently missing because each
submodule imported its own binding.

Without this, ``@patch('system_update.run_command')`` patches only the
re-exported name on the top-level package and real subprocess calls still
fire — which made mocked checker/scanner tests take 2-12s each (hitting
PyPI, winget, etc.).
"""

from __future__ import annotations

import functools
import importlib
import subprocess
import sys

import pytest

import system_update as _su


# ---------------------------------------------------------------------------
# Shared CLI helpers (used by test_sources / test_security / test_cli_basic)
# ---------------------------------------------------------------------------

_PYTHON = sys.executable


@functools.lru_cache(maxsize=256)
def _run_cli_cached(args_tuple, timeout=60):
	"""Cache real CLI invocations by argv tuple so identical calls across test
	files run the subprocess only once per session."""
	result = subprocess.run(
		[_PYTHON, '-m', 'system_update'] + list(args_tuple),
		capture_output=True,
		text=True,
		timeout=timeout,
		encoding='utf-8',
		errors='ignore',
	)
	return {'code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}


@pytest.fixture(scope='session')
def cli_runner():
	"""Fixture returning a callable that runs the CLI with shared result cache."""

	def _run(args, timeout=60):
		return _run_cli_cached(tuple(args), timeout)

	return _run


@pytest.fixture(scope='session')
def seeded_cache(cli_runner):
	"""One real ``--no-cache`` scan across every source integration tests read.

	Subsequent calls without ``--no-cache`` hit the JSON cache on disk and
	return in <1s, so the slow scan cost is paid exactly once per session.
	"""
	return cli_runner(
		['--source', 'winget,npm,chocolatey,pip', '--no-cache'], timeout=240
	)

# Every submodule that does ``from system_update.utils import run_command``.
_SUBMODULES = [
	# checkers
	'system_update.checkers.winget',
	'system_update.checkers.chocolatey',
	'system_update.checkers.npm',
	'system_update.checkers.pnpm',
	'system_update.checkers.bun',
	'system_update.checkers.yarn',
	'system_update.checkers.pip',
	'system_update.checkers.path',
	'system_update.checkers.registry',
	'system_update.checkers.rust',
	'system_update.checkers.scoop',
	'system_update.checkers.dotnet',
	'system_update.checkers._npm_registry',
	# scanners
	'system_update.scanners.bun',
	'system_update.scanners.chocolatey',
	'system_update.scanners.dotnet',
	'system_update.scanners.npm',
	'system_update.scanners.path',
	'system_update.scanners.pip',
	'system_update.scanners.pnpm',
	'system_update.scanners.registry',
	'system_update.scanners.rust',
	'system_update.scanners.scoop',
	'system_update.scanners.winget',
	'system_update.scanners.yarn',
	'system_update.scanners._appx_common',
	# executors + security
	'system_update.executors',
	'system_update.security.npm',
	'system_update.security.pip',
]


def _proxy(*args, **kwargs):
	"""Call whatever ``system_update.run_command`` points to right now.

	This is how ``@patch('system_update.run_command')`` reaches callers that
	did ``from system_update.utils import run_command`` — the lookup happens
	at call time, not at import time.
	"""
	return _su.run_command(*args, **kwargs)


@pytest.fixture(autouse=True, scope='session')
def _rewire_run_command():
	"""Replace the per-submodule ``run_command`` binding with a late-bound proxy."""
	originals = {}
	for name in _SUBMODULES:
		try:
			mod = importlib.import_module(name)
		except Exception:
			continue
		if hasattr(mod, 'run_command'):
			originals[name] = mod.run_command
			mod.run_command = _proxy
	yield
	for name, original in originals.items():
		try:
			mod = importlib.import_module(name)
			mod.run_command = original
		except Exception:
			pass


@pytest.fixture(autouse=True)
def _stub_run_command_default(monkeypatch, request):
	"""Default-stub ``system_update.run_command`` to return '' so tests that
	don't explicitly mock don't accidentally hit real subprocess calls.

	Tests using ``@patch('system_update.run_command')`` still work — the patch
	is applied AFTER this fixture, so their mock overrides the stub.

	Opt-out via ``@pytest.mark.real_run_command`` when a test genuinely wants
	to exercise real commands (e.g. the subprocess-based integration tests in
	``test_security.py`` / ``test_sources.py`` already spawn their own
	subprocesses, so this fixture doesn't affect them).
	"""
	if request.node.get_closest_marker('real_run_command'):
		yield
		return
	monkeypatch.setattr('system_update.run_command', lambda *a, **kw: '')
	yield
