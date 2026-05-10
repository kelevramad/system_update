"""Tests for the per-source command builders in ``executors/commands.py``.

Coverage focuses on Hardening 1.2.2 (no unverified remote-script execution)
and 1.2.3 (argv-token validation against tampered cache strings).
"""

from __future__ import annotations

from system_update.executors.commands import (
	_PATH_UPDATERS,
	_pwsh_updater,
	_safe_argv_token,
	build_rollback_command,
	build_update_command,
)
from system_update.models import AppInfo


# ─── Hardening 1.2.2 — no unverified remote script execution ─────────────


def test_pwsh_updater_uses_winget_not_iex():
	"""``iex (irm ...)`` must not be in the pwsh updater anymore."""
	cmd = _pwsh_updater(AppInfo(name='pwsh', source='path', version='7.4.0'))
	assert cmd[0] == 'winget'
	assert 'iex' not in ' '.join(cmd).lower()
	assert 'irm' not in ' '.join(cmd).lower()
	assert 'aka.ms' not in ' '.join(cmd).lower()
	assert '--id' in cmd
	assert 'Microsoft.PowerShell' in cmd


def test_path_updaters_have_no_remote_iex_invocation():
	"""No PATH updater may contain an ``iex (irm …)`` style fetch+exec."""
	for name, builder in _PATH_UPDATERS.items():
		cmd = builder(AppInfo(name=name, source='path', version='1.0'))
		joined = ' '.join(cmd or []).lower()
		assert 'iex ' not in joined, f'{name} updater still uses iex'
		assert 'invoke-expression' not in joined, f'{name} uses Invoke-Expression'
		assert 'irm ' not in joined and 'invoke-restmethod' not in joined, (
			f'{name} fetches a remote script'
		)


# ─── Hardening 1.2.3 — argv token validator ──────────────────────────────


def test_safe_argv_token_accepts_normal_versions():
	for ok in ('1.0', '1.0.0', '2.6.7-beta+sha.deadbeef', 'Git.Git', 'Microsoft.PowerShell'):
		assert _safe_argv_token(ok, field='x') == ok


def test_safe_argv_token_rejects_injection_payloads(caplog):
	"""Whitespace, quotes, semicolons, leading dashes, ampersands → rejected."""
	import logging

	bad = [
		'1.0 --override "& evil.exe"',
		'1.0; rm -rf /',
		"1.0' OR 1=1",
		'-v',
		'--scope=machine',
		'1.0\nnewline',
		'1.0\tinjection',
		'1.0`backtick`',
		'1.0$evil',
		'',
		None,
	]
	with caplog.at_level(logging.WARNING):
		for value in bad:
			assert _safe_argv_token(value, field='latest_version') is None


def test_winget_builder_drops_unsafe_version():
	"""Tampered cache version → argv produced without -v flag, not concatenated."""
	app = AppInfo(
		name='Pkg', source='winget', app_id='Vendor.Pkg',
		version='1.0', latest_version='1.0 --override "& evil.exe"',
	)
	cmd = build_update_command(app)
	assert cmd is not None
	# No injected flag survives.
	assert '--override' not in cmd
	assert 'evil.exe' not in cmd
	# -v flag is omitted entirely when version is unsafe.
	assert '-v' not in cmd


def test_winget_builder_drops_unsafe_app_id():
	"""Tampered app_id → builder refuses (returns None) instead of running winget."""
	app = AppInfo(
		name='Pkg', source='winget', app_id='Vendor.Pkg --rogue-flag',
		version='1.0', latest_version='1.0',
	)
	assert build_update_command(app) is None


def test_chocolatey_builder_drops_unsafe_version():
	app = AppInfo(
		name='somepkg', source='chocolatey',
		version='1.0', latest_version='1.0 --params="evil"',
	)
	cmd = build_update_command(app)
	assert cmd is not None
	assert '--params=' not in ' '.join(cmd)
	# Without a safe version, --version is dropped from the argv.
	assert '--version' not in cmd


def test_winget_rollback_drops_unsafe_tokens():
	app = AppInfo(
		name='Pkg', source='winget', app_id='Vendor.Pkg',
		version='2.0', latest_version='1.0; calc.exe',
	)
	assert build_rollback_command(app) is None


def test_appx_builder_validates_app_id():
	app = AppInfo(
		name='Some Store App', source='appx', version='1.0',
		app_id='Microsoft.WindowsCalculator_8wekyb3d8bbwe; rogue',
	)
	assert build_update_command(app) is None
