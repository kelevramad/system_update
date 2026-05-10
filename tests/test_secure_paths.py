"""Tests for Hardening 1.4 — file permissions + data_dir()."""

from __future__ import annotations

import json
import platform
import stat
from pathlib import Path
from unittest.mock import patch

import pytest

from system_update.utils import (
	data_dir,
	harden_existing_file,
	secure_write,
)


# ─── 1.4.2 — data_dir() ───────────────────────────────────────────────────


def test_data_dir_default_is_home_dot_system_update(tmp_path, monkeypatch):
	"""Default location is ``~/.system_update`` (no env override)."""
	monkeypatch.delenv('SYSTEM_UPDATE_HOME', raising=False)
	monkeypatch.setattr(Path, 'home', lambda: tmp_path)
	expected = tmp_path / '.system_update'

	got = data_dir()
	assert got == expected
	assert got.is_dir()


def test_data_dir_honors_environment_override(tmp_path, monkeypatch):
	"""``SYSTEM_UPDATE_HOME`` overrides the default location."""
	override = tmp_path / 'custom-data'
	monkeypatch.setenv('SYSTEM_UPDATE_HOME', str(override))

	got = data_dir()
	assert got == override
	assert got.is_dir()


@pytest.mark.skipif(platform.system() == 'Windows', reason='POSIX-only mode bits')
def test_data_dir_creates_with_0o700(tmp_path, monkeypatch):
	"""POSIX: created directory must not be group/other-readable."""
	monkeypatch.setenv('SYSTEM_UPDATE_HOME', str(tmp_path / 'fresh'))
	dirpath = data_dir()
	st = dirpath.stat()
	# At minimum: no group or world bits set.
	assert not (st.st_mode & (stat.S_IRWXG | stat.S_IRWXO))


def test_data_dir_idempotent(tmp_path, monkeypatch):
	monkeypatch.setenv('SYSTEM_UPDATE_HOME', str(tmp_path / 'twice'))
	a = data_dir()
	b = data_dir()
	assert a == b
	assert a.is_dir()


# ─── 1.4.1 — secure_write() ───────────────────────────────────────────────


def test_secure_write_writes_string_data(tmp_path):
	target = tmp_path / 'hello.json'
	secure_write(target, '{"k": 1}')
	assert target.read_text(encoding='utf-8') == '{"k": 1}'


def test_secure_write_writes_bytes_data(tmp_path):
	target = tmp_path / 'binary.bin'
	secure_write(target, b'\x00\x01\x02')
	assert target.read_bytes() == b'\x00\x01\x02'


def test_secure_write_creates_parent_directory(tmp_path):
	target = tmp_path / 'a' / 'b' / 'c.json'
	secure_write(target, '{}')
	assert target.is_file()
	assert target.parent.is_dir()


def test_secure_write_replaces_existing_file(tmp_path):
	target = tmp_path / 'replace.txt'
	target.write_text('old')
	secure_write(target, 'new')
	assert target.read_text(encoding='utf-8') == 'new'


def test_secure_write_does_not_leak_partial_writes(tmp_path):
	"""If write fails, the previous content remains intact."""
	target = tmp_path / 'atomic.txt'
	target.write_text('original')

	# Fail inside the context manager so os.replace is never reached.
	with patch('os.replace', side_effect=OSError('boom')):
		with pytest.raises(OSError):
			secure_write(target, 'replacement')

	assert target.read_text(encoding='utf-8') == 'original'
	# No leftover .tmp files in the directory.
	leftovers = [p for p in target.parent.glob('.atomic*.tmp') if p != target]
	assert not leftovers


@pytest.mark.skipif(platform.system() == 'Windows', reason='POSIX-only mode bits')
def test_secure_write_applies_0o600_on_posix(tmp_path):
	target = tmp_path / 'sensitive.json'
	secure_write(target, '{"secret": true}')
	mode = stat.S_IMODE(target.stat().st_mode)
	# Owner has rw, no group/other access.
	assert mode == 0o600


def test_secure_write_writes_through_data_dir_path(tmp_path, monkeypatch):
	"""Round-trip: secure_write + data_dir lands the file under the right tree."""
	monkeypatch.setenv('SYSTEM_UPDATE_HOME', str(tmp_path / 'root'))
	dirpath = data_dir()
	target = dirpath / 'subfolder' / 'thing.json'
	secure_write(target, json.dumps({'ok': True}))
	assert target.exists()
	assert json.loads(target.read_text()) == {'ok': True}


# ─── harden_existing_file (used for SQLite databases) ─────────────────────


@pytest.mark.skipif(platform.system() == 'Windows', reason='POSIX-only mode bits')
def test_harden_existing_file_chmod_0o600_posix(tmp_path):
	target = tmp_path / 'preexisting.db'
	target.write_bytes(b'\x00')
	# Start with default group/other read bits.
	target.chmod(0o644)
	harden_existing_file(target)
	assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_harden_existing_file_missing_is_noop(tmp_path):
	# Should not raise on a non-existent path.
	harden_existing_file(tmp_path / 'does-not-exist.db')


# ─── End-to-end smoke: SystemConfig + secure_write ────────────────────────


def test_systemconfig_uses_data_dir(tmp_path, monkeypatch):
	"""SystemConfig should plant config_dir at the same location as data_dir."""
	from system_update import SystemConfig

	monkeypatch.setenv('SYSTEM_UPDATE_HOME', str(tmp_path / 'audit'))
	cfg = SystemConfig()
	assert cfg.config_dir == data_dir()


def test_inventory_save_uses_secure_write(tmp_path, monkeypatch):
	from system_update.remote import Inventory, RemoteHost

	inv_path = tmp_path / 'inventory.json'
	inv = Inventory(inv_path)
	inv.add(RemoteHost(name='build01'))

	if platform.system() != 'Windows':
		mode = stat.S_IMODE(inv_path.stat().st_mode)
		assert mode == 0o600


# ─── Windows ACL hardening (icacls) ───────────────────────────────────────
#
# The mode-bit checks above are skipped on Windows because os.chmod and
# Path.mkdir(mode=...) are degenerate there. The actual security on
# Windows comes from icacls. These tests cover that path.


@pytest.mark.skipif(platform.system() != 'Windows', reason='Windows-only ACL path')
def test_secure_write_invokes_icacls_on_windows(tmp_path, monkeypatch):
	"""Unit test: secure_write must shell out to icacls with /inheritance:r.

	Mock the subprocess so the test is fast and deterministic, and assert
	the argv is the exact one that produces a per-user ACL (no inheritance,
	current user gets Full control).
	"""
	monkeypatch.setenv('USERNAME', 'testuser')

	captured = []

	def fake_run(argv, **kwargs):
		captured.append(argv)
		# Match subprocess.run's CompletedProcess shape just enough for the
		# caller to keep going.
		from types import SimpleNamespace
		return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')

	monkeypatch.setattr('system_update.utils.subprocess.run', fake_run)

	target = tmp_path / 'acl.json'
	secure_write(target, '{"x": 1}')

	# Two icacls calls: one on the temp file (before rename), one on the
	# destination as belt-and-suspenders. Both must use /inheritance:r and
	# grant the current user Full control with nothing else.
	assert len(captured) == 2, f'expected 2 icacls calls, got {len(captured)}: {captured}'
	for argv in captured:
		assert argv[0] == 'icacls'
		assert '/inheritance:r' in argv
		grant_idx = argv.index('/grant')
		assert argv[grant_idx + 1] == 'testuser:(F)'


@pytest.mark.skipif(platform.system() != 'Windows', reason='Windows-only ACL path')
def test_secure_write_windows_acl_excludes_others(tmp_path):
	"""Integration test: shell out to icacls and verify the on-disk ACL.

	Slower (one real icacls invocation per call) but proves the file is
	actually locked down rather than just that we asked for it to be.
	"""
	import getpass
	import subprocess as _sp

	target = tmp_path / 'real-acl.json'
	secure_write(target, b'\x00secret\x00')

	# Verify with icacls /q (quiet, no summary line).
	result = _sp.run(
		['icacls', str(target)],
		capture_output=True,
		text=True,
		timeout=10,
	)
	assert result.returncode == 0, f'icacls failed: {result.stderr}'
	output = result.stdout

	# Current user should appear with Full control.
	user = getpass.getuser()
	# icacls prints either "DOMAIN\\user:(F)" or just "user:(F)"; accept both.
	# Use raw strings to avoid Python interpreting \U as a unicode escape.
	assert (
		f'{user}:(F)' in output
		or rf'\{user}:(F)' in output
	), f'expected {user}:(F) in icacls output, got:\n{output}'

	# After /inheritance:r the only ACEs are explicit grants we made.
	# No "Everyone" or "BUILTIN\\Users" / "BUILTIN\\Authenticated Users"
	# should appear with any access right.
	forbidden_aces = (
		'Everyone:',
		r'BUILTIN\Users:',
		r'NT AUTHORITY\Authenticated Users:',
	)
	for forbidden in forbidden_aces:
		assert forbidden not in output, (
			f'unexpected ACE for {forbidden!r} in icacls output:\n{output}'
		)


@pytest.mark.skipif(platform.system() != 'Windows', reason='Windows-only ACL path')
def test_harden_existing_file_invokes_icacls_on_windows(tmp_path, monkeypatch):
	"""harden_existing_file must produce one icacls call per non-empty path."""
	monkeypatch.setenv('USERNAME', 'testuser')
	captured = []

	def fake_run(argv, **kwargs):
		captured.append(argv)
		from types import SimpleNamespace
		return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')

	monkeypatch.setattr('system_update.utils.subprocess.run', fake_run)

	target = tmp_path / 'pre-existing.db'
	target.write_bytes(b'\x00')
	harden_existing_file(target)

	assert len(captured) == 1
	argv = captured[0]
	assert argv[0] == 'icacls'
	assert '/inheritance:r' in argv
	grant_idx = argv.index('/grant')
	assert argv[grant_idx + 1] == 'testuser:(F)'
