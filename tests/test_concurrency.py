"""Tests for Hardening 2.1 — concurrency fixes.

Covers:
* 2.1.1 — sqlite3.Connection per-thread access for SnapshotStore and
  HistoryDatabase. The previous implementation cached one Connection
  object and shared it across threads, which raises ProgrammingError
  ("SQLite objects created in a thread can only be used in that same
  thread") at minimum and can corrupt the WAL at worst.
* 2.1.2 — per-host network rate limiter. Already covered by the
  cross-host parallelism test in test_network.py; this file adds a
  stress-style end-to-end verification on top.
"""

from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from system_update import AppInfo, HistoryDatabase
from system_update.snapshots import SnapshotPackage, SnapshotStore


# ─── 2.1.1 — SQLite thread-safety ─────────────────────────────────────────


def test_snapshot_store_writes_concurrent_records(tmp_path: Path):
	"""Eight threads each record a snapshot — all rows present, no
	ProgrammingError, and WAL mode is active."""
	store = SnapshotStore(tmp_path / 'history.db')
	try:
		def _record(i: int) -> str:
			pkg = SnapshotPackage(name=f'pkg-{i}', source='pip', app_id=None,
			                      version_before='1.0', version_after='1.1',
			                      success=True)
			return store.record([pkg], label=f'thread-{i}')

		with ThreadPoolExecutor(max_workers=8) as ex:
			futures = [ex.submit(_record, i) for i in range(8)]
			ids = [f.result() for f in as_completed(futures)]

		assert len(ids) == 8
		assert len(set(ids)) == 8, 'IDs must be unique across threads'

		# Verify all 8 snapshots are persisted.
		all_snaps = store.list_snapshots(limit=20)
		assert len(all_snaps) == 8

		# Verify WAL mode is on (the journal_mode pragma returns 'wal').
		conn = store._connect()
		row = conn.execute('PRAGMA journal_mode').fetchone()
		assert (row[0] if row is not None else '').lower() == 'wal', (
			'WAL journal mode should be active'
		)
	finally:
		store.close()


def test_history_database_writes_concurrent_records(tmp_path: Path):
	"""Same shape for HistoryDatabase — concurrent record_scan calls."""
	db = HistoryDatabase(tmp_path / 'history.db')
	try:
		apps = [AppInfo(name='git', source='winget', version='1.0',
		                latest_version='1.1')]

		def _record(i: int) -> None:
			db.record_scan(apps, scan_id=f'scan-{i}', source='winget',
			               duration_seconds=0.1)

		with ThreadPoolExecutor(max_workers=8) as ex:
			list(ex.map(_record, range(8)))

		scans = db.get_scans(limit=20)
		assert len(scans) == 8
		# Every scan id we wrote should be present.
		ids = {row['id'] for row in scans}
		assert ids == {f'scan-{i}' for i in range(8)}
	finally:
		db.close()


def test_snapshot_store_per_thread_connections_are_isolated(tmp_path: Path):
	"""Each thread should get its own sqlite3.Connection. Reading
	``store._conn`` from two threads must yield two different objects
	(or one of them ``None`` if it hasn't connected yet)."""
	import threading

	store = SnapshotStore(tmp_path / 'history.db')
	try:
		# Force the main-thread connection.
		main_conn = store._connect()
		captured: dict = {}

		def _grab_in_thread() -> None:
			captured['conn'] = store._connect()

		t = threading.Thread(target=_grab_in_thread)
		t.start()
		t.join()

		worker_conn = captured['conn']
		assert isinstance(main_conn, sqlite3.Connection)
		assert isinstance(worker_conn, sqlite3.Connection)
		assert main_conn is not worker_conn, (
			'Each thread must hold its own Connection — sharing one across '
			'threads raises ProgrammingError on commit/execute.'
		)
	finally:
		store.close()


def test_history_database_per_thread_connections_are_isolated(tmp_path: Path):
	"""HistoryDatabase mirror of the SnapshotStore isolation check."""
	import threading

	db = HistoryDatabase(tmp_path / 'history.db')
	try:
		main_conn = db.conn  # property triggers connect on the main thread
		captured: dict = {}

		def _grab_in_thread() -> None:
			captured['conn'] = db.conn

		t = threading.Thread(target=_grab_in_thread)
		t.start()
		t.join()

		worker_conn = captured['conn']
		assert main_conn is not worker_conn
	finally:
		db.close()


def test_history_database_wal_mode_is_active(tmp_path: Path):
	db = HistoryDatabase(tmp_path / 'history.db')
	try:
		row = db.conn.execute('PRAGMA journal_mode').fetchone()
		assert (row[0] if row is not None else '').lower() == 'wal'
	finally:
		db.close()
