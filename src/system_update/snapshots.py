"""Snapshot storage + rollback — enhancement section 6.2.

Implements:
    6.2.1 — Version snapshots: every batch update saves the
            ``(name, source, version_before, version_after)`` tuple per package
            into a SQLite table so the prior state is recoverable.
    6.2.2 — One-click rollback: ``--rollback <id>`` (or ``--rollback last``)
            re-installs each captured ``version_before`` via the existing
            per-source command builders.
    6.2.3 — Snapshot listing: ``--snapshot list`` shows the recorded batches.

Storage lives in the existing ``history.db`` so we don't introduce a new
file. Two tables:

* ``snapshots``         — header row per batch (id, timestamp, label, counts)
* ``snapshot_packages`` — one row per package in the batch
"""

from __future__ import annotations

import itertools
import logging
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from system_update.models import AppInfo

logger = logging.getLogger(__name__)


# Hardening 2.1.1 — atomic counter for snapshot ids. itertools.count is
# thread-safe in CPython (the GIL serializes next()).
_SNAPSHOT_SEQ = itertools.count(1)


def _next_snapshot_seq() -> int:
	return next(_SNAPSHOT_SEQ)


# ─── Models ────────────────────────────────────────────────────────────────


@dataclass
class SnapshotPackage:
	"""One row in ``snapshot_packages`` — captures pre/post state of a package."""

	name: str
	source: str
	app_id: Optional[str]
	version_before: str
	version_after: str
	success: bool

	def to_appinfo(self) -> AppInfo:
		"""Reconstruct an :class:`AppInfo` for rollback (target = ``version_before``)."""
		return AppInfo(
			name=self.name,
			source=self.source,
			version=self.version_after or '',
			latest_version=self.version_before or '',
			app_id=self.app_id,
		)


@dataclass
class Snapshot:
	"""Header + body of one captured batch update."""

	id: str
	timestamp: str
	label: str
	command: str
	package_count: int
	success_count: int
	packages: List[SnapshotPackage] = field(default_factory=list)


# ─── Storage ───────────────────────────────────────────────────────────────


class SnapshotStore:
	"""SQLite-backed snapshot store reusing the project's ``history.db``."""

	def __init__(self, db_path: Optional[Path] = None) -> None:
		from system_update.utils import data_dir

		self.db_path = db_path or (data_dir() / 'history.db')
		# Hardening 2.1.1 — sqlite3.Connection is not thread-safe. Each
		# worker thread that calls _connect() gets its own connection
		# via threading.local, so concurrent rollback / snapshot writes
		# don't trip ``ProgrammingError: SQLite objects created in a
		# thread can only be used in that same thread``.
		self._tls = threading.local()
		self._schema_initialized = False
		self._schema_lock = threading.Lock()
		# Track every Connection so close() can drain them from any
		# thread (avoids ResourceWarning on GC when the opening thread
		# has already terminated).
		self._all_conns: List[sqlite3.Connection] = []
		self._all_conns_lock = threading.Lock()

	@property
	def _conn(self) -> Optional[sqlite3.Connection]:
		"""Back-compat shim: tests inspect ``store._conn``. Returns the
		current thread's connection (``None`` if it hasn't connected yet)."""
		return getattr(self._tls, 'conn', None)

	def _connect(self) -> sqlite3.Connection:
		from system_update.utils import harden_existing_file

		conn = getattr(self._tls, 'conn', None)
		if conn is not None:
			return conn

		self.db_path.parent.mkdir(exist_ok=True)
		# WAL mode lets concurrent readers coexist with one writer.
		# check_same_thread=False so close() works from any thread —
		# we still hold one Connection per thread via threading.local
		# for safety; the flag only relaxes the close() restriction.
		conn = sqlite3.connect(str(self.db_path), check_same_thread=False, timeout=30)
		conn.row_factory = sqlite3.Row
		conn.execute('PRAGMA busy_timeout=30000')
		conn.execute('PRAGMA synchronous=NORMAL')
		conn.execute('PRAGMA foreign_keys=ON')
		self._tls.conn = conn
		with self._all_conns_lock:
			self._all_conns.append(conn)

		# Schema setup runs exactly once per process (CREATE TABLE IF
		# NOT EXISTS is idempotent but the lock keeps the first-thread
		# race deterministic).
		with self._schema_lock:
			if not self._schema_initialized:
				conn.execute('PRAGMA journal_mode=WAL')
				self._ensure_schema(conn)
				self._schema_initialized = True
				# Restrict the snapshot db to the user (1.4.1) — only
				# needs to happen once, on first connect.
				harden_existing_file(self.db_path)
		return conn

	def _ensure_schema(self, conn: sqlite3.Connection) -> None:
		conn.executescript("""
			CREATE TABLE IF NOT EXISTS snapshots (
				id TEXT PRIMARY KEY,
				timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
				label TEXT,
				command TEXT,
				package_count INTEGER DEFAULT 0,
				success_count INTEGER DEFAULT 0
			);

			CREATE TABLE IF NOT EXISTS snapshot_packages (
				id INTEGER PRIMARY KEY,
				snapshot_id TEXT REFERENCES snapshots(id) ON DELETE CASCADE,
				name TEXT NOT NULL,
				source TEXT,
				app_id TEXT,
				version_before TEXT,
				version_after TEXT,
				success INTEGER DEFAULT 0
			);

			CREATE INDEX IF NOT EXISTS idx_snapshot_packages_id
				ON snapshot_packages(snapshot_id);
		""")
		conn.commit()

	# ── 6.2.1 — record ────────────────────────────────────────────────────

	def record(
		self,
		packages: List[SnapshotPackage],
		label: str = '',
		command: str = '',
	) -> str:
		"""Persist a batch as a new snapshot. Returns the snapshot id."""
		conn = self._connect()
		ts = datetime.now()
		# Hardening 2.1.1 — concurrent threads previously collided on
		# the second-resolution timestamp. Append the per-process
		# counter to keep ids unique under load while staying sortable.
		snapshot_id = (
			f'{ts.strftime("%Y%m%d-%H%M%S")}-{ts.microsecond:06d}'
			f'-{_next_snapshot_seq():03d}'
		)
		conn.execute(
			"""INSERT INTO snapshots
			   (id, timestamp, label, command, package_count, success_count)
			   VALUES (?, ?, ?, ?, ?, ?)""",
			(
				snapshot_id,
				ts.isoformat(timespec='seconds'),
				label,
				command,
				len(packages),
				sum(1 for p in packages if p.success),
			),
		)
		for p in packages:
			conn.execute(
				"""INSERT INTO snapshot_packages
				   (snapshot_id, name, source, app_id,
				    version_before, version_after, success)
				   VALUES (?, ?, ?, ?, ?, ?, ?)""",
				(
					snapshot_id, p.name, p.source, p.app_id,
					p.version_before, p.version_after, 1 if p.success else 0,
				),
			)
		conn.commit()
		return snapshot_id

	# ── 6.2.3 — list / show ───────────────────────────────────────────────

	def list_snapshots(self, limit: int = 20) -> List[Snapshot]:
		"""Return up to ``limit`` snapshot headers, newest first (no packages loaded)."""
		conn = self._connect()
		cur = conn.execute(
			'SELECT * FROM snapshots ORDER BY timestamp DESC LIMIT ?', (limit,)
		)
		return [
			Snapshot(
				id=row['id'],
				timestamp=row['timestamp'],
				label=row['label'] or '',
				command=row['command'] or '',
				package_count=row['package_count'] or 0,
				success_count=row['success_count'] or 0,
			)
			for row in cur.fetchall()
		]

	def get(self, snapshot_id: str) -> Optional[Snapshot]:
		"""Load a snapshot WITH its packages, or ``None`` if not found.

		Accepts the literal string ``'last'`` to fetch the most recent.
		"""
		conn = self._connect()
		if snapshot_id.lower() == 'last':
			cur = conn.execute(
				'SELECT * FROM snapshots ORDER BY timestamp DESC LIMIT 1'
			)
		else:
			cur = conn.execute('SELECT * FROM snapshots WHERE id = ?', (snapshot_id,))
		header = cur.fetchone()
		if not header:
			return None

		pkgs_cur = conn.execute(
			'SELECT * FROM snapshot_packages WHERE snapshot_id = ?', (header['id'],)
		)
		pkgs = [
			SnapshotPackage(
				name=p['name'],
				source=p['source'] or '',
				app_id=p['app_id'],
				version_before=p['version_before'] or '',
				version_after=p['version_after'] or '',
				success=bool(p['success']),
			)
			for p in pkgs_cur.fetchall()
		]
		return Snapshot(
			id=header['id'],
			timestamp=header['timestamp'],
			label=header['label'] or '',
			command=header['command'] or '',
			package_count=header['package_count'] or 0,
			success_count=header['success_count'] or 0,
			packages=pkgs,
		)

	def delete(self, snapshot_id: str) -> bool:
		"""Remove a snapshot + its package rows. Returns True on success."""
		conn = self._connect()
		try:
			conn.execute(
				'DELETE FROM snapshot_packages WHERE snapshot_id = ?', (snapshot_id,)
			)
			cur = conn.execute('DELETE FROM snapshots WHERE id = ?', (snapshot_id,))
			conn.commit()
			return cur.rowcount > 0
		except Exception as e:
			logger.warning(f'Failed to delete snapshot {snapshot_id}: {e}')
			return False

	def close(self) -> None:
		"""Close every Connection this store has opened, across threads.

		Connections are per-thread (threading.local), but ``close()``
		drains the bookkeeping list so a single call from any thread
		(typically the test fixture / main thread at shutdown) releases
		all of them. Without this, ``threading.local`` would hold the
		Connection until each opening thread terminates, producing
		``ResourceWarning: unclosed database`` under GC.
		"""
		with self._all_conns_lock:
			for conn in self._all_conns:
				try:
					conn.close()
				except Exception:
					pass
			self._all_conns.clear()
		if hasattr(self._tls, 'conn'):
			self._tls.conn = None

	def __enter__(self) -> 'SnapshotStore':
		self._connect()
		return self

	def __exit__(self, exc_type, exc_val, exc_tb) -> None:
		self.close()

	def __del__(self) -> None:
		"""Best-effort connection close on garbage collection.

		Closes every Connection without taking the lock — the object is
		being GC'd, no other thread will ever touch it. Avoids the
		``ResourceWarning: unclosed database`` that fires if a per-
		thread connection is still open when the parent object dies.
		"""
		try:
			conns = getattr(self, '_all_conns', None) or []
			for conn in conns:
				try:
					conn.close()
				except Exception:
					pass
			conns.clear() if isinstance(conns, list) else None
		except Exception:
			pass


# ─── Capture helper used by UpdateExecutor ─────────────────────────────────


def capture_pre_update(apps: List[AppInfo]) -> List[Dict]:
	"""Snapshot ``apps`` BEFORE updates run — keeps name/source/app_id/version pairs."""
	return [
		{
			'name': a.name,
			'source': a.source,
			'app_id': a.app_id,
			'version_before': a.version or '',
			'version_target': a.latest_version or '',
		}
		for a in apps
	]


def build_snapshot_packages(
	pre: List[Dict], results: Dict[str, bool]
) -> List[SnapshotPackage]:
	"""Combine pre-update state with post-update success map into rows.

	``results`` keys are ``f"{source}|{name}"``, lowercased.
	"""
	rows: List[SnapshotPackage] = []
	for entry in pre:
		key = f'{(entry["source"] or "").lower()}|{(entry["name"] or "").lower()}'
		ok = bool(results.get(key, False))
		rows.append(SnapshotPackage(
			name=entry['name'],
			source=entry['source'],
			app_id=entry.get('app_id'),
			version_before=entry['version_before'],
			version_after=entry['version_target'] if ok else entry['version_before'],
			success=ok,
		))
	return rows


__all__ = [
	'Snapshot',
	'SnapshotPackage',
	'SnapshotStore',
	'capture_pre_update',
	'build_snapshot_packages',
]
