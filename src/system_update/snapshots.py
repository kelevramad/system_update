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

import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from system_update.config import data_dir
from system_update.models import AppInfo

logger = logging.getLogger(__name__)


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
		self.db_path = db_path or (data_dir() / 'history.db')
		self._conn: Optional[sqlite3.Connection] = None

	def _connect(self) -> sqlite3.Connection:
		if self._conn is None:
			self.db_path.parent.mkdir(exist_ok=True)
			self._conn = sqlite3.connect(str(self.db_path))
			self._conn.row_factory = sqlite3.Row
			self._ensure_schema()
		return self._conn

	def _ensure_schema(self) -> None:
		self._conn.executescript("""
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
		self._conn.commit()

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
		snapshot_id = ts.strftime('%Y%m%d-%H%M%S')
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
		if self._conn is not None:
			self._conn.close()
			self._conn = None

	def __enter__(self) -> 'SnapshotStore':
		self._connect()
		return self

	def __exit__(self, exc_type, exc_val, exc_tb) -> None:
		self.close()

	def __del__(self) -> None:
		"""Best-effort connection close on garbage collection."""
		try:
			self.close()
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
