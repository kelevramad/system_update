"""Historical tracking — SQLite scan history and JSON vulnerability log."""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

from system_update.models import AppInfo

logger = logging.getLogger(__name__)


class HistoryDatabase:
	"""SQLite-backed history of scans, package snapshots, and version changes.

	Tables:
		* ``scans`` — one row per scan run (id, timestamp, counts, duration)
		* ``package_snapshots`` — every ``AppInfo`` observed in a scan
		* ``version_history`` — unique (package, source, version) observations
	"""

	def __init__(self, db_path: Optional[Path] = None, connect: bool = True) -> None:
		from system_update.utils import data_dir

		self.db_path = db_path or (data_dir() / 'history.db')
		# Hardening 2.1.1 — sqlite3.Connection is not thread-safe. Use
		# threading.local so every worker thread gets its own connection
		# (the underlying file is shared via WAL).
		self._tls = threading.local()
		self._schema_initialized = False
		self._schema_lock = threading.Lock()
		# Track every Connection we hand out so close() can drain them
		# from the main thread regardless of which thread opened them.
		# Without this, ResourceWarning "unclosed database" fires on GC.
		self._all_conns: List[sqlite3.Connection] = []
		self._all_conns_lock = threading.Lock()
		if connect:
			self._connect()

	def _connect(self) -> None:
		"""Open the SQLite connection and ensure schema exists."""
		from system_update.utils import harden_existing_file

		conn = getattr(self._tls, 'conn', None)
		if conn is not None:
			return
		self.db_path.parent.mkdir(exist_ok=True)
		# check_same_thread=False so close() can be called from a thread
		# other than the opening one (test fixtures, __del__ from main).
		# We still hold one Connection per thread (threading.local) for
		# safety; the flag only relaxes the close() restriction.
		conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
		conn.row_factory = sqlite3.Row
		conn.execute('PRAGMA journal_mode=WAL')
		conn.execute('PRAGMA synchronous=NORMAL')
		conn.execute('PRAGMA foreign_keys=ON')
		self._tls.conn = conn
		with self._all_conns_lock:
			self._all_conns.append(conn)

		# Schema is created exactly once per process; subsequent threads
		# skip it (CREATE TABLE IF NOT EXISTS is idempotent but skipping
		# avoids an extra round-trip on every new thread).
		with self._schema_lock:
			if not self._schema_initialized:
				self._create_schema(conn)
				self._schema_initialized = True
				# Hardening 1.4.1 — restrict the db file to the user.
				harden_existing_file(self.db_path)

	@property
	def conn(self) -> sqlite3.Connection:
		"""Per-thread lazy-connecting accessor.

		Each thread gets its own ``sqlite3.Connection`` via
		``threading.local``; the underlying database file is shared
		(WAL journal mode allows concurrent readers + one writer).
		"""
		conn = getattr(self._tls, 'conn', None)
		if conn is None:
			self._connect()
			conn = self._tls.conn
		return conn

	@property
	def _conn(self) -> Optional[sqlite3.Connection]:
		"""Back-compat accessor — tests inspect ``hd._conn`` to check
		whether the current thread has connected. Returns ``None`` if
		not yet connected, the live ``Connection`` otherwise."""
		return getattr(self._tls, 'conn', None)

	def _create_schema(self, conn: sqlite3.Connection) -> None:
		"""Create tables and indexes if they don't already exist."""
		conn.executescript("""
			CREATE TABLE IF NOT EXISTS scans (
				id TEXT PRIMARY KEY,
				timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
				source TEXT,
				package_count INTEGER DEFAULT 0,
				update_count INTEGER DEFAULT 0,
				vulnerability_count INTEGER DEFAULT 0,
				duration_seconds REAL DEFAULT 0
			);

			CREATE TABLE IF NOT EXISTS package_snapshots (
				id INTEGER PRIMARY KEY,
				scan_id TEXT REFERENCES scans(id),
				name TEXT NOT NULL,
				source TEXT,
				version TEXT,
				latest_version TEXT,
				update_status TEXT,
				has_vulnerability INTEGER DEFAULT 0
			);

			CREATE INDEX IF NOT EXISTS idx_snapshots_scan ON package_snapshots(scan_id);
			CREATE INDEX IF NOT EXISTS idx_snapshots_name ON package_snapshots(name, source);

			CREATE TABLE IF NOT EXISTS version_history (
				id INTEGER PRIMARY KEY,
				package_name TEXT NOT NULL,
				source TEXT,
				version TEXT NOT NULL,
				timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
				change_type TEXT DEFAULT 'seen'
			);

			CREATE INDEX IF NOT EXISTS idx_version_name ON version_history(package_name, source);
		""")
		conn.commit()

	def _ensure_connection(self) -> None:
		"""Lazy-open the database connection if needed.

		Kept for backward compatibility — accessing ``self.conn`` already
		triggers the lazy connect via the property.
		"""
		if self._conn is None:
			self._connect()

	def record_scan(
		self,
		apps: List[AppInfo],
		scan_id: str,
		source: str,
		duration_seconds: float,
	) -> None:
		"""Persist a complete scan session — header row plus one snapshot per app."""
		self._ensure_connection()
		update_count = sum(1 for a in apps if a.has_update)
		vuln_count = sum(1 for a in apps if a.is_vulnerable)

		self.conn.execute(
			"""INSERT INTO scans
			   (id, source, package_count, update_count, vulnerability_count, duration_seconds)
			   VALUES (?, ?, ?, ?, ?, ?)""",
			(scan_id, source, len(apps), update_count, vuln_count, duration_seconds),
		)

		for app in apps:
			self.conn.execute(
				"""INSERT INTO package_snapshots
				   (scan_id, name, source, version, latest_version, update_status,
				    has_vulnerability)
				   VALUES (?, ?, ?, ?, ?, ?, ?)""",
				(
					scan_id,
					app.name,
					app.source,
					app.version,
					app.latest_version,
					app.update_status.value,
					1 if app.is_vulnerable else 0,
				),
			)

			self.conn.execute(
				"""INSERT OR IGNORE INTO version_history
				   (package_name, source, version, change_type)
				   VALUES (?, ?, ?, 'seen')""",
				(app.name, app.source, app.version),
			)

		self.conn.commit()

	def get_scans(self, limit: int = 10) -> List[Dict]:
		"""Return up to ``limit`` most recent scan header rows."""
		self._ensure_connection()
		cursor = self.conn.execute('SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?', (limit,))
		return [dict(row) for row in cursor.fetchall()]

	def get_package_history(self, package_name: str, source: Optional[str] = None) -> List[Dict]:
		"""Return the version-history rows for a given package (optionally per source)."""
		self._ensure_connection()
		if source:
			cursor = self.conn.execute(
				"""SELECT * FROM version_history
				   WHERE package_name = ? AND source = ?
				   ORDER BY timestamp DESC""",
				(package_name, source),
			)
		else:
			cursor = self.conn.execute(
				"""SELECT * FROM version_history
				   WHERE package_name = ?
				   ORDER BY timestamp DESC""",
				(package_name,),
			)
		return [dict(row) for row in cursor.fetchall()]

	def get_update_trends(self, days: int = 30) -> Dict:
		"""Aggregate scan counts / update counts per source over the last ``days``."""
		self._ensure_connection()
		cursor = self.conn.execute(
			"""SELECT source,
					  COUNT(*) as total_scans,
					  SUM(package_count) as total_packages,
					  SUM(update_count) as total_updates
			   FROM scans
			   WHERE timestamp >= datetime('now', '-' || ? || ' days')
			   GROUP BY source""",
			(days,),
		)
		sources = [dict(row) for row in cursor.fetchall()]

		cursor = self.conn.execute(
			"""SELECT COUNT(DISTINCT package_name) as package_count
			   FROM version_history
			   WHERE timestamp >= datetime('now', '-' || ? || ' days')""",
			(days,),
		)
		unique_packages = cursor.fetchone()[0]

		return {
			'period_days': days,
			'source_stats': sources,
			'unique_packages': unique_packages,
		}

	def get_stale_packages(self, days: int = 90) -> List[Dict]:
		"""Return packages whose most recent ``version_history`` row is older than ``days``."""
		self._ensure_connection()
		cursor = self.conn.execute(
			"""SELECT package_name, source, MAX(timestamp) as last_seen
			   FROM version_history
			   WHERE timestamp < datetime('now', '-' || ? || ' days')
			   GROUP BY package_name, source
			   ORDER BY last_seen""",
			(days,),
		)
		return [dict(row) for row in cursor.fetchall()]

	def get_source_distribution(self) -> Dict:
		"""Return a dict of ``{source: package_count}`` for the most recent scan."""
		self._ensure_connection()
		cursor = self.conn.execute(
			"""SELECT source, COUNT(*) as count
			   FROM package_snapshots
			   WHERE scan_id = (SELECT id FROM scans ORDER BY timestamp DESC LIMIT 1)
			   GROUP BY source""",
		)
		return {row['source']: row['count'] for row in cursor.fetchall()}

	def close(self) -> None:
		"""Close every Connection this instance has opened, across threads.

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
		# Drop the current thread's TLS reference so a subsequent call
		# on this instance reopens a fresh connection.
		if hasattr(self._tls, 'conn'):
			self._tls.conn = None

	def __enter__(self) -> 'HistoryDatabase':
		return self

	def __exit__(self, exc_type, exc_val, exc_tb) -> None:
		self.close()

	def __del__(self) -> None:
		"""Best-effort connection close on garbage collection.

		Closes every Connection without taking the lock — the object is
		being GC'd, no other thread will ever touch it. Avoids the
		``ResourceWarning: unclosed database`` that fires if any per-
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


# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY HISTORY TRACKING
# ═══════════════════════════════════════════════════════════════════════════════


class VulnerabilityHistory:
	"""JSON-file log of discovered vulnerabilities with open/resolved status."""

	def __init__(self, history_file: Optional[Path] = None) -> None:
		from system_update.utils import data_dir

		self.history_file = history_file or (data_dir() / 'vulnerability_history.json')
		self.history: List[Dict] = []
		self._load()

	def _load(self) -> None:
		"""Read history JSON from disk, tolerating missing or corrupted files.

		On corruption: rename the bad file to ``<name>.corrupt-<ts>.bak`` so
		the user can inspect it manually, then start with an empty history.
		The next ``_save`` will write a fresh, valid file.
		"""
		if not self.history_file.exists():
			return
		try:
			with open(self.history_file, 'r', encoding='utf-8') as f:
				data = json.load(f)
				self.history = data if isinstance(data, list) else []
		except Exception as e:
			ts = datetime.now().strftime('%Y%m%d-%H%M%S')
			backup = self.history_file.with_name(
				f'{self.history_file.stem}.corrupt-{ts}.bak'
			)
			try:
				self.history_file.rename(backup)
				logger.warning(
					f'Vulnerability history corrupt ({e}); '
					f'moved to {backup.name} and starting fresh.'
				)
			except Exception as rename_err:
				logger.warning(
					f'Vulnerability history corrupt ({e}); '
					f'could not back up ({rename_err}). Starting fresh.'
				)
			self.history = []

	def _save(self) -> None:
		"""Write the current history list to disk."""
		try:
			from system_update.utils import secure_write

			secure_write(
				self.history_file,
				json.dumps(self.history, indent=2, default=str),
			)
		except Exception as e:
			logger.error(f'Failed to save vulnerability history: {e}')

	def record_vulnerability(self, app: AppInfo, vuln: Dict, scan_id: str) -> None:
		"""Append a new vulnerability record with status=``open`` and save."""
		now_iso = datetime.now().isoformat()
		record = {
			'id': f'vuln-{len(self.history) + 1:06d}',
			'timestamp': now_iso,
			'scan_id': scan_id,
			'package_name': app.name,
			'package_source': app.source,
			'package_version': app.version,
			'cve': vuln.get('cve', 'N/A'),
			'severity': vuln.get('severity', 'UNKNOWN'),
			'cvss_score': vuln.get('cvss_score'),
			'description': vuln.get('description', ''),
			'affected_versions': vuln.get('affected_versions', []),
			'published_date': vuln.get('published_date'),
			'advisory_url': vuln.get('advisory_url', ''),
			'fix_available': vuln.get('fix_available', False),
			'status': 'open',
			'first_seen': now_iso,
			'last_seen': now_iso,
			'resolved_date': None,
		}
		self.history.append(record)
		self._save()

	def mark_resolved(self, app_name: str, cve: Optional[str] = None) -> int:
		"""Mark open vulnerabilities as resolved; returns number updated.

		If ``cve`` is None every open vulnerability for ``app_name`` is resolved;
		otherwise only matching records are.
		"""
		updated = 0
		for record in self.history:
			if (
				record.get('package_name', '').lower() == app_name.lower()
				and record.get('status') == 'open'
				and (cve is None or record.get('cve') == cve)
			):
				record['status'] = 'resolved'
				record['resolved_date'] = datetime.now().isoformat()
				updated += 1
		if updated:
			self._save()
		return updated

	def get_statistics(self) -> Dict:
		"""Aggregate severity counts and persistence heuristics for the history."""
		if not self.history:
			return {
				'total_vulnerabilities': 0,
				'open_vulnerabilities': 0,
				'resolved_vulnerabilities': 0,
				'severity_breakdown': {},
				'critical_count': 0,
				'high_count': 0,
				'medium_count': 0,
				'low_count': 0,
				'packages_affected': 0,
				'persistent_vulnerabilities': 0,
			}

		open_vulns = [r for r in self.history if r.get('status') == 'open']
		resolved_vulns = [r for r in self.history if r.get('status') == 'resolved']

		severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
		for v in open_vulns:
			sev = v.get('severity', 'UNKNOWN').upper()
			severity_counts[sev if sev in severity_counts else 'UNKNOWN'] += 1

		open_packages = {v.get('package_name', '') for v in open_vulns}

		# A vulnerability is "persistent" if it appears in 3+ distinct scans.
		vuln_keys: Dict[tuple, set] = {}
		for v in self.history:
			if v.get('status') == 'open':
				key = (v.get('package_name', ''), v.get('cve', ''))
				vuln_keys.setdefault(key, set()).add(v.get('scan_id', ''))
		persistent = sum(1 for scans in vuln_keys.values() if len(scans) >= 3)

		return {
			'total_vulnerabilities': len(self.history),
			'open_vulnerabilities': len(open_vulns),
			'resolved_vulnerabilities': len(resolved_vulns),
			'severity_breakdown': severity_counts,
			'critical_count': severity_counts['CRITICAL'],
			'high_count': severity_counts['HIGH'],
			'medium_count': severity_counts['MEDIUM'],
			'low_count': severity_counts['LOW'],
			'packages_affected': len(open_packages),
			'persistent_vulnerabilities': persistent,
		}

	def get_vulnerability_trends(self, days: int = 30) -> Dict[str, int]:
		"""Return a mapping of ``YYYY-MM-DD`` → new-vuln count for the last ``days``."""
		cutoff = datetime.now() - timedelta(days=days)
		trends: Dict[str, int] = {}
		for record in self.history:
			try:
				ts = datetime.fromisoformat(record.get('timestamp', '').replace('Z', '+00:00'))
				if ts < cutoff:
					continue
				date_str = ts.strftime('%Y-%m-%d')
				trends[date_str] = trends.get(date_str, 0) + 1
			except Exception:
				continue
		return trends

	def clear(self) -> None:
		"""Delete every vulnerability record (and persist the empty list)."""
		self.history = []
		self._save()
