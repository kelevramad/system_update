"""Historical tracking — SQLite scan history and JSON vulnerability log."""

from __future__ import annotations

import json
import logging
import sqlite3
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
		self.db_path = db_path or (Path.home() / '.system_update' / 'history.db')
		self.conn: Optional[sqlite3.Connection] = None
		if connect:
			self._connect()

	def _connect(self) -> None:
		"""Open the SQLite connection and ensure schema exists."""
		if self.conn is not None:
			return
		self.db_path.parent.mkdir(exist_ok=True)
		self.conn = sqlite3.connect(str(self.db_path))
		self.conn.row_factory = sqlite3.Row
		self._create_schema()

	def _create_schema(self) -> None:
		"""Create tables and indexes if they don't already exist."""
		self.conn.executescript("""
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
		self.conn.commit()

	def _ensure_connection(self) -> None:
		"""Lazy-open the database connection if needed."""
		if self.conn is None:
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
		"""Close the database connection if open."""
		if self.conn:
			self.conn.close()
			self.conn = None

	def __enter__(self) -> 'HistoryDatabase':
		return self

	def __exit__(self, exc_type, exc_val, exc_tb) -> None:
		self.close()

	def __del__(self) -> None:
		"""Best-effort connection close on garbage collection."""
		try:
			self.close()
		except Exception:
			pass


# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY HISTORY TRACKING
# ═══════════════════════════════════════════════════════════════════════════════


class VulnerabilityHistory:
	"""JSON-file log of discovered vulnerabilities with open/resolved status."""

	def __init__(self, history_file: Optional[Path] = None) -> None:
		self.history_file = history_file or (
			Path.home() / '.system_update' / 'vulnerability_history.json'
		)
		self.history: List[Dict] = []
		self._load()

	def _load(self) -> None:
		"""Read history JSON from disk, tolerating missing or corrupted files."""
		if not self.history_file.exists():
			return
		try:
			with open(self.history_file, 'r', encoding='utf-8') as f:
				data = json.load(f)
				self.history = data if isinstance(data, list) else []
		except Exception as e:
			logger.warning(f'Failed to load vulnerability history: {e}')
			self.history = []

	def _save(self) -> None:
		"""Write the current history list to disk."""
		try:
			self.history_file.parent.mkdir(exist_ok=True)
			with open(self.history_file, 'w', encoding='utf-8') as f:
				json.dump(self.history, f, indent=2, default=str)
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
