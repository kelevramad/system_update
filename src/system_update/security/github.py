"""GitHub Advisory Database scanner — queries ``api.github.com/advisories``.

Hardening 4.1 — queries are issued in parallel via a thread pool. The
worker count is taken from ``security.github_workers`` (default 4).
Retries and backoff on transient failures are handled inside
:func:`system_update.network.fetch_json` (Hardening 4.6).
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

from system_update.models import AppInfo, UpdateStatus
from system_update.network import fetch_json

logger = logging.getLogger(__name__)


_ECOSYSTEM_MAP = {
	'npm': 'NPM',
	'pip': 'PIP',
	'cargo': 'CARGO',
	'rubygems': 'RUBYGEMS',
	'go': 'GO',
	'nuget': 'NUGET',
}


def _github_workers() -> int:
	"""Read the configured worker count, clamped to a sane range."""
	try:
		from system_update.config import SystemConfig

		raw = SystemConfig().settings.get('security', {}).get('github_workers', 4)
		workers = int(raw)
	except Exception:
		workers = 4
	return max(1, min(workers, 16))


def _query_advisories(app: AppInfo) -> List[Dict]:
	"""Return the advisory list for ``app`` (or an empty list on failure)."""
	ecosystem = _ECOSYSTEM_MAP.get(app.source.lower())
	if not ecosystem or not app.version:
		return []
	url = f'https://api.github.com/advisories?ecosystem={ecosystem}&package={app.name}'
	try:
		data = fetch_json(
			url,
			headers={
				'Accept': 'application/vnd.github+json',
				'X-GitHub-Api-Version': '2022-11-28',
			},
		)
	except Exception as exc:
		logger.debug('GitHub Advisory query failed for %s: %s', app.name, exc)
		return []
	return list(data or [])


def _build_finding(app: AppInfo, advisory: Dict) -> Optional[Dict]:
	"""Build a finding dict for ``advisory`` if it affects ``app``."""
	affected_versions: List[str] = []
	is_affected = False
	for aff in advisory.get('affected', []) or []:
		if aff.get('package', {}).get('name', '').lower() == app.name.lower():
			versions = aff.get('vulnerable_version_range', '')
			if versions:
				is_affected = True
				affected_versions.append(versions)
				break
	if not is_affected:
		return None

	severity = (advisory.get('severity') or 'MEDIUM').upper()
	ghsa_id = advisory.get('ghsa_id', 'N/A')
	cve = advisory.get('cve_id', 'N/A')

	cvss_score = None
	cvss = advisory.get('cvss')
	if isinstance(cvss, dict):
		cvss_score = cvss.get('score') or cvss.get('cvss_v3', {}).get('score')
	if not cvss_score and advisory.get('cvssScores'):
		for entry in advisory['cvssScores']:
			if entry.get('score'):
				cvss_score = entry['score']
				break

	return {
		'package': app.name,
		'severity': severity,
		'cvss_score': cvss_score,
		'cve': cve if cve != 'N/A' else ghsa_id,
		'description': (advisory.get('description') or '')[:200],
		'source': 'GitHub Advisory',
		'ghsa_url': advisory.get('html_url', ''),
		'affected_versions': affected_versions,
		'published_date': advisory.get('published_at', ''),
		'advisory_url': advisory.get('html_url', ''),
	}


def check(apps: List[AppInfo]) -> List[Dict]:
	"""Query the GitHub Advisory Database for every app in a supported ecosystem."""
	vulns: List[Dict] = []
	unique_apps = list({a.name.lower(): a for a in apps}.values())
	candidates = [a for a in unique_apps if _ECOSYSTEM_MAP.get(a.source.lower()) and a.version]
	if not candidates:
		return vulns

	workers = min(_github_workers(), len(candidates))
	# Per-app advisory results, gathered in parallel; mutation of AppInfo
	# happens in the main thread below to keep the public surface free of
	# concurrent writes.
	results: Dict[int, List[Dict]] = {}
	with ThreadPoolExecutor(max_workers=workers) as pool:
		future_to_app = {pool.submit(_query_advisories, app): app for app in candidates}
		for future in as_completed(future_to_app):
			app = future_to_app[future]
			try:
				results[id(app)] = future.result()
			except Exception as exc:
				logger.debug('GitHub Advisory worker raised for %s: %s', app.name, exc)
				results[id(app)] = []

	for app in candidates:
		for advisory in results.get(id(app), []):
			item = _build_finding(app, advisory)
			if item is None:
				continue
			app.security_findings.append(item)
			app.update_status = UpdateStatus.VULNERABLE
			vulns.append(item)
	return vulns
