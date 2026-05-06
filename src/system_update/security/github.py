"""GitHub Advisory Database scanner — queries ``api.github.com/advisories``."""

from __future__ import annotations

from typing import Dict, List

from system_update.models import AppInfo, UpdateStatus
from system_update.network import fetch_json


_ECOSYSTEM_MAP = {
	'npm': 'NPM',
	'pip': 'PIP',
	'cargo': 'CARGO',
	'rubygems': 'RUBYGEMS',
	'go': 'GO',
	'nuget': 'NUGET',
}


def check(apps: List[AppInfo]) -> List[Dict]:
	"""Query the GitHub Advisory Database for every app in a supported ecosystem."""
	vulns: List[Dict] = []
	unique_apps = {a.name.lower(): a for a in apps}

	for _, app in unique_apps.items():
		ecosystem = _ECOSYSTEM_MAP.get(app.source.lower())
		if not ecosystem or not app.version:
			continue

		try:
			url = f'https://api.github.com/advisories?ecosystem={ecosystem}&package={app.name}'
			data = fetch_json(
				url,
				headers={
					'Accept': 'application/vnd.github+json',
					'X-GitHub-Api-Version': '2022-11-28',
				},
			)
		except Exception:
			continue

		for advisory in data or []:
			affected_versions = []
			is_affected = False
			for aff in advisory.get('affected', []) or []:
				if aff.get('package', {}).get('name', '').lower() == app.name.lower():
					versions = aff.get('vulnerable_version_range', '')
					if versions:
						is_affected = True
						affected_versions.append(versions)
						break
			if not is_affected:
				continue

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

			item = {
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
			app.security_findings.append(item)
			app.update_status = UpdateStatus.VULNERABLE
			vulns.append(item)

	return vulns
