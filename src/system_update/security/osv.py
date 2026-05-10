"""OSV vulnerability scanner — queries the Google OSV API across ecosystems."""

from __future__ import annotations

import json
import logging
from typing import Dict, List
from urllib.error import URLError
from urllib.parse import urlparse

from system_update.models import AppInfo, UpdateStatus
from system_update.network import fetch_json
from system_update.security.common import OSV_ECOSYSTEM_MAP, score_to_severity, security_issue

logger = logging.getLogger(__name__)

_OSV_URL = 'https://api.osv.dev/v1/querybatch'


def check(apps: List[AppInfo]) -> List[Dict]:
	"""Query OSV in batches for every app whose source maps to an OSV ecosystem."""
	vulns: List[Dict] = []
	unique_apps = {a.name.lower(): a for a in apps}
	requests = []
	request_apps: List[AppInfo] = []

	for _, app in unique_apps.items():
		ecosystem = OSV_ECOSYSTEM_MAP.get(app.source.lower())
		if not ecosystem or not app.version:
			continue
		request_apps.append(app)
		requests.append(
			{
				'package': {'name': app.name, 'ecosystem': ecosystem},
				'version': app.version,
			}
		)

	if not requests:
		data: Dict = {}
	else:
		try:
			data = fetch_json(
				_OSV_URL,
				method='POST',
				payload={'queries': requests},
			)
		except (URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
			host = urlparse(_OSV_URL).netloc or 'api.osv.dev'
			message = f'OSV check skipped: {type(exc).__name__}: {exc}'
			logger.warning('OSV check failed for %s: %s', host, message)
			return [security_issue('OSV', 'error', message)]

	results = data.get('results') if isinstance(data, dict) else []
	if not isinstance(results, list):
		results = []

	for app, result in zip(request_apps, results):
		if not isinstance(result, dict):
			continue
		for vuln in result.get('vulns') or []:
			severity = 'MEDIUM'
			cvss_score = None

			if vuln.get('severity'):
				for s in vuln['severity']:
					if s.get('type') == 'cvss_v3':
						cvss_score = s.get('score')
						severity = score_to_severity(cvss_score)
						break
			elif vuln.get('database_specific', {}).get('severity'):
				severity = vuln['database_specific']['severity']

			affected_versions = []
			for affected in vuln.get('affected', []):
				for r in affected.get('ranges', []):
					introduced = None
					fixed = None
					for event in r.get('events', []):
						if event.get('introduced'):
							introduced = event['introduced']
						if event.get('fixed'):
							fixed = event['fixed']
					if introduced and fixed:
						affected_versions.append(f'{introduced} - {fixed}')
					elif introduced:
						affected_versions.append(f'< {introduced}')

			item = {
				'package': app.name,
				'severity': str(severity).upper(),
				'cvss_score': cvss_score,
				'cve': vuln.get('id', 'N/A'),
				'description': (vuln.get('summary') or '')[:200],
				'source': 'OSV',
				'affected_versions': affected_versions,
				'published_date': vuln.get('published', ''),
				'advisory_url': f'https://osv.dev/{vuln.get("id", "")}',
			}
			app.security_findings.append(item)
			app.update_status = UpdateStatus.VULNERABLE
			vulns.append(item)

	return vulns
