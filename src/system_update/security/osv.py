"""OSV vulnerability scanner — queries the Google OSV API across ecosystems."""

from __future__ import annotations

import json
import urllib.request
from typing import Dict, List

from system_update.models import AppInfo, UpdateStatus
from system_update.security.common import OSV_ECOSYSTEM_MAP, score_to_severity


def check(apps: List[AppInfo]) -> List[Dict]:
	"""Query ``api.osv.dev/v1/query`` for every app whose source maps to an OSV ecosystem."""
	vulns: List[Dict] = []
	unique_apps = {a.name.lower(): a for a in apps}

	for _, app in unique_apps.items():
		ecosystem = OSV_ECOSYSTEM_MAP.get(app.source.lower())
		if not ecosystem or not app.version:
			continue

		payload = {
			'package': {'name': app.name, 'ecosystem': ecosystem},
			'version': app.version,
		}

		try:
			req = urllib.request.Request(
				'https://api.osv.dev/v1/query',
				data=json.dumps(payload).encode('utf-8'),
				headers={'Content-Type': 'application/json'},
			)
			with urllib.request.urlopen(req, timeout=10) as resp:
				data = json.loads(resp.read().decode('utf-8'))
		except Exception:
			continue

		for vuln in data.get('vulns') or []:
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
