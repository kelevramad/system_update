"""PyPI vulnerability scanner — queries the PyPI JSON API for known vulnerabilities."""

from __future__ import annotations

import json
import urllib.request
from typing import Dict, List

from system_update.models import AppInfo, UpdateStatus


def check(apps: List[AppInfo]) -> List[Dict]:
	"""Fetch vulnerabilities from ``pypi.org/pypi/<name>/<version>/json`` per PIP app."""
	vulns: List[Dict] = []
	unique_apps = {a.name.lower(): a for a in apps if a.source.lower() == 'pip'}

	for _, app in unique_apps.items():
		if not app.version:
			continue

		try:
			url = f'https://pypi.org/pypi/{app.name}/{app.version}/json'
			req = urllib.request.Request(url, headers={'Accept': 'application/json'})
			with urllib.request.urlopen(req, timeout=10) as resp:
				data = json.loads(resp.read().decode('utf-8'))
		except Exception:
			continue

		for vuln in data.get('vulnerabilities') or []:
			severity = (vuln.get('severity') or 'MEDIUM').upper()
			aliases = vuln.get('aliases') or []
			cve = aliases[0] if aliases else vuln.get('id', 'N/A')

			item = {
				'package': app.name,
				'severity': severity,
				'cvss_score': None,
				'cve': cve,
				'description': (vuln.get('summary') or vuln.get('details') or '')[:200],
				'source': 'PyPI',
				'fixed_in': vuln.get('fixed_in', []),
				'affected_versions': [],
				'published_date': vuln.get('published', ''),
				'advisory_url': f'https://pypi.org/project/{app.name}/{app.version}/',
			}
			app.security_findings.append(item)
			app.update_status = UpdateStatus.VULNERABLE
			vulns.append(item)

	return vulns
