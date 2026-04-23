"""PIP vulnerability scanner — parses ``pip-audit`` JSON output."""

from __future__ import annotations

import json
from typing import Dict, List

from system_update.models import AppInfo, UpdateStatus
from system_update.utils import run_command


def check(apps: List[AppInfo]) -> List[Dict]:
	"""Run ``pip-audit -f json`` and append findings to matching :class:`AppInfo` records."""
	vulns: List[Dict] = []
	pip_apps = [a for a in apps if a.source.lower() == 'pip']
	if not pip_apps:
		return vulns

	out = run_command(['pip-audit', '-o', '-', '-f', 'json'], allow_failure=True)
	if not out:
		return vulns

	try:
		data = json.loads(out)
	except Exception:
		return vulns

	for dep in data.get('dependencies', []):
		pkg_name = dep.get('name', '')
		if not pkg_name:
			continue
		app = next((a for a in pip_apps if a.name.lower() == pkg_name.lower()), None)
		if not app:
			continue

		for vuln in dep.get('vulns', []):
			cve = vuln.get('id', 'N/A')
			aliases = vuln.get('aliases', [])
			if aliases and cve == 'N/A':
				cve = aliases[0]

			item = {
				'package': app.name,
				'severity': 'MEDIUM',
				'cvss_score': vuln.get('cvss_score') or vuln.get('score'),
				'cve': cve,
				'description': vuln.get('description', 'Security vulnerability'),
				'affected_versions': vuln.get('affected_versions', []),
				'published_date': vuln.get('published_date', ''),
				'advisory_url': vuln.get('advisory_url', ''),
				'fix_available': vuln.get('fix_available', False),
			}
			app.security_findings.append(item)
			app.update_status = UpdateStatus.VULNERABLE
			vulns.append(item)

	return vulns
