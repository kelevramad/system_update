"""NPM vulnerability scanner — parses ``npm audit --json`` output."""

from __future__ import annotations

import json
import logging
from typing import Dict, List

from system_update.models import AppInfo, UpdateStatus
from system_update.utils import run_command

logger = logging.getLogger(__name__)


def check(apps: List[AppInfo]) -> List[Dict]:
	"""Run ``npm audit`` and append findings to matching :class:`AppInfo` records."""
	vulns: List[Dict] = []
	out = run_command(['npm', 'audit', '--json', '--silent'], allow_failure=True)
	if not out:
		return vulns

	try:
		data = json.loads(out)
	except Exception:
		return vulns

	for name, details in (data.get('vulnerabilities') or {}).items():
		app = next((a for a in apps if a.name.lower() == name.lower()), None)
		if not app:
			continue

		severity = (details.get('severity') or 'low').upper()
		cve = 'N/A'
		description = 'Vulnerability found'
		advisory_url = ''
		cvss_score = None
		via = details.get('via') or []

		if via:
			first = via[0]
			if isinstance(first, dict):
				cve = first.get('id') or first.get('cve') or 'N/A'
				description = first.get('title') or first.get('url') or 'Vulnerability found'
				advisory_url = first.get('url') or ''
				if first.get('severity'):
					severity = first['severity'].upper()
				cvss_score = first.get('cvss') or first.get('score')
			elif isinstance(first, str):
				description = f'Via: {first}'

		fix_available = details.get('fixAvailable') is True or isinstance(
			details.get('fixAvailable'), dict
		)

		item = {
			'package': name,
			'severity': severity,
			'cvss_score': cvss_score,
			'cve': cve,
			'description': description,
			'advisory_url': advisory_url,
			'fix_available': fix_available,
			'is_direct': details.get('isDirect', False),
			'effects': details.get('effects', []),
			'affected_versions': [],
			'published_date': None,
		}
		app.security_findings.append(item)
		app.update_status = UpdateStatus.VULNERABLE
		vulns.append(item)

	metadata = data.get('metadata', {}).get('vulnerabilities', {})
	if metadata:
		logger.info(
			'npm audit: total=%d critical=%d high=%d moderate=%d low=%d',
			metadata.get('total', 0),
			metadata.get('critical', 0),
			metadata.get('high', 0),
			metadata.get('moderate', 0),
			metadata.get('low', 0),
		)

	return vulns
