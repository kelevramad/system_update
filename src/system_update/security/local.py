"""Local advisory loader + matcher for user-provided vulnerability data."""

from __future__ import annotations

import json
import logging
import os
from typing import Dict, List

from system_update.models import AppInfo, UpdateStatus

logger = logging.getLogger(__name__)


def load_advisories(file_path: str) -> Dict:
	"""Read a JSON file with an ``advisories`` list and return it parsed."""
	if not os.path.isfile(file_path):
		logger.warning(f'Local advisory file not found: {file_path}')
		return {}

	try:
		with open(file_path, 'r', encoding='utf-8') as f:
			data = json.load(f)
		logger.info(
			f'Loaded {len(data.get("advisories", []))} local advisories from {file_path}'
		)
		return data
	except Exception as e:
		logger.warning(f'Failed to load local advisories: {e}')
		return {}


def check(apps: List[AppInfo], local_data: Dict) -> List[Dict]:
	"""Match every entry in ``local_data['advisories']`` against the installed apps list."""
	vulns: List[Dict] = []
	advisories = local_data.get('advisories', [])
	unique_apps = {a.name.lower(): a for a in apps}

	for adv in advisories:
		pkg_name = adv.get('package', '').lower()
		app = unique_apps.get(pkg_name)
		if not app:
			continue

		item = {
			'package': adv.get('package', ''),
			'severity': (adv.get('severity') or 'MEDIUM').upper(),
			'cvss_score': adv.get('cvss_score'),
			'cve': adv.get('cve', 'N/A'),
			'description': (adv.get('description') or '')[:200],
			'source': adv.get('source', 'Local'),
			'affected_versions': adv.get('affected_versions', []),
			'published_date': adv.get('published_date', ''),
			'advisory_url': adv.get('advisory_url', ''),
			'fix_available': adv.get('fix_available', False),
		}
		app.security_findings.append(item)
		app.update_status = UpdateStatus.VULNERABLE
		vulns.append(item)

	return vulns
