"""PIP vulnerability scanner — parses ``pip-audit`` JSON output."""

from __future__ import annotations

import json
import logging
import os
from typing import Dict, List, Optional

from system_update.models import AppInfo, UpdateStatus
from system_update.utils import run_command

logger = logging.getLogger(__name__)


def _parse_version(v: str):
	"""Best-effort PEP 440 parse via ``packaging`` (already a transitive dep).

	Falls back to ``None`` so callers can decide to skip comparison-based
	filtering when versions can't be parsed.
	"""
	if not v:
		return None
	try:
		from packaging.version import InvalidVersion, parse

		try:
			return parse(v)
		except InvalidVersion:
			return None
	except ImportError:  # pragma: no cover — packaging ships with pip
		return None


def _is_already_fixed(installed: str, fix_versions: Optional[List[str]]) -> bool:
	"""True if ``installed`` is at or above any version listed in ``fix_versions``."""
	if not installed or not fix_versions:
		return False
	inst = _parse_version(installed)
	if inst is None:
		return False
	for fv in fix_versions:
		fixed = _parse_version(str(fv))
		if fixed is not None and inst >= fixed:
			return True
	return False


def _same_version(a: str, b: str) -> bool:
	"""Return True when two version strings represent the same installed version."""
	if not a or not b:
		return False
	pa = _parse_version(a)
	pb = _parse_version(b)
	if pa is not None and pb is not None:
		return pa == pb
	return a.strip() == b.strip()


def _audit_interpreter(pip_apps: List[AppInfo]) -> str:
	"""Pick the Python executable that owns the scanned pip packages."""
	for app in pip_apps:
		path = app.install_path or ''
		if path and os.path.exists(path):
			return path
	return ''


def check(apps: List[AppInfo]) -> List[Dict]:
	"""Run ``pip-audit -f json`` and append findings to matching :class:`AppInfo` records."""
	vulns: List[Dict] = []
	pip_apps = [a for a in apps if a.source.lower() == 'pip']
	if not pip_apps:
		return vulns

	env = {}
	interpreter = _audit_interpreter(pip_apps)
	if interpreter:
		env['PIPAPI_PYTHON_LOCATION'] = interpreter

	out = run_command(
		['pip-audit', '-o', '-', '-f', 'json'],
		allow_failure=True,
		env_overrides=env or None,
	)
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

		# pip-audit may have run against a different interpreter than the one
		# our scanner discovered the package in (e.g. global Python vs venv).
		# Refuse to attach findings from a different installed version, then
		# filter findings whose ``fix_versions`` are <= the version we actually
		# have installed — those are already fixed for THIS install.
		audited_version = (dep.get('version') or '').strip()
		if audited_version and not _same_version(app.version, audited_version):
			logger.debug(
				f'Skipping {pkg_name}: pip-audit saw {audited_version}, '
				f'but scanner saw {app.version}'
			)
			continue

		for vuln in dep.get('vulns', []):
			cve = vuln.get('id', 'N/A')
			aliases = vuln.get('aliases', [])
			if aliases and cve == 'N/A':
				cve = aliases[0]

			fix_versions = vuln.get('fix_versions') or []
			if _is_already_fixed(app.version, fix_versions):
				logger.debug(
					f'Skipping {cve} for {app.name}: installed '
					f'{app.version} is already at/above fix '
					f'{fix_versions} (pip-audit saw {audited_version})'
				)
				continue

			item = {
				'package': app.name,
				'severity': 'MEDIUM',
				'cvss_score': vuln.get('cvss_score') or vuln.get('score'),
				'cve': cve,
				'description': vuln.get('description', 'Security vulnerability'),
				'affected_versions': vuln.get('affected_versions', []),
				'fix_versions': fix_versions,
				'audited_version': audited_version,
				'published_date': vuln.get('published_date', ''),
				'advisory_url': vuln.get('advisory_url', ''),
				'fix_available': vuln.get('fix_available', False),
			}
			app.security_findings.append(item)
			app.update_status = UpdateStatus.VULNERABLE
			vulns.append(item)

	return vulns
