"""NPM vulnerability scanner — parses ``npm audit --json`` output."""

from __future__ import annotations

import json
import logging
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List

from system_update.models import AppInfo, UpdateStatus
from system_update.security.common import security_issue
from system_update.utils import decode_command_output

logger = logging.getLogger(__name__)


def _run_npm(cmd: List[str]) -> subprocess.CompletedProcess:
	"""Run npm and decode stdout/stderr with the shared Windows-safe decoder."""
	resolved = list(cmd)
	if platform.system() == 'Windows':
		executable = shutil.which(resolved[0])
		if executable:
			resolved[0] = executable
	result = subprocess.run(
		resolved,
		capture_output=True,
		check=False,
		timeout=45,
	)
	result.stdout = decode_command_output(result.stdout or b'')  # type: ignore[assignment]
	result.stderr = decode_command_output(result.stderr or b'')  # type: ignore[assignment]
	return result


def _audit_command() -> List[str] | None:
	"""Return the npm audit command, preferring local package.json then global root."""
	if (Path.cwd() / 'package.json').is_file():
		return ['npm', 'audit', '--json', '--silent']

	try:
		root = _run_npm(['npm', 'root', '-g'])
	except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
		logger.info('npm audit skipped: global root lookup failed: %s', exc)
		return None

	global_root = (root.stdout or '').strip()
	if root.returncode == 0 and global_root:
		prefix = str(Path(global_root).parent)
		return ['npm', 'audit', '--json', '--silent', '--prefix', prefix]

	logger.info('npm audit skipped: no package.json or global root reachable')
	return None


def check(apps: List[AppInfo]) -> List[Dict]:
	"""Run ``npm audit`` and append findings to matching :class:`AppInfo` records."""
	vulns: List[Dict] = []
	cmd = _audit_command()
	if not cmd:
		return [
			security_issue(
				'npm audit',
				'skipped',
				'npm audit skipped: no package.json or global root reachable',
			)
		]

	try:
		result = _run_npm(cmd)
	except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
		message = f'npm audit failed: {type(exc).__name__}: {exc}'
		logger.warning(message)
		return [security_issue('npm audit', 'error', message)]

	out = (result.stdout or '').strip()
	if not out:
		message = 'npm audit skipped: no JSON output'
		logger.info(message)
		return [security_issue('npm audit', 'skipped', message)]

	if result.returncode >= 2:
		message = f'npm audit failed with exit code {result.returncode}'
		logger.warning('%s: %s', message, (result.stderr or out)[:500])
		return [security_issue('npm audit', 'error', message)]

	try:
		data = json.loads(out)
	except json.JSONDecodeError as exc:
		message = f'npm audit skipped: invalid JSON output: {exc}'
		logger.warning(message)
		return [security_issue('npm audit', 'skipped', message)]

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
