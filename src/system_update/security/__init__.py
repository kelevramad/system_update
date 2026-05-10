"""Security vulnerability checks — one module per source + orchestrator."""

from __future__ import annotations

import logging
import os
from typing import Any, Callable, Dict, List, Optional, Tuple

from system_update.models import AppInfo
from system_update.security import github, local, npm, osv, pip, pypi
from system_update.security.common import OSV_ECOSYSTEM_MAP, is_security_issue, score_to_severity
from system_update.ui.progress import make_progress

logger = logging.getLogger(__name__)


def _group_apps_by_source(apps: List[AppInfo]) -> Dict[str, List[AppInfo]]:
	"""Bucket ``apps`` by lowercased ``source`` name."""
	bucketed: Dict[str, List[AppInfo]] = {}
	for app in apps:
		bucketed.setdefault(app.source.lower(), []).append(app)
	return bucketed


def _active_sources(
	apps_by_source: Dict[str, List[AppInfo]],
	advisory_file: str,
) -> Tuple[List[Tuple[str, List[AppInfo]]], Dict]:
	"""Return the ordered ``(source_name, apps)`` pairs that actually have work to do."""
	order = ['npm', 'pip', 'osv', 'github']
	active: List[Tuple[str, List[AppInfo]]] = [
		(name, apps_by_source[name]) for name in order if apps_by_source.get(name)
	]

	local_data: Dict = {}
	if advisory_file and os.path.isfile(advisory_file):
		local_data = local.load_advisories(advisory_file)
	if local_data:
		all_apps = [app for apps_list in apps_by_source.values() for app in apps_list]
		if all_apps:
			active.append(('local', all_apps))

	if apps_by_source.get('pip'):
		active.append(('pypi', apps_by_source['pip']))

	return active, local_data


def _dispatch(source: str, apps: List[AppInfo], local_data: Dict) -> List[Dict]:
	"""Route a single security source to its checker function."""
	if source == 'npm':
		return npm.check(apps)
	if source == 'pip':
		return pip.check(apps)
	if source == 'pypi':
		return pypi.check(apps)
	if source == 'osv':
		return osv.check(apps)
	if source == 'github':
		return github.check(apps)
	if source == 'local':
		return local.check(apps, local_data)
	return []


def check_all(
	apps: List[AppInfo],
	advisory_file: str = '',
	extra_checkers: Optional[Dict[str, Callable[[List[AppInfo]], List[Dict[str, Any]]]]] = None,
) -> List[Dict]:
	"""Run every enabled security source with a per-source progress bar.

	``extra_checkers`` maps a source name (typically the same identifier
	the plugin's scanner registered) to a callable that returns the list
	of vulnerability dicts found in those packages. Plugin-supplied
	checkers participate as normal rows in the progress display, just
	like the built-in ``npm`` / ``pip`` / ``osv`` / ``github`` ones.
	"""
	apps_by_source = _group_apps_by_source(apps)
	active, local_data = _active_sources(apps_by_source, advisory_file)

	# Append plugin-provided checkers as additional active sources so they
	# show up alongside the built-ins in the progress display.
	plugin_checkers = extra_checkers or {}
	for source_name, _ in plugin_checkers.items():
		bucket = apps_by_source.get(source_name.lower())
		if bucket:
			active.append((source_name, bucket))

	if not active:
		return []

	logger.info(f'Security check sources: {[s[0] for s in active]}')

	vulns: List[Dict] = []
	with make_progress() as progress:
		tasks = {name: progress.add_task(f'🔒 {name}', total=1) for name, _ in active}

		for source_name, source_apps in active:
			try:
				if source_name in plugin_checkers:
					source_vulns = list(plugin_checkers[source_name](source_apps) or [])
				else:
					source_vulns = _dispatch(source_name, source_apps, local_data)
				issue_count = sum(1 for item in source_vulns if is_security_issue(item))
				vuln_count = len(source_vulns) - issue_count
				logger.info(
					f'Security check done for {source_name}: '
					f'{vuln_count} vulns, {issue_count} issue(s)'
				)
			except Exception as e:
				logger.warning(f'Security check failed for {source_name}: {e}')
				source_vulns = []

			vulns.extend(source_vulns)

			issue_count = sum(1 for item in source_vulns if is_security_issue(item))
			vuln_count = len(source_vulns) - issue_count
			icon = '!' if issue_count else ('🔥' if vuln_count else '✓')
			progress.update(
				tasks[source_name],
				completed=1,
				description=f'{icon} {source_name} [{vuln_count}]',
			)

	return vulns


class SecurityChecker:
	"""Static-method facade around the per-source checkers."""

	check_all = staticmethod(check_all)
	check_npm = staticmethod(npm.check)
	check_pip = staticmethod(pip.check)
	check_pypi = staticmethod(pypi.check)
	check_osv = staticmethod(osv.check)
	check_github = staticmethod(github.check)
	check_local = staticmethod(local.check)
	load_local_advisories = staticmethod(local.load_advisories)


__all__ = [
	'OSV_ECOSYSTEM_MAP',
	'SecurityChecker',
	'check_all',
	'is_security_issue',
	'score_to_severity',
]
