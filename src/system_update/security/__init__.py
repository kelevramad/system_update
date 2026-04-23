"""Security vulnerability checks — one module per source + orchestrator."""

from __future__ import annotations

import logging
import os
from typing import Dict, List, Tuple

from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeElapsedColumn

from system_update.models import AppInfo
from system_update.security import github, local, npm, osv, pip, pypi
from system_update.security.common import OSV_ECOSYSTEM_MAP, score_to_severity
from system_update.utils import console

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


def check_all(apps: List[AppInfo], advisory_file: str = '') -> List[Dict]:
	"""Run every enabled security source with a per-source progress bar and return all findings."""
	apps_by_source = _group_apps_by_source(apps)
	active, local_data = _active_sources(apps_by_source, advisory_file)

	if not active:
		return []

	logger.info(f'Security check sources: {[s[0] for s in active]}')

	vulns: List[Dict] = []
	with Progress(
		TextColumn('{task.description}'),
		BarColumn(
			bar_width=16,
			complete_style='red',
			style='dim red',
			finished_style='red',
		),
		MofNCompleteColumn(),
		TimeElapsedColumn(),
		console=console,
	) as progress:
		tasks = {name: progress.add_task(f'🔒 {name}', total=1) for name, _ in active}

		for source_name, source_apps in active:
			try:
				source_vulns = _dispatch(source_name, source_apps, local_data)
				logger.info(
					f'Security check done for {source_name}: {len(source_vulns)} vulns'
				)
			except Exception as e:
				logger.warning(f'Security check failed for {source_name}: {e}')
				source_vulns = []

			vulns.extend(source_vulns)

			icon = '🔥' if source_vulns else '✓'
			progress.update(
				tasks[source_name],
				completed=1,
				description=f'{icon} {source_name} [{len(source_vulns)}]',
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
	'score_to_severity',
]
