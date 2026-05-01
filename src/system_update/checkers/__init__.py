"""Per-source update checkers and the :class:`UpdateChecker` facade.

Each submodule exposes a ``check(apps) -> int`` function. The facade class
re-exports them as ``_check_<source>_updates`` static methods (the names used
by tests and legacy call sites) and owns :meth:`check_all_updates`, which
groups apps by source, dispatches to the per-source checker, and reconciles
:class:`UpdateStatus` values.
"""

from __future__ import annotations

from typing import Dict, List

from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeElapsedColumn

from system_update.checkers import (
	bun,
	chocolatey,
	dotnet,
	npm,
	path,
	pip,
	pnpm,
	registry,
	rust,
	scoop,
	winget,
	yarn,
)
from system_update.models import AppInfo, UpdateStatus
from system_update.utils import console, source_badge

# Sources whose checkers call ``run_command``/remote APIs to set status
# themselves. Apps from these sources without a confirmed update should be
# marked UP_TO_DATE rather than left UNKNOWN.
_CHECKED_SOURCES = frozenset(
	{
		'winget', 'chocolatey', 'npm', 'pnpm', 'bun', 'yarn',
		'pip', 'registry', 'rust', 'path', 'dotnet', 'appx', 'msix',
	}
)

_SOURCE_CHECKERS = {
	'winget': winget.check,
	'chocolatey': chocolatey.check,
	'npm': npm.check,
	'pnpm': pnpm.check,
	'bun': bun.check,
	'yarn': yarn.check,
	'pip': pip.check,
	'path': path.check,
	'registry': registry.check,
	'rust': rust.check,
	'scoop': scoop.check,
	'dotnet': dotnet.check,
}


def _group_by_source(apps: List[AppInfo]) -> Dict[str, List[AppInfo]]:
	groups: Dict[str, List[AppInfo]] = {source: [] for source in _SOURCE_CHECKERS}
	groups['appx'] = []
	groups['msix'] = []
	for app in apps:
		source = app.source.lower()
		if source in groups:
			groups[source].append(app)
	return {source: group for source, group in groups.items() if group}


def _count_updates(source_apps: List[AppInfo]) -> tuple[int, int]:
	regular = sum(1 for a in source_apps if a.update_status == UpdateStatus.UPDATE_AVAILABLE)
	security = sum(
		1 for a in source_apps
		if a.update_status == UpdateStatus.VULNERABLE and a.has_update
	)
	return regular, security


def _reconcile_final_status(apps: List[AppInfo]) -> None:
	for app in apps:
		if app.update_status in (UpdateStatus.UPDATE_AVAILABLE, UpdateStatus.UP_TO_DATE):
			continue
		if app.latest_version or app.source.lower() in _CHECKED_SOURCES:
			app.update_status = UpdateStatus.UP_TO_DATE
		else:
			app.update_status = UpdateStatus.UNKNOWN


def check_all_updates(apps: List[AppInfo]) -> int:
	"""Run every applicable checker against ``apps`` with a Rich progress bar."""
	active_sources = _group_by_source(apps)
	total_updates = 0

	with Progress(
		TextColumn('{task.description}'),
		BarColumn(
			bar_width=16,
			complete_style='yellow',
			style='dim yellow',
			finished_style='yellow',
		),
		MofNCompleteColumn(),
		TimeElapsedColumn(),
		console=console,
	) as progress:
		tasks = {
			source: progress.add_task(f'🔄 {source_badge(source)}', total=1)
			for source in active_sources
		}

		for source, source_apps in active_sources.items():
			checker = _SOURCE_CHECKERS.get(source)
			if checker is not None:
				checker(source_apps)

			regular, security = _count_updates(source_apps)
			source_total = regular + security
			total_updates += source_total

			if source_total == 0:
				desc = f'✓ {source_badge(source)} [0]'
			elif security > 0:
				desc = f'✅ {source_badge(source)} [{regular}+{security}]'
			else:
				desc = f'✅ {source_badge(source)} [{source_total}]'
			progress.update(tasks[source], completed=1, description=desc)

	_reconcile_final_status(apps)
	return total_updates


class UpdateChecker:
	"""Static-method facade over the per-source checkers."""

	check_all_updates = staticmethod(check_all_updates)
	_check_winget_updates = staticmethod(winget.check)
	_check_choco_updates = staticmethod(chocolatey.check)
	_check_npm_updates = staticmethod(npm.check)
	_check_pnpm_updates = staticmethod(pnpm.check)
	_check_bun_updates = staticmethod(bun.check)
	_check_yarn_updates = staticmethod(yarn.check)
	_check_pip_updates = staticmethod(pip.check)
	_check_path_updates = staticmethod(path.check)
	_check_registry_updates = staticmethod(registry.check)
	_check_rust_updates = staticmethod(rust.check)
	_check_scoop_updates = staticmethod(scoop.check)
	_check_dotnet_updates = staticmethod(dotnet.check)


__all__ = ['UpdateChecker', 'check_all_updates']
