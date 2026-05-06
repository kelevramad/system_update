"""Per-source update checkers and the :class:`UpdateChecker` facade.

Each submodule exposes a ``check(apps) -> int`` function. The facade class
re-exports them as ``_check_<source>_updates`` static methods (the names used
by tests and legacy call sites) and owns :meth:`check_all_updates`, which
groups apps by source, dispatches to the per-source checker, and reconciles
:class:`UpdateStatus` values.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional

from system_update.ui.progress import make_progress

from system_update.checkers._winget_upgrade import cached_upgrade_rows
from system_update.checkers import (
	bun,
	chocolatey,
	dotnet,
	drivers,
	npm,
	appx,
	path,
	pip,
	pnpm,
	psmodules,
	registry,
	rust,
	scoop,
	services,
	vsextensions,
	winget,
	yarn,
)
from system_update.models import AppInfo, UpdateStatus
from system_update.utils import source_chip

logger = logging.getLogger(__name__)

# Sources whose checkers call ``run_command``/remote APIs to set status
# themselves. Apps from these sources without a confirmed update should be
# marked UP_TO_DATE rather than left UNKNOWN.
_CHECKED_SOURCES = frozenset(
	{
		'winget', 'chocolatey', 'npm', 'pnpm', 'bun', 'yarn',
		'pip', 'registry', 'rust', 'path', 'dotnet', 'appx', 'msix',
		'drivers', 'services', 'psmodules', 'vsextensions',
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
	'appx': appx.check,
	'msix': appx.check_msix,
	'drivers': drivers.check,
	'services': services.check,
	'psmodules': psmodules.check,
	'vsextensions': vsextensions.check,
}


def _group_by_source(
	apps: List[AppInfo],
	source_checkers: Dict[str, Callable[[List[AppInfo]], object]],
) -> Dict[str, List[AppInfo]]:
	groups: Dict[str, List[AppInfo]] = {source: [] for source in source_checkers}
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


def _normalize_statuses(apps: List[AppInfo]) -> None:
	for app in apps:
		if isinstance(app.update_status, str):
			app.update_status = (
				UpdateStatus(app.update_status)
				if app.update_status in {status.value for status in UpdateStatus}
				else UpdateStatus.UNKNOWN
			)


def _reconcile_final_status(apps: List[AppInfo], checked_sources: set[str]) -> None:
	for app in apps:
		if app.update_status in (
			UpdateStatus.UPDATE_AVAILABLE,
			UpdateStatus.UP_TO_DATE,
			UpdateStatus.ERROR,
		):
			continue
		if app.latest_version or app.source.lower() in checked_sources:
			app.update_status = UpdateStatus.UP_TO_DATE
		else:
			app.update_status = UpdateStatus.UNKNOWN


def _check_source(
	source: str,
	source_apps: List[AppInfo],
	source_checkers: Dict[str, Callable[[List[AppInfo]], object]],
) -> tuple[int, int]:
	checker = source_checkers.get(source)
	if checker is not None:
		checker(source_apps)
	_normalize_statuses(source_apps)
	return _count_updates(source_apps)


def check_all_updates(
	apps: List[AppInfo],
	max_workers: Optional[int] = None,
	extra_checkers: Optional[Dict[str, Callable[[List[AppInfo]], object]]] = None,
) -> int:
	"""Run every applicable checker against ``apps`` with a Rich progress bar."""
	source_checkers = dict(_SOURCE_CHECKERS)
	source_checkers.update({source.lower(): check for source, check in (extra_checkers or {}).items()})
	active_sources = _group_by_source(apps, source_checkers)
	total_updates = 0
	if not active_sources:
		return 0

	workers = max(1, min(max_workers or 6, len(active_sources)))

	with cached_upgrade_rows():
		with make_progress() as progress:
			tasks = {
				source: progress.add_task(f'🔄 {source_chip(source)}', total=1)
				for source in active_sources
			}

			with ThreadPoolExecutor(max_workers=workers) as executor:
				future_to_source = {
					executor.submit(_check_source, source, source_apps, source_checkers): source
					for source, source_apps in active_sources.items()
				}
				for future in as_completed(future_to_source):
					source = future_to_source[future]
					try:
						regular, security = future.result()
						source_total = regular + security
						total_updates += source_total

						if source_total == 0:
							desc = f'✓ {source_chip(source)} [0]'
						elif security > 0:
							desc = f'✅ {source_chip(source)} [{regular}+{security}]'
						else:
							desc = f'✅ {source_chip(source)} [{source_total}]'
						progress.update(tasks[source], completed=1, description=desc)
					except Exception as exc:  # noqa: BLE001 — keep other sources running
						logger.warning('Update checker failed for %s: %s', source, exc)
						for app in active_sources[source]:
							app.update_status = UpdateStatus.ERROR
						progress.update(
							tasks[source],
							completed=1,
							description=f'❌ {source_chip(source)} error',
						)

	_reconcile_final_status(apps, set(_CHECKED_SOURCES) | set(source_checkers))
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
	_check_appx_updates = staticmethod(appx.check)
	_check_msix_updates = staticmethod(appx.check_msix)
	_check_drivers_updates = staticmethod(drivers.check)
	_check_services_updates = staticmethod(services.check)
	_check_psmodules_updates = staticmethod(psmodules.check)
	_check_vsextensions_updates = staticmethod(vsextensions.check)


__all__ = ['UpdateChecker', 'check_all_updates']
