"""Update-execution orchestrator and the :class:`UpdateExecutor` facade.

:func:`execute_updates` drives a Rich progress bar over ``apps`` and delegates
the actual per-package work to :func:`execute_single_update`, which builds the
argv via :mod:`system_update.executors.commands` and invokes
:func:`system_update.utils.run_command`.
"""

from __future__ import annotations

import time
from typing import Callable, Dict, List, Optional

from rich.progress import (
	BarColumn,
	MofNCompleteColumn,
	Progress,
	TextColumn,
	TimeElapsedColumn,
	TimeRemainingColumn,
)

from system_update.executors.commands import (
	build_rollback_command,
	build_update_command,
	supports_rollback,
)
from system_update.models import AppInfo, UpdateStatus
from system_update.utils import console, display_source, run_command


def _needs_venv_scrub(app: AppInfo) -> bool:
	"""True if the update should run with ``VIRTUAL_ENV`` scrubbed.

	Pip packages tracked to a global Python interpreter must NOT inherit the
	parent's active venv — otherwise pip writes into the venv instead of the
	target interpreter's site-packages.
	"""
	if (app.source or '').lower() != 'pip':
		return False
	hint = (app.install_path or '').lower()
	if not hint:
		return False
	# Active venv path is what matters; if install_path points to a different
	# tree we need to scrub.
	import sys

	venv_root = sys.prefix.lower()
	return not hint.startswith(venv_root)


def execute_single_update(
	app: AppInfo,
	extra_updaters: Optional[Dict[str, Callable[[AppInfo], object]]] = None,
) -> bool:
	"""Run the update command for one package; return True on success or no-op."""
	if app.latest_version and app.version and app.latest_version == app.version:
		return True
	updater = (extra_updaters or {}).get((app.source or '').lower())
	if updater is not None:
		return bool(updater(app))
	cmd = build_update_command(app)
	if cmd is None:
		return False
	return bool(run_command(cmd, scrub_venv=_needs_venv_scrub(app)))


def _progress() -> Progress:
	return Progress(
		TextColumn('{task.description}'),
		BarColumn(
			bar_width=26,
			complete_style='white',
			style='dim white',
			finished_style='white',
		),
		TextColumn('[progress.percentage]{task.percentage:>3.0f}%'),
		MofNCompleteColumn(),
		TimeElapsedColumn(),
		TimeRemainingColumn(),
		TextColumn('{task.fields[extra]}'),
		console=console,
	)


def _run_one(
	app: AppInfo,
	dry_run: bool,
	extra_updaters: Optional[Dict[str, Callable[[AppInfo], object]]] = None,
) -> bool:
	"""Apply or simulate one update; prints its own success/failure line."""
	if dry_run:
		time.sleep(0.3)
		console.print(f'[yellow]🔍 DRY RUN[/yellow]: {app.name} → {app.latest_version}')
		return True

	target = app.latest_version or 'latest'
	if execute_single_update(app, extra_updaters):
		console.print(f'[green]✅[/green] {app.name} updated to {target}')
		return True

	console.print(f'[red]❌[/red] Failed to update {app.name}')
	return False


def execute_updates(
	apps: List[AppInfo],
	dry_run: bool = False,
	snapshot_store=None,
	snapshot_label: str = '',
	snapshot_command: str = '',
	extra_updaters: Optional[Dict[str, Callable[[AppInfo], object]]] = None,
) -> Optional[str]:
	"""Update every package in ``apps`` and emit a final success/total summary.

	If ``snapshot_store`` is provided AND not in dry-run, a 6.2.1 snapshot is
	recorded after the batch. Returns the snapshot id (or ``None``).
	"""
	from system_update.snapshots import build_snapshot_packages, capture_pre_update

	pre_state = capture_pre_update(apps) if snapshot_store and not dry_run else None
	results: dict = {}
	success_count = 0

	with _progress() as progress:
		task = progress.add_task('⚙️ Applying updates', total=len(apps), extra='')
		for app in apps:
			label = f'{app.name} ({display_source(app.source)})'
			ok = _run_one(app, dry_run, extra_updaters)
			if ok and not dry_run:
				if app.latest_version and app.latest_version != app.version:
					app.version = app.latest_version
					app.latest_version = ''
				app.update_status = UpdateStatus.UP_TO_DATE
			success_count += int(ok)
			icon = '✅' if ok else '❌'
			progress.update(task, advance=1, extra=f'{icon} [bold]{label}[/bold]')
			results[f'{(app.source or "").lower()}|{(app.name or "").lower()}'] = ok

		progress.update(task, extra='✨ [bold cyan]finished[/bold cyan]')

	console.print(
		f'\n📊 Completed: [bold]{success_count}/{len(apps)}[/bold] successful.'
	)

	if pre_state is not None and snapshot_store is not None:
		try:
			rows = build_snapshot_packages(pre_state, results)
			snap_id = snapshot_store.record(
				rows, label=snapshot_label, command=snapshot_command,
			)
			console.print(
				f'[dim]📸 Snapshot saved as [cyan]{snap_id}[/cyan] — rollback via '
				f'[cyan]--rollback {snap_id}[/cyan][/dim]'
			)
			return snap_id
		except Exception as e:
			console.print(f'[red]✗ Snapshot save failed:[/red] {e}')
	return None


def execute_rollback(
	packages, dry_run: bool = False
) -> int:
	"""Restore each :class:`SnapshotPackage` to its ``version_before``.

	Skips entries whose source has no rollback builder; logs a warning per
	skipped item. Returns count of successful rollbacks.
	"""
	success = 0
	with _progress() as progress:
		task = progress.add_task(
			'⏪ Rolling back', total=len(packages), extra=''
		)
		for pkg in packages:
			label = f'{pkg.name} ({display_source(pkg.source)}) → {pkg.version_before or "?"}'
			if not supports_rollback(pkg.source):
				console.print(
					f'[yellow]⚠ Skipping[/yellow] {pkg.name}: rollback not '
					f'supported for source [bold]{display_source(pkg.source)}[/bold]'
				)
				progress.update(task, advance=1, extra=f'⚠ {label}')
				continue
			if not pkg.version_before:
				console.print(
					f'[yellow]⚠ Skipping[/yellow] {pkg.name}: no recorded '
					f'previous version'
				)
				progress.update(task, advance=1, extra=f'⚠ {label}')
				continue

			fake = pkg.to_appinfo()
			cmd = build_rollback_command(fake)
			if cmd is None:
				progress.update(task, advance=1, extra=f'⚠ {label}')
				continue

			if dry_run:
				console.print(
					f'[yellow]🔍 DRY RUN[/yellow]: {label} ← '
					f'[dim]{" ".join(cmd)}[/dim]'
				)
				success += 1
				progress.update(task, advance=1, extra=f'🔍 {label}')
				continue

			ok = bool(run_command(cmd, scrub_venv=_needs_venv_scrub(fake)))
			if ok:
				console.print(f'[green]⏪[/green] {label}')
				success += 1
			else:
				console.print(f'[red]❌ Rollback failed:[/red] {label}')
			progress.update(
				task, advance=1, extra=f'{"✅" if ok else "❌"} {label}'
			)
		progress.update(task, extra='✨ [bold cyan]finished[/bold cyan]')

	console.print(
		f'\n📊 Rollback: [bold]{success}/{len(packages)}[/bold] restored.'
	)
	return success


class UpdateExecutor:
	"""Static-method facade preserving the legacy API used by tests and the CLI."""

	execute_updates = staticmethod(execute_updates)
	execute_rollback = staticmethod(execute_rollback)
	_execute_single_update = staticmethod(execute_single_update)


__all__ = [
	'UpdateExecutor',
	'execute_single_update',
	'execute_updates',
	'execute_rollback',
]
