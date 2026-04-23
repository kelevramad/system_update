"""Update-execution orchestrator and the :class:`UpdateExecutor` facade.

:func:`execute_updates` drives a Rich progress bar over ``apps`` and delegates
the actual per-package work to :func:`execute_single_update`, which builds the
argv via :mod:`system_update.executors.commands` and invokes
:func:`system_update.utils.run_command`.
"""

from __future__ import annotations

import time
from typing import List

from rich.progress import (
	BarColumn,
	MofNCompleteColumn,
	Progress,
	TextColumn,
	TimeElapsedColumn,
	TimeRemainingColumn,
)

from system_update.executors.commands import build_update_command
from system_update.models import AppInfo
from system_update.utils import console, run_command


def execute_single_update(app: AppInfo) -> bool:
	"""Run the update command for one package; return True on success."""
	cmd = build_update_command(app)
	if cmd is None:
		return False
	return bool(run_command(cmd))


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


def _run_one(app: AppInfo, dry_run: bool) -> bool:
	"""Apply or simulate one update; prints its own success/failure line."""
	if dry_run:
		time.sleep(0.3)
		console.print(f'[yellow]🔍 DRY RUN[/yellow]: {app.name} → {app.latest_version}')
		return True

	if execute_single_update(app):
		console.print(f'[green]✅[/green] {app.name} updated to {app.latest_version}')
		return True

	console.print(f'[red]❌[/red] Failed to update {app.name}')
	return False


def execute_updates(apps: List[AppInfo], dry_run: bool = False) -> None:
	"""Update every package in ``apps`` and emit a final success/total summary."""
	success_count = 0

	with _progress() as progress:
		task = progress.add_task('⚙️ Applying updates', total=len(apps), extra='')
		for app in apps:
			label = f'{app.name} ({app.source})'
			ok = _run_one(app, dry_run)
			success_count += int(ok)
			icon = '✅' if ok else '❌'
			progress.update(task, advance=1, extra=f'{icon} [bold]{label}[/bold]')

		progress.update(task, extra='✨ [bold cyan]finished[/bold cyan]')

	console.print(
		f'\n📊 Completed: [bold]{success_count}/{len(apps)}[/bold] successful.'
	)


class UpdateExecutor:
	"""Static-method facade preserving the legacy API used by tests and the CLI."""

	execute_updates = staticmethod(execute_updates)
	_execute_single_update = staticmethod(execute_single_update)


__all__ = ['UpdateExecutor', 'execute_single_update', 'execute_updates']
