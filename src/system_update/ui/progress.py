"""Shared Rich-progress helpers for scan / check / security phases.

Why this exists: the previous implementation handed every per-source task
to ``TimeElapsedColumn``. With parallel execution all tasks share wall-clock
elapsed time — so every running row appeared to advance at the same rate
even though they finished one-by-one. That confused users into thinking the
tool was timing wrong.

This module provides:

* :class:`TaskDurationColumn` — only renders a duration when the task is
  finished (``task.finished``); running tasks show ``⏳``. Once a task
  completes the column locks in ``finished_time - start_time``.
* :func:`make_progress` — a single Progress factory that picks a sensible
  bar width / column set used everywhere.
"""

from __future__ import annotations

from rich.progress import (
	BarColumn,
	MofNCompleteColumn,
	Progress,
	ProgressColumn,
	Task,
	TextColumn,
)
from rich.text import Text

from system_update.utils import console


class TaskDurationColumn(ProgressColumn):
	"""Per-task duration. Blank while running, ``Ns`` once finished."""

	def render(self, task: Task) -> Text:
		if not task.finished:
			return Text('⏳', style='dim')
		seconds = task.finished_time or task.elapsed or 0
		# Keep it short: ``0.8s`` / ``12s`` / ``2m 14s``.
		if seconds < 1:
			text = f'{seconds:.1f}s'
		elif seconds < 60:
			text = f'{seconds:.1f}s'
		else:
			minutes, secs = divmod(int(seconds), 60)
			text = f'{minutes}m {secs}s'
		return Text(text, style='cyan')


def make_progress(*, bar_width: int = 20) -> Progress:
	"""Return a Progress with the project's standard column set.

	Order: description · bar · M/N · per-task duration. Works in interactive
	TTYs (animated bar) and in pipes (final state only).
	"""
	return Progress(
		TextColumn('{task.description}'),
		BarColumn(
			bar_width=bar_width,
			complete_style='cyan',
			style='dim cyan',
			finished_style='cyan',
		),
		MofNCompleteColumn(),
		TaskDurationColumn(),
		console=console,
		transient=False,
	)


__all__ = ['TaskDurationColumn', 'make_progress']
