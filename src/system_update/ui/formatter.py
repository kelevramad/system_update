"""Table formatters — compact / verbose / auto / JSON views of :class:`AppInfo` lists."""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Callable, Dict, List

from rich import box
from rich.table import Table

from system_update.models import AppInfo
from system_update.ui.theme import ThemeManager
from system_update.utils import display_source, source_icon


def _source_icon(source: str) -> str:
	"""Return a package-source icon, using a plugin glyph for custom sources."""
	return source_icon(source)


def _compact_table(apps: List[AppInfo], theme: str, use_icons: bool) -> Table:
	"""Three-column dense view: icon | name | current → latest (or ✓ up-to-date).

	Designed for fast visual scanning. Each row stays on a single line — names
	are truncated with an ellipsis if they exceed the name column. Up-to-date
	rows are dimmed so update candidates stand out, and the version column
	uses a colour ramp (green ✓ for current, yellow ↑ for update,
	red 🔥 for vulnerable, dim grey for unknown / no version).
	"""
	from system_update.models import UpdateStatus

	table = Table(
		box=box.SIMPLE,
		show_header=True,
		header_style='bold cyan',
		pad_edge=False,
		expand=False,
	)
	table.add_column('', width=2, no_wrap=True)
	table.add_column('Package', min_width=30, max_width=42, no_wrap=True, overflow='ellipsis')
	table.add_column('Current', min_width=10, no_wrap=True, overflow='ellipsis', style='dim')
	table.add_column('→', width=1, justify='center', style='dim')
	table.add_column('Latest', min_width=14, no_wrap=True, overflow='ellipsis')

	def _state_marker(app: AppInfo) -> tuple:
		"""Return (latest_text, latest_style) for the right-most column."""
		st = app.update_status
		if st == UpdateStatus.VULNERABLE:
			return (
				f'🔥 {app.latest_version}' if app.latest_version
				else '🔥 vulnerable',
				'bold red',
			)
		if st in (UpdateStatus.UPDATE_AVAILABLE, UpdateStatus.SECURITY_UPDATE_AVAILABLE):
			return (f'↑ {app.latest_version or "?"}', 'bold yellow')
		if st == UpdateStatus.UP_TO_DATE:
			return ('✓ up-to-date', 'green')
		if st == UpdateStatus.ERROR:
			return ('✗ error', 'red')
		return ('? unknown', 'dim')

	for app in sorted(apps, key=lambda x: (x.source, x.name.lower())):
		icon = _source_icon(app.source)
		src_color = ThemeManager.get_source_color(app.source, theme)
		latest_text, latest_style = _state_marker(app)

		# Dim the whole row when the package is up-to-date so updatable
		# entries pop visually.
		dim = app.update_status == UpdateStatus.UP_TO_DATE
		name_style = 'dim white' if dim else 'bold white'

		table.add_row(
			f'[{src_color}]{icon}[/{src_color}]',
			f'[{name_style}]{app.name}[/{name_style}]',
			app.version or '-',
			'→',
			f'[{latest_style}]{latest_text}[/{latest_style}]',
		)
	return table


def _verbose_table(apps: List[AppInfo], theme: str, use_icons: bool) -> Table:
	"""Full 5-column detail table with borders and row separators."""
	theme_data = ThemeManager.get_theme(theme)
	# Verbose mode is always more "framed" than auto mode.
	default_box = box.ROUNDED if theme == 'default' else theme_data.get('box', box.ROUNDED)

	table = Table(
		box=default_box,
		show_header=True,
		show_lines=True,
		header_style=theme_data['header_style'],
		border_style=theme_data['border_style'],
		pad_edge=False,
	)
	table.add_column('Package', style='bold white', width=25)
	# 16 fits "🍫 chocolatey" (icon takes 2 cells). ``no_wrap`` keeps it on
	# one line if a longer source ever appears.
	table.add_column('Source', min_width=16, no_wrap=True)
	table.add_column('Version', width=15)
	table.add_column('Latest', width=15)
	table.add_column('Status', width=20)

	for app in sorted(apps, key=lambda x: (x.source, x.name)):
		icon = f'{_source_icon(app.source)} '
		src_color = ThemeManager.get_source_color(app.source, theme)
		status_color = ThemeManager.get_status_color(app.update_status.name, theme)
		table.add_row(
			app.name[:25],
			f'[{src_color}]{icon}{display_source(app.source)}[/{src_color}]',
			app.version,
			app.latest_version or '-',
			f'[{status_color}]{app.status_display}[/{status_color}]',
		)
	return table


def _json_table(apps: List[AppInfo]) -> Table:
	"""Single-cell table containing the apps list serialized as JSON."""
	table = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
	table.add_column('JSON', width=80)
	payload = [
		{
			'name': app.name,
			'source': display_source(app.source),
			'version': app.version,
			'latest': app.latest_version,
			'status': app.update_status.name,
		}
		for app in apps
	]
	table.add_row(f'[cyan]{json.dumps(payload, indent=2)}[/cyan]')
	return table


def _auto_table(apps: List[AppInfo], theme: str, use_icons: bool, show_all: bool) -> Table:
	"""Defer to :func:`create_apps_table`, which is the default display used everywhere."""
	from system_update.ui.system import create_apps_table

	return create_apps_table(
		deepcopy(apps), show_all=show_all, theme=theme, use_icons=use_icons
	)


_FORMATTERS: Dict[str, Callable[..., Table]] = {
	'compact': lambda apps, theme, use_icons, show_all: _compact_table(apps, theme, use_icons),
	'verbose': lambda apps, theme, use_icons, show_all: _verbose_table(apps, theme, use_icons),
	'json': lambda apps, theme, use_icons, show_all: _json_table(apps),
}


class DisplayFormatter:
	"""Dispatch :class:`AppInfo` lists to the right ``Table`` builder."""

	@staticmethod
	def format_table(
		apps: List[AppInfo],
		format_mode: str = 'auto',
		theme: str = 'default',
		use_icons: bool = False,
		show_all: bool = False,
	) -> Table:
		"""Return a Rich ``Table`` for ``apps`` in the requested ``format_mode``.

		Unknown modes fall through to the ``auto`` renderer so callers can pass
		export format names (``html``/``xml``/etc.) without crashing when the UI
		is used as a preview.
		"""
		builder = _FORMATTERS.get(format_mode)
		if builder is not None:
			return builder(apps, theme, use_icons, show_all)
		return _auto_table(apps, theme, use_icons, show_all)


# Re-export so tests and other modules can avoid deep imports.
__all__ = [
	'DisplayFormatter',
	'_auto_table',
	'_compact_table',
	'_json_table',
	'_verbose_table',
]
