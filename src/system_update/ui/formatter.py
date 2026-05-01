"""Table formatters — compact / verbose / auto / JSON views of :class:`AppInfo` lists."""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Callable, Dict, List

from rich import box
from rich.table import Table

from system_update.models import AppInfo
from system_update.ui.theme import ThemeManager
from system_update.utils import display_source


def _compact_table(apps: List[AppInfo], theme: str, use_icons: bool) -> Table:
	"""Single-column table: ``icon name → latest`` per row."""
	table = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
	table.add_column('Item', width=50)
	for app in sorted(apps, key=lambda x: x.name):
		icon = ThemeManager.get_source_icon(app.source) if use_icons else ''
		color = ThemeManager.get_source_color(app.source, theme)
		row_text = f'{icon} {app.name} → {app.latest_version or "up-to-date"}'
		table.add_row(f'[{color}]{row_text}[/{color}]')
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
	table.add_column('Source', width=10)
	table.add_column('Version', width=15)
	table.add_column('Latest', width=15)
	table.add_column('Status', width=20)

	for app in sorted(apps, key=lambda x: (x.source, x.name)):
		icon = ThemeManager.get_source_icon(app.source) + ' ' if use_icons else ''
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
