"""Theme lookup — thin wrapper over the :data:`THEMES` / :data:`SOURCE_ICONS` dicts."""

from __future__ import annotations

from system_update.utils import SOURCE_ICONS, THEMES


class ThemeManager:
	"""Static accessors for the theme and icon tables in :mod:`system_update.utils`."""

	@staticmethod
	def get_theme(name: str = 'default') -> dict:
		"""Return the theme dict for ``name``, falling back to ``'default'``."""
		return THEMES.get(name, THEMES['default'])

	@staticmethod
	def get_source_color(source: str, theme: str = 'default') -> str:
		"""Return the colour used to render ``source`` under ``theme``."""
		return ThemeManager.get_theme(theme)['source_colors'].get(source.lower(), 'white')

	@staticmethod
	def get_status_color(status: str, theme: str = 'default') -> str:
		"""Return the colour for an :class:`UpdateStatus` label under ``theme``."""
		key = status.lower().replace(' ', '_')
		return ThemeManager.get_theme(theme)['status_colors'].get(key, 'white')

	@staticmethod
	def get_source_icon(source: str) -> str:
		"""Return the emoji icon registered for ``source`` (empty string if none)."""
		return SOURCE_ICONS.get(source.lower(), '')
