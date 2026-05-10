"""Scheduled update command entry point."""

from __future__ import annotations

from argparse import Namespace


class ScheduleCommand:
	"""Dispatch schedule actions through the app context."""

	def execute(self, args: Namespace, app_ctx: object) -> int:
		handler = getattr(app_ctx, '_handle_schedule')
		handler(args)
		return 0


__all__ = ['ScheduleCommand']
