"""Update command entry point."""

from __future__ import annotations

from argparse import Namespace


class UpdateCommand:
	"""Dispatch update flows through the app context."""

	def execute(self, args: Namespace, app_ctx: object) -> int:
		handler = getattr(app_ctx, 'run')
		handler(args)
		return 0


__all__ = ['UpdateCommand']
