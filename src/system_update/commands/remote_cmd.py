"""Remote management command entry point."""

from __future__ import annotations

from argparse import Namespace


class RemoteCommand:
	"""Dispatch remote-management actions through the app context."""

	def execute(self, args: Namespace, app_ctx: object) -> int:
		handler = getattr(app_ctx, '_handle_remote')
		handler(args)
		return 0


__all__ = ['RemoteCommand']
