"""Scan command entry point."""

from __future__ import annotations

from argparse import Namespace


class ScanCommand:
	"""Dispatch scan-only work through the app context."""

	def execute(self, args: Namespace, app_ctx: object) -> int:
		handler = getattr(app_ctx, 'scan_system')
		handler(getattr(args, 'source', None))
		return 0


__all__ = ['ScanCommand']
