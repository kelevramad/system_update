"""Scan command entry point."""

from __future__ import annotations

from typing import Any

from system_update.cli_options import CLIOptions


class ScanCommand:
	"""Dispatch scan-only work through the app context."""

	def execute(self, args: Any, app_ctx: object) -> int:
		args = CLIOptions.from_namespace(args)
		handler = getattr(app_ctx, 'scan_system')
		handler(args.source)
		return 0


__all__ = ['ScanCommand']
