"""Command objects for top-level CLI verbs."""

from __future__ import annotations

from typing import Any, Protocol

class Command(Protocol):
	"""Small command protocol shared by extracted CLI verbs."""

	def execute(self, args: Any, app_ctx: object) -> int:
		"""Run this command against an application context."""
		...


__all__ = ['Command']
