"""Per-execution cache for ``winget upgrade`` rows shared by checkers.

Hardening 2.2.2 — parsing delegated to :mod:`scanners._winget_table`,
which is locale-agnostic (anchors on the dashed-separator line winget
always emits below the column titles).
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Generator

from system_update.scanners._winget_table import (
	parse_winget_json,
	parse_winget_table,
)
from system_update.utils import run_command

_LOCK = threading.Lock()
_CACHE_ENABLED = False
_ROWS_CACHE: list[dict[str, str]] | None = None


@contextmanager
def cached_upgrade_rows() -> Generator[None, None, None]:
	"""Enable one shared ``winget upgrade`` read for the current check run."""
	global _CACHE_ENABLED, _ROWS_CACHE
	with _LOCK:
		previous_enabled = _CACHE_ENABLED
		previous_rows = _ROWS_CACHE
		_CACHE_ENABLED = True
		_ROWS_CACHE = None
	try:
		yield
	finally:
		with _LOCK:
			_CACHE_ENABLED = previous_enabled
			_ROWS_CACHE = previous_rows


def _parse_rows(output: str) -> list[dict[str, str]]:
	"""Parse winget upgrade output. JSON path first, table fallback."""
	return parse_winget_json(output) or parse_winget_table(output)


def get_upgrade_rows() -> list[dict[str, str]]:
	"""Return parsed ``winget upgrade`` rows, cached when a check run enables it."""
	global _ROWS_CACHE
	with _LOCK:
		if _CACHE_ENABLED and _ROWS_CACHE is not None:
			return list(_ROWS_CACHE)
		if _CACHE_ENABLED:
			output = run_command(['winget', 'upgrade', '--accept-source-agreements'], allow_failure=True)
			rows = _parse_rows(output or '')
			_ROWS_CACHE = rows
			return list(_ROWS_CACHE)

	output = run_command(['winget', 'upgrade', '--accept-source-agreements'], allow_failure=True)
	rows = _parse_rows(output or '')
	return rows
