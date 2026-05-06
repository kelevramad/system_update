"""Per-execution cache for ``winget upgrade`` rows shared by checkers."""

from __future__ import annotations

import re
import threading
from contextlib import contextmanager
from typing import Generator

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
	"""Parse the fixed-width table emitted by ``winget upgrade``."""
	lines = output.splitlines()
	header_index = next((i for i, line in enumerate(lines) if 'Name' in line and 'Id' in line), -1)
	if header_index == -1:
		return []

	header = lines[header_index]
	name_match = re.search(r'Name\s+Id', header)
	if name_match:
		header = header[name_match.start() :]

	positions = {
		'id': header.find('Id'),
		'version': header.find('Version'),
		'available': header.find('Available'),
		'source': header.find('Source'),
	}
	if positions['id'] == -1 or positions['available'] == -1:
		return []

	rows: list[dict[str, str]] = []
	for line in lines[header_index + 1 :]:
		if not line.strip() or set(line.strip()) <= {'-'}:
			continue
		try:
			source_end = len(line)
			avail_end = positions['source'] if positions['source'] != -1 else source_end
			rows.append(
				{
					'name': line[: positions['id']].strip(),
					'id': line[positions['id'] : positions['version']].strip()
					if positions['version'] > 0
					else '',
					'version': line[positions['version'] : positions['available']].strip()
					if positions['version'] > 0
					else '',
					'available': line[positions['available'] : avail_end].strip(),
					'source': line[positions['source'] : source_end].strip()
					if positions['source'] != -1
					else '',
				}
			)
		except Exception:
			continue
	return rows


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
