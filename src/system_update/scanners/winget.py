"""Scan Winget-managed packages via ``winget list``.

Hardening 2.2.2 — parsing delegated to :mod:`_winget_table`, which
locates columns from the dashed separator winget always emits below
the header. That makes it locale-agnostic (pt-BR ``Nome / ID / Versão
/ Origem`` and de-DE ``Name / ID / Version / Quelle`` parse the same
as en-US) and tolerant of long names abutting the next column.
"""

from __future__ import annotations

from typing import List

from system_update.models import AppInfo, UpdateStatus
from system_update.scanners._winget_table import (
	parse_winget_json,
	parse_winget_table,
)
from system_update.utils import run_command


def scan() -> List[AppInfo]:
	"""Parse ``winget list`` output into :class:`AppInfo` records."""
	apps: List[AppInfo] = []
	output = run_command(['winget', 'list', '--accept-source-agreements'], allow_failure=True)
	if not output:
		return apps

	# Try the JSON path first (winget ≥ 1.7); fall back to the
	# whitespace-separator parser for older versions and anything
	# that happens to emit table output.
	rows = parse_winget_json(output) or parse_winget_table(output)
	for row in rows:
		name = row.get('name', '').strip()
		app_id = row.get('id', '').strip()
		version = row.get('version', '').strip()
		if not name or not app_id or not version:
			continue
		apps.append(
			AppInfo(
				name=name,
				source='Winget',
				version=version,
				app_id=app_id,
				update_status=UpdateStatus.UNKNOWN,
			)
		)
	return apps
