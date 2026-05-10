"""Robust parser for the fixed-width tables emitted by winget.

Hardening 2.2.2 — the previous parsers used ``header.find('Id')`` /
``header.find('Version')`` to locate column starts, which only worked
on en-US consoles. Non-EN locales (pt-BR ``Nome / ID / Versão /
Disponível / Origem``, de-DE ``Name / ID / Version / Verfügbar /
Quelle``, …) broke silently — the row parser dropped every package.

The new approach is locale-agnostic:

1. Find the header by looking for the dashed separator winget always
   emits below the column titles (a single long run of ``-``). The
   header line is one above; data starts on the line below.
2. Compute column boundaries from the **header's** whitespace pattern:
   each column starts at position 0 or right after a run of 2+ spaces.
   This handles every locale because the column widths line up with
   the header text regardless of the language used.
3. Slice every data row at those exact byte offsets and strip.

For winget ≥ 1.7 the ideal path is ``winget --format json``, which
sidesteps text parsing entirely. That's tried first via
:func:`parse_winget_json`; this module is the fallback for everything
else.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Sequence

# A "separator line" is a continuous run of dashes with optional
# leading/trailing whitespace. Real winget output uses one long line
# (e.g. ``-----------------``), not column-aligned runs.
_SEPARATOR_RE = re.compile(r'^\s*-{3,}\s*$')
# Column starts in a header line: position 0, plus every position
# that follows a run of 2+ spaces.
_COLUMN_GAP_RE = re.compile(r'\s{2,}')


def _find_separator_line(lines: Sequence[str]) -> int:
	"""Return the index of the first dashed-separator row, or ``-1``."""
	for i, line in enumerate(lines):
		if _SEPARATOR_RE.match(line):
			return i
	return -1


def _column_starts_from_header(header: str) -> List[int]:
	"""Compute column-start indices using the header's whitespace gaps.

	Column 0 always starts at position 0; each subsequent column
	starts immediately after a run of 2+ spaces. Works in any locale
	because we don't look at column *names*, only spacing.
	"""
	if not header.strip():
		return []
	starts = [0]
	for m in _COLUMN_GAP_RE.finditer(header):
		# The next column begins at the first non-space after the gap.
		starts.append(m.end())
	# Filter trailing entries that fell past end-of-header.
	return [s for s in starts if s < len(header)]


def _slice_row(line: str, starts: List[int]) -> List[str]:
	"""Slice ``line`` at column-start boundaries; trim each cell.

	The last column extends to end-of-line so a value wider than the
	header isn't cropped.
	"""
	cells: List[str] = []
	for i, start in enumerate(starts):
		if i == len(starts) - 1:
			cells.append(line[start:].strip())
		else:
			cells.append(line[start:starts[i + 1]].strip())
	return cells


def parse_winget_table(output: str) -> List[Dict[str, str]]:
	"""Parse a winget fixed-width table into a list of dict rows.

	Returns an empty list if the table can't be located. Keys are
	canonical English names (``name``, ``id``, ``version``,
	``available``, ``source``) regardless of the console locale —
	mapping is positional, anchored to the header line above the
	dashed separator.

	Column conventions (winget 1.6+):
		* ``winget list`` → 4 cols: Name · Id · Version · Source
		* ``winget upgrade`` → 5 cols: Name · Id · Version · Available · Source
	"""
	lines = output.splitlines()
	sep_idx = _find_separator_line(lines)
	if sep_idx <= 0:
		return []

	header = lines[sep_idx - 1]
	starts = _column_starts_from_header(header)
	if len(starts) < 3:
		return []  # at minimum we need name + id + version

	# Map column count → ordered list of canonical keys.
	if len(starts) == 4:
		keys = ['name', 'id', 'version', 'source']
	elif len(starts) == 5:
		keys = ['name', 'id', 'version', 'available', 'source']
	elif len(starts) == 3:
		keys = ['name', 'id', 'version']
	else:
		# Unknown shape — return positional cells so the caller can
		# decide what to do; older versions sometimes added extra
		# columns (e.g. ``Match`` for `winget search`).
		keys = [f'col{i}' for i in range(len(starts))]

	rows: List[Dict[str, str]] = []
	for line in lines[sep_idx + 1:]:
		if not line.strip():
			# Blank line typically marks "end of table" / "X upgrades available".
			break
		if not _looks_like_data_row(line, starts):
			# Skip footer lines like "5 upgrades available.".
			continue
		cells = _slice_row(line, starts)
		row = dict(zip(keys, cells))
		if not row.get('name'):
			continue
		rows.append(row)
	return rows


def _looks_like_data_row(line: str, starts: List[int]) -> bool:
	"""Skip footer lines that don't fill the column structure.

	A real data row is at least as long as the second column's start
	(i.e. has *something* in column 0 plus whitespace plus more
	content). Footer lines like ``5 upgrades available.`` typically
	fail this check because they're shorter than the column 1 offset.
	"""
	if len(starts) < 2:
		return bool(line.strip())
	return len(line) > starts[1] and bool(line[: starts[1]].strip())


# ─── Optional JSON path (winget 1.7+) ─────────────────────────────────────


def parse_winget_json(output: str) -> Optional[List[Dict[str, str]]]:
	"""Parse the experimental ``winget --format json`` output if present.

	Returns ``None`` if the input doesn't look like the JSON envelope
	winget produces — the caller should fall back to ``parse_winget_table``.
	"""
	import json

	stripped = output.lstrip()
	if not stripped.startswith('{') and not stripped.startswith('['):
		return None
	try:
		data = json.loads(stripped)
	except (json.JSONDecodeError, ValueError):
		return None

	# winget JSON shape (still experimental):
	#   {"Sources": [{"Packages": [{"PackageIdentifier": ..., "PackageName": ...,
	#                                "InstalledVersion": ..., "AvailableVersion": ...}]}]}
	rows: List[Dict[str, str]] = []
	if isinstance(data, dict):
		for source in data.get('Sources') or []:
			for pkg in (source or {}).get('Packages') or []:
				rows.append(_normalize_json_pkg(pkg))
	elif isinstance(data, list):
		for pkg in data:
			rows.append(_normalize_json_pkg(pkg))
	return rows


def _normalize_json_pkg(pkg: Dict) -> Dict[str, str]:
	"""Map winget's JSON keys to the same shape the table parser produces."""
	return {
		'name': str(pkg.get('PackageName') or pkg.get('Name') or '').strip(),
		'id': str(pkg.get('PackageIdentifier') or pkg.get('Id') or '').strip(),
		'version': str(pkg.get('InstalledVersion') or pkg.get('Version') or '').strip(),
		'available': str(pkg.get('AvailableVersion') or pkg.get('Available') or '').strip(),
		'source': str(pkg.get('Source') or '').strip(),
	}
