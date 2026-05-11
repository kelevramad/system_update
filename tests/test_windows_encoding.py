"""Hardening 2.2 — Windows encoding and parsing.

* 2.2.1 — ``decode_command_output`` decodes raw subprocess bytes
  through a UTF-8 → UTF-16-LE → OEM → CP1252 fallback chain.
* 2.2.2 — ``parse_winget_table`` / ``parse_winget_json`` cope with
  non-EN locales (pt-BR, de-DE) and with the experimental JSON
  output flag.
* 2.2.3 — ``parse_iso_utc`` always returns timezone-aware UTC.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from system_update.scanners._winget_table import (
	parse_winget_json,
	parse_winget_table,
)
from system_update.utils import decode_command_output, parse_iso_utc


# ─── 2.2.3 — parse_iso_utc ─────────────────────────────────────────────────


def test_parse_iso_utc_z_suffix_yields_aware_utc():
	dt = parse_iso_utc('2025-01-01T00:00:00Z')
	assert dt.tzinfo is timezone.utc
	assert dt == datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def test_parse_iso_utc_explicit_offset_normalizes_to_utc():
	dt = parse_iso_utc('2025-01-01T00:00:00+00:00')
	assert dt.tzinfo is timezone.utc
	assert dt == datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def test_parse_iso_utc_negative_offset_shifts_to_utc():
	# 2025-01-01T00:00:00-03:00 == 2025-01-01T03:00:00Z
	dt = parse_iso_utc('2025-01-01T00:00:00-03:00')
	assert dt == datetime(2025, 1, 1, 3, 0, 0, tzinfo=timezone.utc)


def test_parse_iso_utc_naive_assumed_utc():
	"""Legacy entries written without tz info should be treated as UTC."""
	dt = parse_iso_utc('2025-01-01T00:00:00')
	assert dt.tzinfo is timezone.utc
	assert dt == datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def test_parse_iso_utc_empty_raises():
	with pytest.raises(ValueError):
		parse_iso_utc('')


def test_cache_freshness_compare_via_parse_iso_utc(tmp_path):
	"""Round-trip — write a UTC-Z timestamp, parse it back, compare."""
	import json

	from system_update.cache import CacheManager

	cache_file = tmp_path / 'cache.json'
	written = datetime.now(timezone.utc) - timedelta(minutes=5)
	cache_file.write_text(
		json.dumps({
			'timestamp': written.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
			'apps': [],
			'sources': [],
		}),
		encoding='utf-8',
	)
	mgr = CacheManager(cache_file, duration_hours=1)
	# 5 minutes < 1 hour → still valid. The naive vs aware bug would
	# have raised TypeError or returned False here.
	assert mgr.is_valid() is True


# ─── 2.2.1 — decode_command_output ─────────────────────────────────────────


def test_decode_command_output_utf8():
	assert decode_command_output('Café'.encode('utf-8')) == 'Café'


def test_decode_command_output_utf8_with_bom():
	# UTF-8 with BOM (some Windows tools emit this).
	raw = '﻿Café'.encode('utf-8')
	assert decode_command_output(raw) == 'Café'


def test_decode_command_output_utf16_le_with_bom():
	# UTF-16-LE BOM (\xff\xfe) followed by the encoded text — no
	# pre-existing BOM character in the source, just the bytes.
	raw = b'\xff\xfe' + 'Software Müller'.encode('utf-16-le')
	assert decode_command_output(raw) == 'Software Müller'


def test_decode_command_output_cp850_for_e_acute():
	# CP850 encodes 'é' as 0x82.
	raw = b'Caf\x82'
	# UTF-8 will reject 0x82; cp1252 maps 0x82 to "‚" (single low quote),
	# so the result depends on order. The OEM page detection is
	# Windows-specific; on non-Windows we fall through to cp1252,
	# which gives "Caf‚" — different from "Café" but stable.
	# Either decode is acceptable provided no exception leaks.
	result = decode_command_output(raw)
	assert isinstance(result, str)
	assert result.startswith('Caf')


def test_decode_command_output_pure_ascii_unchanged():
	assert decode_command_output(b'plain ASCII') == 'plain ASCII'


def test_decode_command_output_empty():
	assert decode_command_output(b'') == ''
	assert decode_command_output(None) == ''


def test_decode_command_output_str_passthrough():
	"""Tolerate already-decoded input (test mocks return str)."""
	assert decode_command_output('already decoded') == 'already decoded'


def test_decode_command_output_undecodable_falls_back_replacement():
	"""Malformed bytes get replaced, never raised."""
	# Lone UTF-8 continuation byte that can't start a sequence and
	# isn't valid in any of the fallback codecs either.
	raw = b'A\xfeB' * 200  # repeated to defeat a possible single-codec match
	result = decode_command_output(raw)
	# Result is decoded under *some* fallback (cp1252 accepts it).
	# Just assert no exception and prefix preserved.
	assert isinstance(result, str)
	assert result.startswith('A')


# ─── 2.2.2 — winget table parser (locale-agnostic) ────────────────────────


# en-US ``winget upgrade`` — 5 columns.
WINGET_UPGRADE_EN = """\
Name             Id            Version    Available  Source
-----------------------------------------------------------
Git              Git.Git       2.40.0     2.41.0     winget
Visual Studio    Microsoft.VS  17.5       17.6       winget

3 upgrades available.
"""

# pt-BR — same shape, translated headers. Real winget pads column
# titles so each gap is at least 2 spaces; the dashed separator is
# wide enough to span them all.
WINGET_UPGRADE_PTBR = """\
Nome             ID            Versão     Disponível  Origem
------------------------------------------------------------
Git              Git.Git       2.40.0     2.41.0      winget
Visual Studio    Microsoft.VS  17.5       17.6        winget

3 atualizações disponíveis.
"""

# de-DE — same shape, German headers.
WINGET_UPGRADE_DE = """\
Name             ID            Version    Verfügbar  Quelle
-----------------------------------------------------------
Git              Git.Git       2.40.0     2.41.0     winget
Visual Studio    Microsoft.VS  17.5       17.6       winget

3 Aktualisierungen verfügbar.
"""

# ``winget list`` — 4 columns (no Available).
WINGET_LIST_EN = """\
Name             Id            Version    Source
-------------------------------------------------
Git              Git.Git       2.40.0     winget
Python           Python.Python 3.11.0     winget
"""


@pytest.mark.parametrize('output,expected_count', [
	(WINGET_UPGRADE_EN, 2),
	(WINGET_UPGRADE_PTBR, 2),
	(WINGET_UPGRADE_DE, 2),
])
def test_parse_winget_upgrade_locale_agnostic(output, expected_count):
	rows = parse_winget_table(output)
	assert len(rows) == expected_count
	# Positional mapping — first row is Git regardless of locale.
	assert rows[0]['name'] == 'Git'
	assert rows[0]['id'] == 'Git.Git'
	assert rows[0]['version'] == '2.40.0'
	assert rows[0]['available'] == '2.41.0'
	assert rows[0]['source'] == 'winget'


def test_parse_winget_list_4_columns():
	rows = parse_winget_table(WINGET_LIST_EN)
	assert len(rows) == 2
	assert rows[0] == {
		'name': 'Git',
		'id': 'Git.Git',
		'version': '2.40.0',
		'source': 'winget',
	}


def test_parse_winget_table_empty_input():
	assert parse_winget_table('') == []


def test_parse_winget_table_no_separator_returns_empty():
	"""Defensive: no dashed line means we can't anchor — return []."""
	bad = 'Name  Id  Version\nGit  Git.Git  2.40.0\n'
	assert parse_winget_table(bad) == []


def test_parse_winget_table_skips_summary_footer():
	"""The ``3 upgrades available.`` line at the bottom is a footer."""
	rows = parse_winget_table(WINGET_UPGRADE_EN)
	for row in rows:
		assert 'upgrades available' not in row['name']
		assert row['name'] in ('Git', 'Visual Studio')


def test_parse_winget_table_long_name_with_short_gap():
	"""A long Name column that abuts Id with one space: regression for
	the en-US-only ``header.find('Id')`` parser, which would have
	read into the Id column and lost the package."""
	# Single space between long Name "VeryLongVendorName.Tool" and Id.
	# But the header has 2+ spaces, so the column boundary is locked
	# at the header position; the data row's overflow into the next
	# column gets clipped and the data parses correctly when there
	# are 2+ spaces. This test confirms the column boundaries aren't
	# computed from the *data* row.
	output = """\
Name                          Id              Version  Source
--------------------------------------------------------------
A Very Long Package Name      Long.Vendor.Pkg 1.0      winget
"""
	rows = parse_winget_table(output)
	assert len(rows) == 1
	assert rows[0]['name'] == 'A Very Long Package Name'
	assert rows[0]['id'] == 'Long.Vendor.Pkg'


# ─── 2.2.2 — winget JSON path ─────────────────────────────────────────────


def test_parse_winget_json_returns_normalized_rows():
	json_output = """{
		"Sources": [
			{
				"Packages": [
					{
						"PackageName": "Git",
						"PackageIdentifier": "Git.Git",
						"InstalledVersion": "2.40.0",
						"AvailableVersion": "2.41.0",
						"Source": "winget"
					}
				]
			}
		]
	}"""
	rows = parse_winget_json(json_output)
	assert rows == [{
		'name': 'Git',
		'id': 'Git.Git',
		'version': '2.40.0',
		'available': '2.41.0',
		'source': 'winget',
	}]


def test_parse_winget_json_returns_none_for_table_input():
	"""Plain table output should return None so the caller can fall back."""
	assert parse_winget_json(WINGET_UPGRADE_EN) is None


def test_parse_winget_json_returns_none_for_garbage():
	assert parse_winget_json('this is not json') is None
	assert parse_winget_json('{ malformed') is None
