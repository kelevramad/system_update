"""Hardening 5.3 — Hypothesis fuzz tests for scanner parsers.

Each parser must either return a (possibly empty) list of records or
raise a parser-specific exception. It must NOT crash with
``IndexError``/``KeyError``/``AttributeError`` on adversarial input.

These tests are marked ``slow`` so the regular suite stays fast; run
with ``-m slow`` (or remove the marker for CI fuzz jobs).
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from system_update.scanners import bun, chocolatey, rust, scoop, yarn
from system_update.scanners._winget_table import parse_winget_json, parse_winget_table


# ─── Text strategies ─────────────────────────────────────────────────────


_HUMAN_TEXT = st.text(
	alphabet=st.characters(
		blacklist_categories=('Cs',),
		blacklist_characters='\x00\r',
	),
	max_size=80,
)

_VERSION = st.text(
	alphabet='0123456789.-+abcdef',
	min_size=1,
	max_size=20,
)

_NAME = st.text(
	alphabet=st.characters(blacklist_categories=('Cs',), blacklist_characters='\x00\r\n@" '),
	min_size=1,
	max_size=20,
)


def _row(width=4):
	def build(cells):
		gap = ' ' * 3
		return gap.join(cells).rstrip()

	return st.builds(build, st.lists(_HUMAN_TEXT, min_size=width, max_size=width))


_TABLE = st.builds(
	'\n'.join,
	st.lists(
		st.one_of(
			st.just('Name                          Id            Version       Source'),
			st.just('-' * 80),
			_row(width=4),
			st.text(max_size=80),
		),
		min_size=2,
		max_size=20,
	),
)


_SLOW_SETTINGS = settings(
	max_examples=500,
	deadline=None,
	suppress_health_check=[
		HealthCheck.too_slow,
		HealthCheck.filter_too_much,
	],
)


# ─── Property: parsers never crash ───────────────────────────────────────


@pytest.mark.slow
@_SLOW_SETTINGS
@given(text=_TABLE)
def test_parse_winget_table_does_not_crash_on_garbage(text):
	rows = parse_winget_table(text)
	assert isinstance(rows, list)


@pytest.mark.slow
@_SLOW_SETTINGS
@given(text=st.text(max_size=400))
def test_parse_winget_json_does_not_crash_on_garbage(text):
	result = parse_winget_json(text)
	assert result is None or isinstance(result, list)


@pytest.mark.slow
@_SLOW_SETTINGS
@given(rows=st.lists(st.tuples(_NAME, _VERSION), max_size=15))
def test_bun_scanner_parser_does_not_crash(rows):
	output = '\n'.join(f'  {name}@{version}' for name, version in rows)
	with patch('system_update.scanners.bun.run_command', return_value=output):
		apps = bun.scan()
	for app in apps:
		assert app.name
		assert app.version


@pytest.mark.slow
@_SLOW_SETTINGS
@given(rows=st.lists(st.tuples(_NAME, _VERSION), max_size=15))
def test_rust_scanner_parser_does_not_crash(rows):
	output = '\n'.join(f'{name} v{version}:' for name, version in rows)
	with patch('system_update.scanners.rust.run_command', return_value=output):
		apps = rust.scan()
	for app in apps:
		assert app.name
		assert app.version


@pytest.mark.slow
@_SLOW_SETTINGS
@given(rows=st.lists(st.tuples(_NAME, _VERSION), max_size=15))
def test_yarn_scanner_parser_does_not_crash(rows):
	output = '\n'.join(f'info "{name}@{version}"' for name, version in rows)
	with patch('system_update.scanners.yarn.run_command', return_value=output):
		apps = yarn.scan()
	for app in apps:
		assert app.name
		assert app.version


@pytest.mark.slow
@_SLOW_SETTINGS
@given(
	rows=st.lists(
		st.tuples(
			st.text(
				alphabet=st.characters(
					blacklist_categories=('Cs',),
					blacklist_characters='\x00\r\n\t ',
				),
				min_size=1,
				max_size=15,
			),
			_VERSION,
		),
		max_size=15,
	)
)
def test_scoop_scanner_parser_does_not_crash(rows):
	header = 'Name      Version   Source\n----      -------   ------'
	body = '\n'.join(f'{name} {version}' for name, version in rows)
	output = f'{header}\n{body}'
	with patch('system_update.scanners.scoop.run_command', return_value=output):
		apps = scoop.scan()
	for app in apps:
		assert app.name
		assert app.version


@pytest.mark.slow
@_SLOW_SETTINGS
@given(rows=st.lists(st.tuples(_NAME, _VERSION), max_size=15))
def test_choco_scanner_parser_does_not_crash(rows):
	output = '\n'.join(f'{name}|{version}' for name, version in rows)
	with patch('system_update.scanners.chocolatey.run_command', return_value=output):
		apps = chocolatey.scan()
	for app in apps:
		assert app.name
		assert app.version


# ─── Adversarial pure-garbage shapes ─────────────────────────────────────


@pytest.mark.slow
@_SLOW_SETTINGS
@given(garbage=st.text(max_size=500))
def test_scoop_scanner_survives_arbitrary_text(garbage):
	with patch('system_update.scanners.scoop.run_command', return_value=garbage):
		apps = scoop.scan()
	assert isinstance(apps, list)


@pytest.mark.slow
@_SLOW_SETTINGS
@given(garbage=st.text(max_size=500))
def test_choco_scanner_survives_arbitrary_text(garbage):
	with patch('system_update.scanners.chocolatey.run_command', return_value=garbage):
		apps = chocolatey.scan()
	assert isinstance(apps, list)
