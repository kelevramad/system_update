"""Tests for the sub-help system (`subhelp` module + `--explain` CLI flag)."""

from __future__ import annotations

import functools
import subprocess
import sys

import pytest
from rich.console import Console

from system_update import subhelp


# ─── Module-level API ──────────────────────────────────────────────────────


def test_list_topics_returns_sorted_unique():
	topics = subhelp.list_topics()
	assert topics == sorted(topics)
	assert len(topics) == len(set(topics))
	# Profile aliases must be deduped (same handler).
	assert sum(t.startswith('profile') for t in topics) == 1


def test_list_topics_includes_all_expected():
	expected = {
		'cloud-sync', 'export', 'format', 'history-stale', 'history-trends',
		'import', 'interactive', 'notify', 'report', 'source', 'theme',
		'update-source',
	}
	topics = set(subhelp.list_topics())
	assert expected.issubset(topics)


def test_has_subhelp_known_topic():
	assert subhelp.has_subhelp('cloud-sync') is True
	assert subhelp.has_subhelp('--cloud-sync') is True  # leading dashes stripped
	assert subhelp.has_subhelp('cloud_sync') is True   # underscore normalised


def test_has_subhelp_unknown_topic():
	assert subhelp.has_subhelp('xpto') is False
	assert subhelp.has_subhelp('') is False


def test_show_returns_false_for_unknown_topic(capsys):
	result = subhelp.show('not-a-real-flag')
	assert result is False


@pytest.mark.parametrize('topic', subhelp.list_topics())
def test_every_registered_topic_renders_without_error(topic):
	"""Every page must render to a Rich Console without raising."""
	# Use a recording console so we can assert content was emitted.
	c = Console(record=True, width=120)
	assert subhelp.show(topic, console=c) is True
	out = c.export_text()
	assert len(out) > 100  # non-trivial page
	# Page should mention the flag name somewhere.
	assert topic.split('-')[0].lower() in out.lower()


def test_profile_aliases_share_handler():
	c1 = Console(record=True, width=120)
	c2 = Console(record=True, width=120)
	subhelp.show('profile', console=c1)
	subhelp.show('profile-export', console=c2)
	assert c1.export_text() == c2.export_text()


def test_show_normalizes_dashes_and_underscores():
	c1 = Console(record=True, width=120)
	c2 = Console(record=True, width=120)
	c3 = Console(record=True, width=120)
	subhelp.show('cloud-sync', console=c1)
	subhelp.show('cloud_sync', console=c2)
	subhelp.show('--cloud-sync', console=c3)
	assert c1.export_text() == c2.export_text() == c3.export_text()


def test_cloud_sync_page_mentions_backends():
	c = Console(record=True, width=120)
	subhelp.show('cloud-sync', console=c)
	out = c.export_text()
	assert 'push' in out and 'pull' in out and 'status' in out
	assert 'file' in out and 'http' in out


def test_interactive_page_mentions_selection_syntax():
	c = Console(record=True, width=120)
	subhelp.show('interactive', console=c)
	out = c.export_text()
	assert 'all' in out and 'none' in out
	assert '1,3,5' in out or '5-7' in out


def test_export_page_lists_all_formats():
	c = Console(record=True, width=120)
	subhelp.show('export', console=c)
	out = c.export_text()
	for fmt in ('json', 'csv', 'html', 'xml', 'markdown', 'diff'):
		assert fmt in out


# ─── CLI integration ───────────────────────────────────────────────────────


@functools.lru_cache(maxsize=64)
def _run_cli(args_tuple, timeout=30):
	result = subprocess.run(
		[sys.executable, '-m', 'system_update'] + list(args_tuple),
		capture_output=True, text=True, timeout=timeout,
		encoding='utf-8', errors='replace',
	)
	return {
		'code': result.returncode,
		'stdout': result.stdout,
		'stderr': result.stderr,
	}


def test_cli_explain_list_shows_topics():
	res = _run_cli(('--explain', 'list'))
	assert res['code'] == 0
	out = res['stdout'] + res['stderr']
	assert 'cloud-sync' in out
	assert 'interactive' in out
	assert 'topics' in out.lower() or 'available' in out.lower()


def test_cli_explain_known_topic_renders_page():
	res = _run_cli(('--explain', 'cloud-sync'))
	assert res['code'] == 0
	out = res['stdout'] + res['stderr']
	assert 'push' in out and 'pull' in out


def test_cli_explain_unknown_topic_friendly_error():
	res = _run_cli(('--explain', 'xpto-does-not-exist'))
	assert res['code'] != 0
	out = res['stdout'] + res['stderr']
	# typer.BadParameter rendering — should be a friendly panel, no traceback.
	assert 'Traceback' not in out
	assert 'No detailed help' in out or 'not' in out.lower()
	# Lists available topics.
	assert 'cloud-sync' in out


def test_cli_choice_flag_help_value_renders_page():
	"""``--cloud-sync help`` should print sub-help and exit 0 without scanning."""
	res = _run_cli(('--cloud-sync', 'help'))
	assert res['code'] == 0
	out = res['stdout'] + res['stderr']
	assert 'push' in out and 'pull' in out
	# No scan banners — confirms the CLI short-circuited before app.run().
	assert 'Scanning sources' not in out


def test_cli_export_help_value_renders_page():
	res = _run_cli(('--export', 'help'))
	assert res['code'] == 0
	out = res['stdout'] + res['stderr']
	assert 'json' in out and 'html' in out and 'diff' in out


def test_cli_explain_normalizes_dashes():
	"""``--explain cloud_sync`` should work the same as ``cloud-sync``."""
	res_dash = _run_cli(('--explain', 'cloud-sync'))
	res_underscore = _run_cli(('--explain', 'cloud_sync'))
	assert res_dash['code'] == 0
	assert res_underscore['code'] == 0
	# Output should be effectively identical (modulo any timestamp).
	assert 'push' in res_underscore['stdout'] + res_underscore['stderr']
