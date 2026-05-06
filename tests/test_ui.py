import sys
import subprocess
import functools
import pytest
from rich.console import Console
import system_update.ui.system as ui_system
from system_update import AppInfo, ThemeManager, DisplayFormatter, UpdateStatus

PYTHON = sys.executable


@functools.lru_cache(maxsize=128)
def run_cli_cached(args_tuple, timeout=60):
	args = list(args_tuple)
	result = subprocess.run(
		[PYTHON, '-m', 'system_update'] + args,
		capture_output=True,
		text=True,
		timeout=timeout,
		encoding='utf-8',
		errors='ignore',
	)
	return {'code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}


def run_cli(args, timeout=60):
	return run_cli_cached(tuple(args), timeout)


def test_banner_shows_all_config_files():
	res = run_cli(['--source', 'chocolatey', '--no-cache'], timeout=120)
	output = res['stdout'] + res['stderr']
	assert 'cache.json' in output.lower()
	assert 'config.json' in output.lower()
	assert 'system.log' in output.lower()
	assert 'errors.log' in output.lower()
	assert 'vulnerability_history' in output.lower()


def test_cli_themes_execution():
	for theme in ['vibrant', 'minimal']:
		res = run_cli(['--theme', theme, '--source', 'chocolatey'], timeout=60)
		assert res['code'] == 0


def test_cli_formats_execution():
	res = run_cli(['--format', 'json', '--source', 'chocolatey'], timeout=60)
	assert res['code'] == 0 and '{' in res['stdout']

	res = run_cli(['--format', 'compact', '--source', 'chocolatey'], timeout=60)
	assert res['code'] == 0


def test_summary_source_chips_include_icons(monkeypatch):
	console = Console(record=True, width=180)
	monkeypatch.setattr(ui_system, 'console', console)

	ui_system.display_summary(
		total_apps=3,
		updates=1,
		scan_time=0.01,
		sources_count={'winget': 2, 'demo': 1},
	)

	output = console.export_text()
	assert '📦 winget:2' in output
	assert '🧩 demo:1' in output


def test_summary_wraps_source_chips_inside_panel(monkeypatch):
	console = Console(record=True, width=220)
	monkeypatch.setattr(ui_system, 'console', console)

	ui_system.display_summary(
		total_apps=625,
		updates=105,
		scan_time=0,
		sources_count={
			'winget': 243,
			'registry': 105,
			'pip': 85,
			'appx': 78,
			'msix': 57,
			'chocolatey': 21,
			'npm': 20,
			'path': 12,
			'demo': 1,
			'dotnet': 1,
			'rust': 1,
			'yarn': 1,
		},
		security_stats={
			'total_vulnerabilities': 2,
			'packages_affected': 2,
			'persistent_vulnerabilities': 0,
			'severity_breakdown': {'MEDIUM': 2},
		},
	)

	output = console.export_text()
	all_lines = output.splitlines()
	border_lines = [
		line for line in all_lines
		if line.startswith('┌') or line.startswith('├') or line.startswith('└')
	]
	content_lines = [line for line in all_lines if line.startswith('│')]

	# Real regression: top and bottom panel borders must agree on width.
	# The previous pre-wrapping helper miscounted emoji-with-variation-
	# selector cells and let the title/border drift apart by one cell.
	# (Note: content-line ``len()`` legitimately differs from border length
	# because Python counts code points but terminals render most emoji as
	# two cells; Rich pads to its own measurement, which is what the
	# terminal sees once rendered.)
	assert border_lines, 'panel produced no border lines'
	assert content_lines, 'panel produced no content lines'
	border_widths = {len(line) for line in border_lines}
	assert len(border_widths) == 1, (
		f'panel borders disagree on width: {border_widths}'
	)
	assert all(line.endswith('│') for line in content_lines)

	# All chip data is rendered (across however many lines Rich chose).
	assert '📚 npm:20' in output
	assert '🧶 yarn:1' in output
	assert '✨ Sources:' in output


def test_package_table_uses_plugin_fallback_icon():
	apps = [
		AppInfo(
			name='Demo Package',
			source='demo',
			version='1.0.0',
			latest_version='1.1.0',
			update_status=UpdateStatus.UPDATE_AVAILABLE,
		)
	]
	table = DisplayFormatter.format_table(apps, 'auto', show_all=True)
	console = Console(record=True, width=120)
	console.print(table)
	output = console.export_text()
	assert '🧩 demo' in output


def test_display_formatter_diff():
	apps = [
		AppInfo(name='Test', source='npm', version='1.0.0'),
		AppInfo(name='Test2', source='pip', version='2.0.0'),
	]
	table = DisplayFormatter.format_table(apps, 'diff')
	assert table is not None


def test_display_formatter_html():
	apps = [AppInfo(name='Test', source='npm', version='1.0.0')]
	table = DisplayFormatter.format_table(apps, 'html')
	assert table is not None


def test_display_formatter_markdown():
	apps = [AppInfo(name='Test', source='npm', version='1.0.0')]
	table = DisplayFormatter.format_table(apps, 'markdown')
	assert table is not None


def test_display_formatter_xml():
	apps = [AppInfo(name='Test', source='npm', version='1.0.0')]
	table = DisplayFormatter.format_table(apps, 'xml')
	assert table is not None


@pytest.mark.parametrize(
	'format', ['compact', 'verbose', 'json', 'auto', 'diff', 'html', 'markdown', 'xml']
)
def test_display_formatter_all_formats(format):
	apps = [AppInfo(name='Test', source='npm', version='1.0.0')]
	table = DisplayFormatter.format_table(apps, format)
	assert table is not None


@pytest.mark.parametrize('format_mode', ['auto', 'verbose', 'json'])
def test_display_formatter_renders_sources_lowercase(format_mode):
	apps = [
		AppInfo(
			name='Demo',
			source='PIP',
			version='1.0.0',
			latest_version='1.1.0',
			update_status=UpdateStatus.UPDATE_AVAILABLE,
		)
	]
	table = DisplayFormatter.format_table(apps, format_mode, show_all=True)
	console = Console(record=True, width=120)
	console.print(table)
	output = console.export_text()
	assert 'pip' in output
	assert 'PIP' not in output


def test_theme_manager_default():
	theme = ThemeManager.get_theme('default')
	assert theme is not None


def test_theme_manager_all_themes():
	themes = ['default', 'vibrant', 'minimal', 'dark', 'neon']
	for theme_name in themes:
		theme = ThemeManager.get_theme(theme_name)
		assert theme is not None


def test_theme_manager_status_colors():
	for status in ['up_to_date', 'outdated', 'vulnerable', 'unknown']:
		color = ThemeManager.get_status_color(status, 'default')
		assert color is not None
