import sys
import subprocess
import functools
import pytest
from pathlib import Path
from system_update import AppInfo, ThemeManager, DisplayFormatter

SCRIPT = Path(__file__).parent.parent / 'system_update.py'
PYTHON = sys.executable


@functools.lru_cache(maxsize=128)
def run_cli_cached(args_tuple, timeout=60):
	args = list(args_tuple)
	result = subprocess.run(
		[PYTHON, str(SCRIPT)] + args,
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


def test_cli_icons_execution():
	res = run_cli(['--icons', '--source', 'chocolatey'], timeout=60)
	assert res['code'] == 0


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
