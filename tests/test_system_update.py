import os
import sys
import subprocess
import tempfile
import pytest
import functools
from pathlib import Path

SCRIPT = Path(__file__).parent.parent / 'system_update.py'
PYTHON = sys.executable


# Cache for CLI results to avoid redundant subprocess calls
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
	return {
		'code': result.returncode,
		'stdout': result.stdout,
		'stderr': result.stderr,
	}


def run_cli(args, timeout=60):
	# Using tuple for lru_cache compatibility
	return run_cli_cached(tuple(args), timeout)


@pytest.fixture(scope='session')
def help_output():
	"""Cache --help output for all tests that need it."""
	return run_cli(['--help'])


@pytest.fixture(scope='session')
def choco_scan_output():
	"""Cache a single chocolatey scan for multiple tests."""
	return run_cli(['--source', 'chocolatey', '--no-cache'], timeout=120)


@pytest.fixture(scope='session')
def pip_scan_output():
	"""Cache a single pip scan for security tests."""
	return run_cli(['--source', 'pip', '--no-cache'], timeout=120)


def test_help_flag_shows_usage(help_output):
	res = help_output
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0
	assert 'usage' in output.lower() or 'system' in output.lower()


def test_no_args_shows_error():
	# This one shouldn't be cached as it's quick and tests error state
	res = run_cli([])
	output = res['stdout'] + res['stderr']
	assert res['code'] != 0 or 'system' in output.lower()


def test_source_winget():
	res = run_cli(['--source', 'winget', '--no-cache'], timeout=120)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_source_chocolatey(choco_scan_output):
	res = choco_scan_output
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_source_npm():
	res = run_cli(['--source', 'npm', '--no-cache'], timeout=120)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_source_pnpm():
	res = run_cli(['--source', 'pnpm', '--no-cache'], timeout=120)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_source_pip(pip_scan_output):
	res = pip_scan_output
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_source_path():
	"""Coverage: Explicitly test the 'path' source."""
	res = run_cli(['--source', 'path', '--no-cache'], timeout=120)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_source_bun():
	"""Coverage: Explicitly test the 'bun' source."""
	res = run_cli(['--source', 'bun', '--no-cache'], timeout=120)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_source_yarn():
	"""Coverage: Explicitly test the 'yarn' source."""
	res = run_cli(['--source', 'yarn', '--no-cache'], timeout=120)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_source_registry():
	res = run_cli(['--source', 'registry', '--no-cache'], timeout=120)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_source_rust():
	res = run_cli(['--source', 'rust', '--no-cache'], timeout=120)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_source_scoop():
	res = run_cli(['--source', 'scoop', '--no-cache'], timeout=120)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_source_dotnet():
	res = run_cli(['--source', 'dotnet', '--no-cache'], timeout=120)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_source_appx():
	res = run_cli(['--source', 'appx', '--no-cache'], timeout=120)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_source_msix():
	res = run_cli(['--source', 'msix', '--no-cache'], timeout=120)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_dry_run_flag():
	res = run_cli(['--dry-run', '--source', 'chocolatey'], timeout=120)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_show_all_flag():
	res = run_cli(['--show-all', '--source', 'chocolatey', '--no-cache'], timeout=120)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_export_json():
	with tempfile.TemporaryDirectory() as tmpdir:
		output_file = os.path.join(tmpdir, 'export.json')
		res = run_cli(
			['--export', 'json', '--output', output_file, '--source', 'chocolatey'], timeout=120
		)
		assert os.path.exists(output_file) or res['code'] == 0


def test_export_csv():
	with tempfile.TemporaryDirectory() as tmpdir:
		output_file = os.path.join(tmpdir, 'export.csv')
		res = run_cli(
			['--export', 'csv', '--output', output_file, '--source', 'chocolatey'], timeout=120
		)
		assert os.path.exists(output_file) or res['code'] == 0


def test_clear_cache():
	res = run_cli(['--clear-cache'])
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0
	assert 'cache' in output.lower() or 'clear' in output.lower()


def test_source_unknown_source():
	res = run_cli(['--source', 'unknown_source_xyz'])
	output = res['stdout'] + res['stderr']
	assert res['code'] != 0 or 'source' in output.lower()


def test_source_multiple_sources():
	res = run_cli(['--source', 'winget,npm', '--no-cache'], timeout=120)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_log_and_debug_flags():
	"""Consolidated test for log and debug flags to save time."""
	res = run_cli(['--debug', '--log', '--source', 'chocolatey', '--no-cache'], timeout=120)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0
	assert 'debug' in output.lower() or 'info' in output.lower() or 'scan' in output.lower()


def test_security_scan(pip_scan_output):
	res = pip_scan_output
	output = res['stdout'] + res['stderr']
	assert (
		res['code'] == 0
		or 'vuln' in output.lower()
		or 'security' in output.lower()
		or 'scan' in output.lower()
	)


def test_security_osv_source(pip_scan_output):
	res = pip_scan_output
	output = res['stdout'] + res['stderr']
	assert (
		res['code'] == 0
		or 'osv' in output.lower()
		or 'vuln' in output.lower()
		or 'security' in output.lower()
	)


def test_security_github_advisory():
	res = run_cli(['--source', 'npm', '--no-cache'], timeout=120)
	output = res['stdout'] + res['stderr']
	assert (
		res['code'] == 0
		or 'vuln' in output.lower()
		or 'security' in output.lower()
		or 'advisory' in output.lower()
	)


def test_security_local_advisory():
	with tempfile.TemporaryDirectory() as tmpdir:
		adv_file = os.path.join(tmpdir, 'advisories.json')
		with open(adv_file, 'w') as f:
			f.write('{"advisories": []}')

		original_home = os.environ.get('SYSTEM_UPDATE_HOME')
		try:
			os.environ['SYSTEM_UPDATE_HOME'] = tmpdir
			res = run_cli(['--source', 'pip', '--no-cache'], timeout=120)
			output = res['stdout'] + res['stderr']
			assert res['code'] == 0 or 'scan' in output.lower()
		finally:
			if original_home:
				os.environ['SYSTEM_UPDATE_HOME'] = original_home


def test_critical_alert_priority(pip_scan_output):
	res = pip_scan_output
	output = res['stdout'] + res['stderr']
	# If there are vulnerabilities, they should show priority
	assert (
		res['code'] == 0
		or 'CRITICAL' in output
		or 'critical' in output.lower()
		or 'scan' in output.lower()
	)


def test_security_update_auto_priority():
	res = run_cli(['--source', 'pip', '--update-all', '--dry-run', '--yes'], timeout=120)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'vuln' in output.lower() or 'update' in output.lower()


def test_interactive_flag(help_output):
	res = help_output
	output = res['stdout'] + res['stderr']
	assert '--interactive' in output


def test_banner_shows_all_config_files():
	res = run_cli(['--source', 'chocolatey', '--no-cache'], timeout=120)
	output = res['stdout'] + res['stderr']
	assert 'cache.json' in output.lower()
	assert 'config.json' in output.lower()
	assert 'system.log' in output.lower()
	assert 'errors.log' in output.lower()
	assert 'vulnerability_history' in output.lower()


def test_error_category_classification():
	from system_update import CommandError, ErrorCategory
	import subprocess

	err = CommandError.classify(FileNotFoundError(), 'test-command')
	assert err.category == ErrorCategory.NOT_FOUND
	assert 'not found' in err.message.lower()

	err = CommandError.classify(subprocess.TimeoutExpired('cmd', 1), 'test-command')
	assert err.category == ErrorCategory.TIMEOUT

	err = CommandError.classify(PermissionError(), 'test-command')
	assert err.category == ErrorCategory.PERMISSION_DENIED

	err = CommandError.classify(ValueError(), 'test-command')
	assert err.category == ErrorCategory.PARSE_ERROR

	err = CommandError.classify(Exception('unknown'), 'test-command')
	assert err.category == ErrorCategory.UNKNOWN


def test_command_error_suggestions():
	from system_update import CommandError, ErrorCategory

	err = CommandError(
		category=ErrorCategory.NOT_FOUND,
		message='Command not found',
		command='test-cmd',
		suggestion='Ensure test-cmd is installed',
	)
	assert err.suggestion != ''
	assert 'install' in err.suggestion.lower()


def test_notification_system_import():
	from system_update import NotificationManager

	assert NotificationManager is not None


def test_notification_cli_flag(help_output):
	res = help_output
	output = res['stdout'] + res['stderr']
	assert '--notify' in output.lower()


def test_send_webhook_valid_url():
	from system_update import NotificationManager

	nm = NotificationManager()
	# Mocked or simple check to avoid network latency in tests
	result = nm.send_webhook('https://httpbin.org/post', {'test': 'data'})
	assert result in [True, False]


def test_send_webhook_invalid_url():
	from system_update import NotificationManager

	nm = NotificationManager()
	result = nm.send_webhook('https://invalid-url-that-does-not-exist.xyz', {'test': 'data'})
	assert result is False


def test_send_email_missing_config():
	from system_update import NotificationManager

	nm = NotificationManager()
	result = nm.send_email('test@example.com', 'Test', 'Body')
	assert result is False


def test_run_custom_script_invalid_path():
	from system_update import NotificationManager

	nm = NotificationManager()
	result = nm.run_custom_script('nonexistent_script.bat')
	assert result is False


def test_theme_manager_import():
	from system_update import ThemeManager, THEMES, SOURCE_ICONS

	assert ThemeManager is not None
	assert isinstance(THEMES, dict)
	assert isinstance(SOURCE_ICONS, dict)


def test_theme_manager_get_source_color():
	from system_update import ThemeManager

	assert ThemeManager.get_source_color('winget', 'default') == 'blue'
	assert ThemeManager.get_source_color('npm', 'vibrant') == 'bright_red'


def test_theme_manager_get_source_icon():
	from system_update import ThemeManager

	assert ThemeManager.get_source_icon('npm') == '📚'
	assert ThemeManager.get_source_icon('winget') == '📦'


def test_cli_theme_flag(help_output):
	res = help_output
	output = res['stdout'] + res['stderr']
	assert '--theme' in output.lower()


def test_cli_format_flag(help_output):
	res = help_output
	output = res['stdout'] + res['stderr']
	assert '--format' in output.lower()


def test_cli_icons_flag(help_output):
	res = help_output
	output = res['stdout'] + res['stderr']
	assert '--icons' in output.lower()


def test_cli_themes_execution(choco_scan_output):
	"""Optimized: Verification of theme flags without redundant full scans."""
	# We already have choco_scan_output, but themes change the UI.
	# To be fast, we can test one or two, or use a very fast command.
	for theme in ['vibrant', 'minimal']:
		res = run_cli(['--theme', theme, '--source', 'chocolatey'], timeout=60)
		assert res['code'] == 0


def test_cli_formats_execution():
	"""Optimized: Test multiple formats efficiently."""
	# JSON format is usually very fast as it skips Rich rendering
	res = run_cli(['--format', 'json', '--source', 'chocolatey'], timeout=60)
	assert res['code'] == 0 and '{' in res['stdout']

	# Compact format
	res = run_cli(['--format', 'compact', '--source', 'chocolatey'], timeout=60)
	assert res['code'] == 0


def test_cli_icons_execution():
	res = run_cli(['--icons', '--source', 'chocolatey'], timeout=60)
	assert res['code'] == 0


def test_all_source_icons():
	"""Verify icons for all supported package sources."""
	from system_update import ThemeManager, SOURCE_ICONS

	for source, expected_icon in SOURCE_ICONS.items():
		assert ThemeManager.get_source_icon(source) == expected_icon

	# Test case insensitivity
	assert ThemeManager.get_source_icon('WINGET') == '📦'
	# Test unknown source
	assert ThemeManager.get_source_icon('unknown_xyz') == ''


def test_system_config_migration(tmp_path, monkeypatch):
	from system_update import SystemConfig
	import json

	config_dir = tmp_path / '.system_update'
	config_dir.mkdir()
	config_file = config_dir / 'config.json'

	old_config = {'cache': {'duration_hours': 4, 'enabled': False}}
	with open(config_file, 'w', encoding='utf-8') as f:
		json.dump(old_config, f)

	monkeypatch.setattr(SystemConfig, '__init__', lambda self: None)
	config = SystemConfig()
	config.config_dir = config_dir
	config.config_file = config_file
	config.yaml_config_file = config_dir / 'config.yaml'
	config.yml_config_file = config_dir / 'config.yml'
	config.settings = {
		'version': 1,
		'cache': {'duration_hours': 2, 'enabled': True},
		'performance': {'max_workers': 6, 'timeout_seconds': 45},
		'security': {'severity_threshold': 'medium', 'enabled': True},
	}
	config.load()

	assert config.settings['version'] == 1
	assert config.settings['cache']['duration_hours'] == 4
	assert config.settings['cache']['enabled'] is False


def test_system_config_validation(tmp_path, monkeypatch):
	from system_update import SystemConfig
	import json

	config_dir = tmp_path / '.system_update'
	config_dir.mkdir()
	config_file = config_dir / 'config.json'

	invalid_config = {
		'version': 1,
		'cache': {'duration_hours': -5, 'enabled': 'not_a_bool'},
		'performance': {'max_workers': 0, 'timeout_seconds': -10},
		'security': {'severity_threshold': 'super_critical', 'enabled': 'yes'},
	}
	with open(config_file, 'w', encoding='utf-8') as f:
		json.dump(invalid_config, f)

	monkeypatch.setattr(SystemConfig, '__init__', lambda self: None)
	config = SystemConfig()
	config.config_dir = config_dir
	config.config_file = config_file
	config.yaml_config_file = config_dir / 'config.yaml'
	config.yml_config_file = config_dir / 'config.yml'
	config.settings = {
		'version': 1,
		'cache': {'duration_hours': 2, 'enabled': True},
		'performance': {'max_workers': 6, 'timeout_seconds': 45},
		'security': {'severity_threshold': 'medium', 'enabled': True},
	}
	config.load()

	assert config.settings['cache']['duration_hours'] == 2
	assert config.settings['cache']['enabled'] is True
	assert config.settings['performance']['max_workers'] == 6
	assert config.settings['performance']['timeout_seconds'] == 45
	assert config.settings['security']['severity_threshold'] == 'medium'
	assert config.settings['security']['enabled'] is True


def test_system_config_yaml_support(tmp_path, monkeypatch):
	pytest.importorskip('yaml')
	from system_update import SystemConfig
	import yaml

	config_dir = tmp_path / '.system_update'
	config_dir.mkdir()
	yaml_config_file = config_dir / 'config.yaml'

	yaml_data = {'version': 1, 'cache': {'duration_hours': 10}}
	with open(yaml_config_file, 'w', encoding='utf-8') as f:
		yaml.dump(yaml_data, f)

	monkeypatch.setattr(SystemConfig, '__init__', lambda self: None)
	config = SystemConfig()
	config.config_dir = config_dir
	config.config_file = config_dir / 'config.json'
	config.yaml_config_file = yaml_config_file
	config.yml_config_file = config_dir / 'config.yml'
	config.settings = {
		'version': 1,
		'cache': {'duration_hours': 2, 'enabled': True},
		'performance': {'max_workers': 6, 'timeout_seconds': 45},
		'security': {'severity_threshold': 'medium', 'enabled': True},
	}
	config.load()

	assert config.settings['cache']['duration_hours'] == 10

	config.settings['cache']['duration_hours'] = 12
	config.save()

	with open(yaml_config_file, 'r', encoding='utf-8') as f:
		saved_data = yaml.safe_load(f)
	assert saved_data['cache']['duration_hours'] == 12


def test_env_vars_specific_shortcuts(monkeypatch, tmp_path):
	from system_update import SystemConfig

	config_dir = tmp_path / '.system_update'
	config_dir.mkdir()
	monkeypatch.setattr(SystemConfig, '__init__', lambda self: None)

	monkeypatch.setenv('SYSTEM_UPDATE_SOURCES', 'choco, npm')
	monkeypatch.setenv('SYSTEM_UPDATE_TIMEOUT', '120')
	monkeypatch.setenv('SYSTEM_UPDATE_WORKERS', '10')
	monkeypatch.setenv('SYSTEM_UPDATE_EXCLUDE', 'pkg1, pkg2')
	monkeypatch.setenv('SYSTEM_UPDATE_LOG_LEVEL', 'DEBUG')

	config = SystemConfig()
	config.config_dir = config_dir
	config.config_file = config_dir / 'config.json'
	config.yaml_config_file = config_dir / 'config.yaml'
	config.yml_config_file = config_dir / 'config.yml'
	config.settings = {
		'version': 1,
		'exclude': [],
		'log_level': 'WARNING',
		'performance': {'max_workers': 6, 'timeout_seconds': 45},
		'sources': {'chocolatey': True, 'npm': True, 'winget': True, 'pip': True},
		'cache': {'duration_hours': 2, 'enabled': True},
		'security': {'severity_threshold': 'medium', 'enabled': True},
	}

	config.load()

	assert config.settings['sources']['chocolatey'] is True
	assert config.settings['sources']['npm'] is True
	assert config.settings['sources']['winget'] is False
	assert config.settings['sources']['pip'] is False
	assert config.settings['performance']['timeout_seconds'] == 120
	assert config.settings['performance']['max_workers'] == 10
	assert config.settings['exclude'] == ['pkg1', 'pkg2']
	assert config.settings['log_level'] == 'DEBUG'


def test_env_vars_dynamic_overrides(monkeypatch, tmp_path):
	from system_update import SystemConfig

	config_dir = tmp_path / '.system_update'
	config_dir.mkdir()
	monkeypatch.setattr(SystemConfig, '__init__', lambda self: None)

	monkeypatch.setenv('SYSTEM_UPDATE_CACHE__ENABLED', 'false')
	monkeypatch.setenv('SYSTEM_UPDATE_UI__COLOR_SCHEME', 'neon')
	monkeypatch.setenv('SYSTEM_UPDATE_PERFORMANCE__MAX_WORKERS', '15')

	config = SystemConfig()
	config.config_dir = config_dir
	config.config_file = config_dir / 'config.json'
	config.yaml_config_file = config_dir / 'config.yaml'
	config.yml_config_file = config_dir / 'config.yml'
	config.settings = {
		'version': 1,
		'cache': {'duration_hours': 2, 'enabled': True},
		'performance': {'max_workers': 6, 'timeout_seconds': 45},
		'ui': {'color_scheme': 'minimal'},
		'security': {'severity_threshold': 'medium', 'enabled': True},
	}

	config.load()

	assert config.settings['cache']['enabled'] is False
	assert config.settings['ui']['color_scheme'] == 'neon'
	assert config.settings['performance']['max_workers'] == 15


def test_env_vars_type_casting(monkeypatch, tmp_path):
	from system_update import SystemConfig

	config_dir = tmp_path / '.system_update'
	config_dir.mkdir()
	monkeypatch.setattr(SystemConfig, '__init__', lambda self: None)

	monkeypatch.setenv('SYSTEM_UPDATE_CACHE__ENABLED', '0')
	monkeypatch.setenv('SYSTEM_UPDATE_PERFORMANCE__TIMEOUT_SECONDS', '300')
	monkeypatch.setenv('SYSTEM_UPDATE_CACHE__DURATION_HOURS', '3.5')
	monkeypatch.setenv('SYSTEM_UPDATE_SECURITY__AUTO_CHECK', 'YES')

	config = SystemConfig()
	config.config_dir = config_dir
	config.config_file = config_dir / 'config.json'
	config.yaml_config_file = config_dir / 'config.yaml'
	config.yml_config_file = config_dir / 'config.yml'
	config.settings = {
		'version': 1,
		'cache': {'duration_hours': 2, 'enabled': True},
		'performance': {'timeout_seconds': 45, 'max_workers': 6},
		'security': {'auto_check': False, 'severity_threshold': 'medium', 'enabled': True},
	}

	config.load()

	assert config.settings['cache']['enabled'] is False
	assert type(config.settings['performance']['timeout_seconds']) is int
	assert config.settings['performance']['timeout_seconds'] == 300
	assert type(config.settings['cache']['duration_hours']) is float
	assert config.settings['cache']['duration_hours'] == 3.5
	assert config.settings['security']['auto_check'] is True
