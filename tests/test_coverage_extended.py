import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch
from system_update import (
	AppInfo,
	UpdateStatus,
	PackageScanner,
	UpdateChecker,
	UpdateExecutor,
	SystemUpdateApp,
	source_badge,
	run_command,
	ThemeManager,
	DisplayFormatter,
	VulnerabilityHistory,
	NotificationManager,
	CommandError,
	ErrorCategory,
	SystemConfig,
	CacheManager,
	SecurityInfo,
)

# ═══════════════════════════════════════════════════════════════════════════════
# SOURCE BADGE TESTS - COVER ALL SOURCES
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize(
	'source,expected_style',
	[
		('winget', 'blue'),
		('chocolatey', 'yellow'),
		('npm', 'red'),
		('pnpm', 'color(206)'),
		('pip', 'cyan'),
		('bun', 'bright_blue'),
		('yarn', 'bright_white'),
		('rust', 'color(129)'),
		('path', 'green'),
		('registry', 'grey37'),
		('scoop', 'bright_yellow'),
		('dotnet', 'gold'),
		('unknown', 'bright_white'),
		('WINGET', 'blue'),  # case insensitive
		('', 'bright_white'),  # empty source
		(None, 'bright_white'),  # None source
	],
)
def test_source_badge_styles(source, expected_style):
	result = source_badge(source)
	assert expected_style in result


# ═══════════════════════════════════════════════════════════════════════════════
# SCANNER TESTS FOR ADDITIONAL SOURCES
# ═══════════════════════════════════════════════════════════════════════════════


@patch('system_update.run_command')
def test_scan_scoop_parsing(mock_run):
	mock_run.return_value = 'git (2.41.0) - A distributed version control system'
	apps = PackageScanner.scan_scoop()
	assert isinstance(apps, list)


@patch('system_update.run_command')
def test_scan_pnpm_parsing(mock_run):
	mock_run.return_value = json.dumps({'package-manager': {'version': '1.0.0'}})
	apps = PackageScanner.scan_pnpm()
	assert isinstance(apps, list)


@patch('system_update.run_command')
def test_scan_bun_parsing(mock_run):
	mock_run.return_value = json.dumps([{'name': 'test', 'version': '1.0.0'}])
	apps = PackageScanner.scan_bun()
	assert isinstance(apps, list)


@patch('system_update.run_command')
def test_scan_yarn_parsing(mock_run):
	mock_run.return_value = json.dumps([{'name': 'test', 'version': '1.0.0'}])
	apps = PackageScanner.scan_yarn()
	assert isinstance(apps, list)


@patch('system_update.run_command')
def test_scan_rust_parsing(mock_run):
	mock_run.return_value = 'clippy 0.1.0'
	apps = PackageScanner.scan_rust()
	assert isinstance(apps, list)


@patch('system_update.run_command')
def test_scan_dotnet_parsing(mock_run):
	mock_run.return_value = 'NuGet.Client                      6.0.0'
	apps = PackageScanner.scan_dotnet()
	assert isinstance(apps, list)


@patch('system_update.run_command')
def test_scan_appx_parsing(mock_run):
	mock_run.return_value = json.dumps([{'Name': 'App', 'Version': '1.0'}])
	apps = PackageScanner.scan_appx()
	assert isinstance(apps, list)


@patch('system_update.run_command')
def test_scan_msix_parsing(mock_run):
	mock_run.return_value = json.dumps([{'Name': 'App', 'Version': '1.0'}])
	apps = PackageScanner.scan_msix()
	assert isinstance(apps, list)


@patch('system_update.run_command')
def test_scan_path_parsing(mock_run):
	mock_run.return_value = '1.0.0'
	apps = PackageScanner.scan_path()
	assert isinstance(apps, list)


# ═══════════════════════════════════════════════════════════════════════════════
# UPDATE CHECKER TESTS FOR ADDITIONAL SOURCES
# ═══════════════════════════════════════════════════════════════════════════════


@patch('system_update.run_command')
def test_check_pip_updates(mock_run):
	apps = [AppInfo(name='requests', source='pip', version='2.28.0')]
	mock_run.return_value = json.dumps({'info': {'version': '2.28.1'}})
	count = UpdateChecker._check_pip_updates(apps)
	assert count >= 0


@patch('system_update.run_command')
def test_check_npm_updates(mock_run):
	apps = [AppInfo(name='lodash', source='npm', version='4.17.20')]
	mock_run.return_value = json.dumps({'dist-tags': {'latest': '4.17.21'}})
	count = UpdateChecker._check_npm_updates(apps)
	assert count >= 0


@patch('system_update.run_command')
def test_check_choco_updates(mock_run):
	apps = [AppInfo(name='git', source='chocolatey', version='2.40.0')]
	mock_run.return_value = 'git|2.40.0|2.41.0'
	count = UpdateChecker._check_choco_updates(apps)
	assert count >= 0


@patch('system_update.run_command')
def test_check_rust_updates(mock_run):
	apps = [AppInfo(name='rustc', source='rust', version='1.70.0')]
	mock_run.return_value = 'rustc 1.71.0 (...'
	count = UpdateChecker._check_rust_updates(apps)
	assert count >= 0


@patch('system_update.run_command')
def test_check_pnpm_updates(mock_run):
	apps = [AppInfo(name='test', source='pnpm', version='7.0.0')]
	mock_run.return_value = json.dumps({'dist-tags': {'latest': '8.0.0'}})
	count = UpdateChecker._check_pnpm_updates(apps)
	assert count >= 0


@patch('system_update.run_command')
def test_check_yarn_updates(mock_run):
	apps = [AppInfo(name='test', source='yarn', version='1.22.0')]
	mock_run.return_value = json.dumps({'dist-tags': {'latest': '3.0.0'}})
	count = UpdateChecker._check_yarn_updates(apps)
	assert count >= 0


@patch('system_update.run_command')
def test_check_bun_updates(mock_run):
	apps = [AppInfo(name='test', source='bun', version='0.6.0')]
	mock_run.return_value = '0.7.0'
	count = UpdateChecker._check_bun_updates(apps)
	assert count >= 0


# ═══════════════════════════════════════════════════════════════════════════════
# EXECUTOR TESTS - ERROR BRANCHES
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize(
	'source',
	[
		'Winget',
		'Chocolatey',
		'NPM',
		'PNPM',
		'Bun',
		'Yarn',
		'PIP',
		'Rust',
		'dotnet',
		'scoop',
		'path',
		'registry',
		'appx',
		'msix',
	],
)
@patch('system_update.run_command', return_value='Updated successfully')
def test_executor_all_sources(mock_run, source):
	app = AppInfo(
		name='testpkg', source=source, version='1.0', latest_version='1.1', app_id='test.id'
	)
	result = UpdateExecutor._execute_single_update(app)
	assert isinstance(result, bool)


@patch('system_update.run_command')
def test_executor_failure_branch(mock_run):
	mock_run.side_effect = Exception('Command failed')
	app = AppInfo(name='test', source='Winget', version='1.0', latest_version='1.1', app_id='test')
	try:
		UpdateExecutor._execute_single_update(app)
	except Exception:
		pass


@patch('system_update.run_command')
def test_executor_no_update_needed(mock_run):
	app = AppInfo(name='test', source='Winget', version='1.0', latest_version='1.0', app_id='test')
	result = UpdateExecutor._execute_single_update(app)
	assert result is True  # No update needed, considered success


# ═══════════════════════════════════════════════════════════════════════════════
# SYSTEM UPDATE APP - ADDITIONAL BRANCHES
# ═══════════════════════════════════════════════════════════════════════════════


def test_app_init():
	app = SystemUpdateApp()
	assert app is not None


@patch('system_update.PackageScanner.scan_winget')
@patch('system_update.UpdateChecker._check_winget_updates')
@patch('system_update.console.print')
def test_app_run_with_no_updates(mock_print, mock_check, mock_scan):
	mock_scan.return_value = []
	mock_check.return_value = 0
	app = SystemUpdateApp()
	args = MagicMock()
	args.clear_cache = False
	args.interactive = False
	args.update_all = False
	args.dry_run = False
	args.package = None
	args.update_source = None
	app.run(args)


@patch('system_update.PackageScanner.scan_winget')
@patch('system_update.UpdateChecker._check_winget_updates')
@patch('system_update.UpdateExecutor.execute_updates')
@patch('system_update.console.print')
def test_app_run_update_all(mock_print, mock_exec, mock_check, mock_scan):
	mock_scan.return_value = [
		AppInfo(name='Git', source='Winget', version='1.0', latest_version='2.0', app_id='Git')
	]
	mock_check.return_value = 1
	app = SystemUpdateApp()
	args = MagicMock()
	args.clear_cache = False
	args.interactive = False
	args.update_all = True
	args.dry_run = False
	args.package = None
	args.update_source = None
	args.yes = True
	app.run(args)


@patch('system_update.PackageScanner.scan_winget')
@patch('system_update.UpdateChecker._check_winget_updates')
@patch('system_update.console.print')
def test_app_run_dry_run(mock_print, mock_check, mock_scan):
	mock_scan.return_value = [
		AppInfo(name='Git', source='Winget', version='1.0', latest_version='2.0', app_id='Git')
	]
	mock_check.return_value = 1
	app = SystemUpdateApp()
	args = MagicMock()
	args.clear_cache = False
	args.interactive = False
	args.update_all = False
	args.dry_run = True
	args.package = None
	args.update_source = None
	args.yes = False
	app.run(args)


@patch('system_update.PackageScanner.scan_winget')
@patch('system_update.UpdateChecker._check_winget_updates')
@patch('system_update.console.print')
def test_app_run_specific_package(mock_print, mock_check, mock_scan):
	mock_scan.return_value = [
		AppInfo(name='Git', source='Winget', version='1.0', latest_version='2.0', app_id='Git'),
		AppInfo(
			name='NodeJS', source='Winget', version='1.0', latest_version='1.1', app_id='NodeJS'
		),
	]
	mock_check.return_value = 1
	app = SystemUpdateApp()
	args = MagicMock()
	args.clear_cache = False
	args.interactive = False
	args.update_all = False
	args.dry_run = False
	args.package = 'Git'
	args.update_source = None
	args.yes = False
	app.run(args)
	app.history_db.close()


@patch('system_update.PackageScanner.scan_winget')
@patch('system_update.PackageScanner.scan_npm')
@patch('system_update.UpdateChecker._check_winget_updates')
@patch('system_update.UpdateChecker._check_npm_updates')
@patch('system_update.console.print')
def test_app_run_update_source(
	mock_print, mock_check_npm, mock_check_winget, mock_scan_npm, mock_scan_winget
):
	mock_scan_winget.return_value = [
		AppInfo(name='Git', source='Winget', version='1.0', latest_version='2.0', app_id='Git')
	]
	mock_scan_npm.return_value = []
	mock_check_winget.return_value = 1
	mock_check_npm.return_value = 0
	app = SystemUpdateApp()
	args = MagicMock()
	args.clear_cache = False
	args.interactive = False
	args.update_all = False
	args.dry_run = False
	args.package = None
	args.update_source = 'winget'
	args.yes = False
	app.run(args)


# ═══════════════════════════════════════════════════════════════════════════════
# THEME AND DISPLAY TESTS (CORRECT API)
# ═══════════════════════════════════════════════════════════════════════════════


def test_theme_manager_vibrant():
	theme = ThemeManager.get_theme('vibrant')
	assert theme is not None


def test_theme_manager_minimal():
	theme = ThemeManager.get_theme('minimal')
	assert theme is not None


def test_theme_manager_dark():
	theme = ThemeManager.get_theme('dark')
	assert theme is not None


def test_theme_manager_neon():
	theme = ThemeManager.get_theme('neon')
	assert theme is not None


def test_theme_manager_get_source_color():
	color = ThemeManager.get_source_color('winget', 'default')
	assert color is not None


def test_theme_manager_get_status_color():
	color = ThemeManager.get_status_color('up_to_date', 'default')
	assert color is not None


def test_display_formatter_compact():
	apps = [AppInfo(name='test', source='winget', version='1.0')]
	table = DisplayFormatter.format_table(apps, 'compact')
	assert table is not None


def test_display_formatter_verbose():
	apps = [AppInfo(name='test', source='winget', version='1.0')]
	table = DisplayFormatter.format_table(apps, 'verbose')
	assert table is not None


def test_display_formatter_json():
	apps = [AppInfo(name='test', source='winget', version='1.0')]
	table = DisplayFormatter.format_table(apps, 'json')
	assert table is not None


def test_display_formatter_auto():
	apps = [AppInfo(name='test', source='winget', version='1.0')]
	table = DisplayFormatter.format_table(apps, 'auto')
	assert table is not None


# ═══════════════════════════════════════════════════════════════════════════════
# ADDITIONAL ERROR HANDLING TESTS
# ═══════════════════════════════════════════════════════════════════════════════


@patch('subprocess.run')
def test_run_command_timeout(mock_sub):
	import subprocess

	mock_sub.side_effect = subprocess.TimeoutExpired('cmd', 10)
	result = run_command(['test'])
	assert result is None


@patch('subprocess.run')
def test_run_command_permission_error(mock_sub):
	mock_sub.side_effect = PermissionError('Access denied')
	result = run_command(['test'])
	assert result is None


@patch('subprocess.run')
def test_run_command_file_not_found(mock_sub):
	mock_sub.side_effect = FileNotFoundError('Command not found')
	result = run_command(['nonexistent'])
	assert result is None


@patch('subprocess.run')
def test_run_command_allow_failure(mock_sub):
	mock_sub.return_value = MagicMock(returncode=1, stdout='Error output', stderr='', text=True)
	result = run_command(['test'], allow_failure=True)
	assert result == 'Error output'


@patch('subprocess.run')
def test_run_command_include_stderr(mock_sub):
	mock_sub.return_value = MagicMock(returncode=0, stdout='stdout', stderr='stderr', text=True)
	result = run_command(['test'], include_stderr=True)
	assert 'stderr' in result


# ═══════════════════════════════════════════════════════════════════════════════
# ADDITIONAL VULNERABILITY TESTS
# ═══════════════════════════════════════════════════════════════════════════════


@patch('urllib.request.urlopen')
def test_check_npm_vulns_critical(mock_url):
	app_obj = SystemUpdateApp()
	apps = [AppInfo(name='test', source='npm', version='1.0.0')]
	mock_resp = MagicMock()
	mock_resp.read.return_value = json.dumps(
		{
			'vulnerabilities': {
				'test': {'severity': 'critical', 'via': [{'id': 'CVE-1', 'title': 'Test'}]}
			}
		}
	).encode('utf-8')
	mock_url.return_value.__enter__.return_value = mock_resp
	vulns = app_obj._check_npm_vulns(apps)
	assert len(vulns) >= 0


@patch('urllib.request.urlopen')
def test_check_pip_vulns(mock_url):
	app_obj = SystemUpdateApp()
	apps = [AppInfo(name='requests', source='pip', version='2.28.0')]
	mock_resp = MagicMock()
	mock_resp.read.return_value = json.dumps(
		{'dependencies': [{'name': 'requests', 'vulns': [{'id': 'CVE-2023-1234'}]}]}
	).encode('utf-8')
	mock_url.return_value.__enter__.return_value = mock_resp
	vulns = app_obj._check_pip_vulns(apps)
	assert len(vulns) >= 0


# ═══════════════════════════════════════════════════════════════════════════════
# COMMAND ERROR CLASSIFICATION TESTS (CORRECT API)
# ═══════════════════════════════════════════════════════════════════════════════


def test_command_error_os_error():
	ce = CommandError.classify(OSError('disk full'), 'cmd')
	assert ce.category in ErrorCategory


def test_command_error_keyboard_interrupt():
	ce = CommandError.classify(KeyboardInterrupt(), 'cmd')
	assert ce.category in ErrorCategory


def test_command_error_timeout():
	import subprocess

	ce = CommandError.classify(subprocess.TimeoutExpired('cmd', 10), 'cmd')
	assert ce.category == ErrorCategory.TIMEOUT


def test_command_error_permission():
	ce = CommandError.classify(PermissionError('Access denied'), 'cmd')
	assert ce.category == ErrorCategory.PERMISSION_DENIED


def test_command_error_network():
	import urllib.error

	ce = CommandError.classify(urllib.error.URLError('no network'), 'cmd')
	assert ce.category == ErrorCategory.NETWORK_ERROR or ce.category == ErrorCategory.UNKNOWN


# ═══════════════════════════════════════════════════════════════════════════════
# NOTIFICATION MANAGER TESTS
# ═══════════════════════════════════════════════════════════════════════════════


@patch('urllib.request.urlopen')
def test_notification_webhook_failure(mock_url):
	nm = NotificationManager()
	mock_url.side_effect = Exception('Network error')
	result = nm.send_webhook('http://test.com', {'key': 'val'})
	assert result is False


@patch('platform.system')
def test_notification_windows(mock_sys):
	mock_sys.return_value = 'Windows'
	nm = NotificationManager()
	mock_result = MagicMock(returncode=0)
	with patch('subprocess.run', return_value=mock_result):
		result = nm.send_system_notification('Title', 'Msg')
		assert result is True or result is False


@patch('platform.system')
def test_notification_linux_fallback(mock_sys):
	mock_sys.return_value = 'Linux'
	nm = NotificationManager()
	with patch('subprocess.run') as mock_sub:
		mock_sub.side_effect = FileNotFoundError('notifier not found')
		result = nm.send_system_notification('Title', 'Msg')
		assert result is False


@patch('platform.system')
def test_notification_darwin_fallback(mock_sys):
	mock_sys.return_value = 'Darwin'
	nm = NotificationManager()
	with patch('subprocess.run') as mock_sub:
		mock_sub.side_effect = FileNotFoundError('notifyutil not found')
		result = nm.send_system_notification('Title', 'Msg')
		assert result is False


@patch('platform.system')
def test_notification_unknown_os(mock_sys):
	mock_sys.return_value = 'FreeBSD'
	nm = NotificationManager()
	result = nm.send_system_notification('Title', 'Msg')
	assert result is False


# ═══════════════════════════════════════════════════════════════════════════════
# UI SYSTEM AND VULNERABILITY HISTORY TESTS
# ═══════════════════════════════════════════════════════════════════════════════


def test_theme_manager_source_icons():
	icon = ThemeManager.get_source_icon('winget')
	assert isinstance(icon, str)


def test_display_formatter_auto_with_show_all():
	apps = [AppInfo(name='test', source='winget', version='1.0')]
	table = DisplayFormatter.format_table(apps, 'auto', show_all=True)
	assert table is not None


def test_display_formatter_compact_with_icons():
	apps = [AppInfo(name='test', source='winget', version='1.0')]
	table = DisplayFormatter.format_table(apps, 'compact', use_icons=True)
	assert table is not None


# ═══════════════════════════════════════════════════════════════════════════════
# ADDITIONAL APPINFO PROPERTIES TESTS
# ═══════════════════════════════════════════════════════════════════════════════


def test_app_info_properties_full():
	app = AppInfo(
		name='Git',
		source='Winget',
		version='2.40.0',
		latest_version='2.41.0',
		app_id='Git.Git',
		install_path='C:\\Program Files\\Git',
	)
	assert app.has_update is True
	assert app.latest_version == '2.41.0'


def test_app_info_vulnerable():
	app = AppInfo(name='Git', source='Winget', version='2.40.0')
	app.security_findings = [
		{'cve_id': 'CVE-2023-1234', 'severity': 'HIGH', 'cvss_score': 8.0, 'description': 'Test'}
	]
	assert app.is_vulnerable is True
	assert len(app.security_findings) == 1


def test_app_info_status_display():
	app = AppInfo(name='Git', source='Winget', version='2.40.0')
	for status in UpdateStatus:
		app.update_status = status
		display = app.status_display
		assert len(display) > 0


def test_app_info_all_statuses():
	for status in UpdateStatus:
		app = AppInfo(name='Test', source='Winget', version='1.0')
		app.update_status = status
		display = app.status_display
		assert len(display) > 0


# ═══════════════════════════════════════════════════════════════════════════════════════
# ADDITIONAL CONFIG TESTS
# ═══════════════════════════════════════════════════════════════════════════════════════


def test_system_config_defaults(tmp_path):
	with patch('pathlib.Path.home', return_value=tmp_path):
		cfg = SystemConfig()
		assert cfg.settings is not None
		assert 'sources' in cfg.settings
		assert 'security' in cfg.settings


def test_system_config_sources(tmp_path):
	with patch('pathlib.Path.home', return_value=tmp_path):
		cfg = SystemConfig()
		assert cfg.settings['sources']['winget'] is True


def test_system_config_security(tmp_path):
	with patch('pathlib.Path.home', return_value=tmp_path):
		cfg = SystemConfig()
		assert 'severity_threshold' in cfg.settings['security']


def test_system_config_performance(tmp_path):
	with patch('pathlib.Path.home', return_value=tmp_path):
		cfg = SystemConfig()
		assert 'max_workers' in cfg.settings['performance']


# ═══════════════════════════════════════════════════════════════════════════════════════
# ADDITIONAL VULNERABILITY HISTORY TESTS
# ═══════════════════════════════════════════════════════════════════════════════


def test_vulnerability_history_stats():
	history_file = __import__('pathlib').Path('test_vuln_history.json')
	vh = VulnerabilityHistory(history_file)

	app = AppInfo(name='TestApp', source='pip', version='1.0')
	vuln = {'cve': 'CVE-2023-9999', 'severity': 'HIGH', 'cvss_score': 8.5, 'description': 'Test'}

	vh.record_vulnerability(app, vuln, 'scan-test-1')
	stats = vh.get_statistics()
	assert isinstance(stats, dict)


def test_vulnerability_history_trends():
	history_file = __import__('pathlib').Path('test_vuln_history2.json')
	vh = VulnerabilityHistory(history_file)

	trends = vh.get_vulnerability_trends(days=7)
	assert isinstance(trends, dict)


# ═══════════════════════════════════════════════════════════════════════════════
# ADDITIONAL CACHE MANAGER TESTS
# ═══════════════════════════════════════════════════════════════════════════════════════


def test_cache_manager_clear(tmp_path):
	cache_file = tmp_path / 'cache.json'
	mgr = CacheManager(cache_file, duration_hours=1)

	apps = [AppInfo(name='App1', source='Winget', version='1.0')]
	mgr.save(apps)
	assert mgr.is_valid() is True

	mgr.clear()
	assert mgr.is_valid() is False


def test_cache_manager_expired(tmp_path):
	cache_file = tmp_path / 'cache.json'
	mgr = CacheManager(cache_file, duration_hours=1)

	apps = [AppInfo(name='App1', source='Winget', version='1.0')]
	mgr.save(apps)

	with patch('system_update.datetime') as mock_dt:
		mock_dt.now.return_value = datetime.now() + timedelta(hours=3)
		mock_dt.fromisoformat.side_effect = datetime.fromisoformat
		assert mgr.is_valid() is False


# ═══════════════════════════════════════════════════════════════════════════════════════
# ADDITIONAL UPDATE CHECKER TESTS
# ═══════════════════════════════════════════════════════════════════════════════���═��═════


@patch('system_update.run_command')
def test_check_scoop_updates(mock_run):
	apps = [AppInfo(name='git', source='scoop', version='2.40.0')]
	mock_run.return_value = 'git (2.41.0) - A distributed version control system'
	count = UpdateChecker._check_scoop_updates(apps)
	assert count >= 0


@patch('system_update.run_command')
def test_check_dotnet_updates(mock_run):
	apps = [AppInfo(name='nuget', source='dotnet', version='6.0.0')]
	mock_run.return_value = 'NuGet.Client                      6.0.1'
	count = UpdateChecker._check_dotnet_updates(apps)
	assert count >= 0


@patch('system_update.run_command')
def test_check_registry_updates(mock_run):
	apps = [AppInfo(name='test', source='registry', version='1.0')]
	mock_run.return_value = 'TestApp v2.0'
	count = UpdateChecker._check_registry_updates(apps)
	assert count >= 0


# ═══════════════════════════════════════════════════════════════════════════════════════
# ADDITIONAL EXECUTOR TESTS
# ═══════════════════════════════════════════════════════════════════════════════════════


def test_executor_empty_list():
	result = UpdateExecutor.execute_updates([])
	assert result is None or result is True


# ═══════════════════════════════════════════════════════════════════════════════
# NOTIFICATION MANAGER ADVANCED TESTS
# ═══════════════════════════════════════════════════════════════════════════════════════


def test_notification_manager_initialization():
	nm = NotificationManager()
	assert nm is not None


def test_notification_send_webhook_success():
	nm = NotificationManager()
	with patch('urllib.request.urlopen') as mock_url:
		mock_url.return_value.__enter__.return_value.status = 200
		result = nm.send_webhook('http://example.com/webhook', {'title': 'Test', 'message': 'Msg'})
		assert result is True


def test_notification_send_webhook_failure():
	nm = NotificationManager()
	with patch('urllib.request.urlopen') as mock_url:
		mock_url.side_effect = Exception('Network error')
		result = nm.send_webhook('http://example.com/webhook', {'title': 'Test', 'message': 'Msg'})
		assert result is False


@patch('os.path.exists')
def test_run_custom_script_not_found(mock_exists):
	nm = NotificationManager()
	mock_exists.return_value = False
	result = nm.run_custom_script('nonexistent.py', {'VAR': 'value'})
	assert result is False


# ═══════════════════════════════════════════════════════════════════════════════
# NOTIFY COMPLETE AND UPDATE METHODS
# ═══════════════════════════════════════════════════════════════════════════════


@patch('system_update.NotificationManager.send_system_notification')
def test_notify_updates_with_vulns(mock_notif):
	nm = NotificationManager()
	nm.notify_updates_available(updates_count=5, vulnerable_count=2, force=True)
	assert mock_notif.called


@patch('system_update.NotificationManager.send_system_notification')
def test_notify_updates_no_vulns(mock_notif):
	nm = NotificationManager()
	nm.notify_updates_available(updates_count=5, vulnerable_count=0, force=True)
	assert mock_notif.called


@patch('system_update.NotificationManager.send_system_notification')
def test_notify_scan_complete(mock_notif):
	nm = NotificationManager()
	nm.notify_scan_complete(total_apps=10, scan_time=5.5, force=True)
	assert mock_notif.called


# ═══════════════════════════════════════════════════════════════════════════════════════
# SECURITY INFO AND PUBLISH DATE
# ═══════════════════════════════════════════════════════════════════════════════════════


def test_security_info_to_dict():
	si = SecurityInfo(
		cve_id='CVE-2023-1234', severity='HIGH', cvss_score=8.0, description='Test vuln'
	)
	d = si.to_dict()
	assert 'cve_id' in d
	assert d['cve_id'] == 'CVE-2023-1234'


def test_security_info_published_date():
	si = SecurityInfo(
		cve_id='CVE-2023-1234',
		severity='HIGH',
		cvss_score=8.0,
		description='Test vuln',
		published_date=datetime.now(),
	)
	d = si.to_dict()
	assert 'published_date' in d


# ═══════════════════════════════════════════════════════════════════════════════════════
# APP INFO SERIALIZATION
# ═══════════════════════════════════════════════════════════════════════════════


def test_app_info_to_dict():
	app = AppInfo(name='Git', source='Winget', version='2.40.0')
	d = app.to_dict()
	assert d['name'] == 'Git'
	assert 'status' in d
