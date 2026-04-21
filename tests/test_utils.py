import subprocess as sp
import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch
from system_update import (
    ThemeManager, DisplayFormatter, VulnerabilityHistory,
    CacheManager, AppInfo, UpdateStatus, SecurityInfo,
    source_badge, run_command,
    SOURCE_ICONS, CommandError, ErrorCategory
)

def test_all_source_icons():
    for source, expected_icon in SOURCE_ICONS.items():
        assert ThemeManager.get_source_icon(source) == expected_icon
    assert ThemeManager.get_source_icon('WINGET') == '📦'
    assert ThemeManager.get_source_icon('unknown_xyz') == ''

def test_theme_manager_get_source_color():
    assert ThemeManager.get_source_color('winget', 'default') == 'blue'
    assert ThemeManager.get_source_color('npm', 'vibrant') == 'bright_red'

def test_theme_manager_get_source_icon():
    assert ThemeManager.get_source_icon('npm') == '📚'
    assert ThemeManager.get_source_icon('winget') == '📦'

def test_error_category_classification():
    err = CommandError.classify(FileNotFoundError(), 'test-command')
    assert err.category == ErrorCategory.NOT_FOUND
    assert 'not found' in err.message.lower()

    err = CommandError.classify(sp.TimeoutExpired('cmd', 1), 'test-command')
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
        ('WINGET', 'blue'),
        ('', 'bright_white'),
        (None, 'bright_white'),
    ],
)
def test_source_badge_styles(source, expected_style):
    result = source_badge(source)
    assert expected_style in result


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


def test_theme_manager_source_icons():
    icon = ThemeManager.get_source_icon('winget')
    assert isinstance(icon, str)


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


def test_display_formatter_auto_with_show_all():
    apps = [AppInfo(name='test', source='winget', version='1.0')]
    table = DisplayFormatter.format_table(apps, 'auto', show_all=True)
    assert table is not None


def test_display_formatter_compact_with_icons():
    apps = [AppInfo(name='test', source='winget', version='1.0')]
    table = DisplayFormatter.format_table(apps, 'compact', use_icons=True)
    assert table is not None


def test_display_formatter_unknown_format():
    apps = [AppInfo(name='test', source='winget', version='1.0')]
    table = DisplayFormatter.format_table(apps, 'unknown_format')
    assert table is not None


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


def test_cache_manager_validation(tmp_path):
    cache_file = tmp_path / 'cache.json'
    mgr = CacheManager(cache_file, duration_hours=1)

    assert mgr.is_valid() is False
    assert mgr.load() is None

    apps = [AppInfo(name='App1', source='Winget', version='1.0')]
    mgr.save(apps)
    assert mgr.is_valid() is True

    loaded = mgr.load()
    assert len(loaded) == 1
    assert loaded[0].name == 'App1'


def test_vulnerability_history_stats(tmp_path):
    history_file = tmp_path / 'vuln_history.json'
    vh = VulnerabilityHistory(history_file)

    app = AppInfo(name='VulnApp', source='Pip', version='1.0')
    vuln = {'cve': 'CVE-2023-1234', 'severity': 'HIGH', 'cvss_score': 8.0, 'description': 'Test'}

    vh.record_vulnerability(app, vuln, 'scan-1')
    stats = vh.get_statistics()
    assert stats['total_vulnerabilities'] == 1
    assert stats['open_vulnerabilities'] == 1


def test_vulnerability_history_trends(tmp_path):
    history_file = tmp_path / 'vuln_history2.json'
    vh = VulnerabilityHistory(history_file)

    trends = vh.get_vulnerability_trends(days=7)
    assert isinstance(trends, dict)


def test_cache_manager_invalid_json(tmp_path):
    cache_file = tmp_path / 'cache.json'
    cache_file.write_text('{invalid json}')
    mgr = CacheManager(cache_file)
    result = mgr.load()
    assert result is None


def test_cache_manager_invalid_version(tmp_path):
    cache_file = tmp_path / 'cache.json'
    cache_file.write_text(json.dumps({
        'version': '0.0.1',
        'timestamp': '2000-01-01T00:00:00',
        'apps': [],
    }))
    mgr = CacheManager(cache_file)
    assert mgr.is_valid() is False


def test_vulnerability_history_corrupted(tmp_path):
    hist_file = tmp_path / 'vuln.json'
    hist_file.write_text('{corrupted')
    vh = VulnerabilityHistory(hist_file)
    stats = vh.get_statistics()
    assert isinstance(stats, dict)


def test_theme_manager_invalid():
    theme_invalid = ThemeManager.get_theme('invalid_theme')
    theme_default = ThemeManager.get_theme('default')
    assert theme_invalid == theme_default


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


def test_app_info_to_dict():
    app = AppInfo(name='Git', source='Winget', version='2.40.0')
    d = app.to_dict()
    assert d['name'] == 'Git'
    assert 'status' in d


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


def test_app_info_has_update():
    from system_update import AppInfo
    app = AppInfo(name='Test', source='npm', version='1.0.0')
    assert app.has_update is False
    app.latest_version = '2.0.0'
    assert app.has_update is True


def test_app_info_is_vulnerable():
    from system_update import AppInfo
    app = AppInfo(name='Test', source='npm', version='1.0.0')
    assert app.is_vulnerable is False
    app.security_findings = [{'cve_id': 'CVE-2023-1'}]
    assert app.is_vulnerable is True


def test_app_info_str():
    from system_update import AppInfo
    app = AppInfo(name='Test', source='npm', version='1.0.0')
    s = str(app)
    assert 'Test' in s


def test_app_info_repr():
    from system_update import AppInfo
    app = AppInfo(name='Test', source='npm', version='1.0.0')
    r = repr(app)
    assert 'Test' in r


def test_update_status_enum():
    from system_update import UpdateStatus
    assert UpdateStatus.UP_TO_DATE.value == 'up_to_date'
    assert UpdateStatus.UPDATE_AVAILABLE.value == 'update_available'
    assert UpdateStatus.VULNERABLE.value == 'vulnerable'
    assert UpdateStatus.UNKNOWN.value == 'unknown'
    assert UpdateStatus.ERROR.value == 'error'
    assert UpdateStatus.SECURITY_UPDATE_AVAILABLE.value == 'security_update_available'


def test_app_info_install_path():
    from system_update import AppInfo
    app = AppInfo(name='Test', source='npm', version='1.0.0', install_path='C:\\Test')
    assert app.install_path == 'C:\\Test'


def test_app_info_install_path_none():
    from system_update import AppInfo
    app = AppInfo(name='Test', source='npm', version='1.0.0')
    assert app.install_path is None


def test_app_info_app_id():
    from system_update import AppInfo
    app = AppInfo(name='Test', source='npm', version='1.0.0', app_id='test-app')
    assert app.app_id == 'test-app'


def test_app_info_app_id_none():
    from system_update import AppInfo
    app = AppInfo(name='Test', source='npm', version='1.0.0')
    assert app.app_id is None


def test_app_info_source():
    from system_update import AppInfo
    app = AppInfo(name='Test', source='npm', version='1.0.0')
    assert app.source == 'npm'


def test_app_info_latest_version():
    from system_update import AppInfo
    app = AppInfo(name='Test', source='npm', version='1.0.0', latest_version='2.0.0')
    assert app.latest_version == '2.0.0'


def test_app_info_latest_version_none():
    from system_update import AppInfo
    app = AppInfo(name='Test', source='npm', version='1.0.0')
    assert app.latest_version == ''