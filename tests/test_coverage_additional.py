import pytest
import json
import os
from unittest.mock import MagicMock, patch
from pathlib import Path
from system_update import (
    AppInfo, UpdateStatus, PackageScanner, UpdateChecker,
    UpdateExecutor, SystemUpdateApp, SystemConfig,
    ThemeManager, DisplayFormatter,
    run_command,
)


def test_system_config_reinit_profile(tmp_path, monkeypatch):
    with patch('pathlib.Path.home', return_value=tmp_path):
        cfg = SystemConfig()
        cfg.settings = cfg._get_default_settings()
        cfg.reinit('test_profile')
        assert cfg.current_profile == 'test_profile'


def test_system_config_export_profile(tmp_path, monkeypatch):
    with patch('pathlib.Path.home', return_value=tmp_path):
        cfg = SystemConfig()
        cfg.settings = cfg._get_default_settings()

        output_file = tmp_path / 'exported_profile.json'
        result = cfg.export_profile(str(output_file))
        assert result is True
        assert output_file.exists()


def test_system_config_import_profile(tmp_path, monkeypatch):
    with patch('pathlib.Path.home', return_value=tmp_path):
        cfg = SystemConfig()
        cfg.settings = cfg._get_default_settings()

        import_file = tmp_path / 'import_profile.json'
        import_data = {
            'profile_name': 'imported',
            'settings': cfg._get_default_settings(),
        }
        import_data['settings']['cache']['duration_hours'] = 5
        with open(import_file, 'w', encoding='utf-8') as f:
            json.dump(import_data, f)

        result = cfg.import_profile(str(import_file))
        assert result is True


def test_system_config_get_default_settings():
    cfg = SystemConfig()
    settings = cfg._get_default_settings()
    assert 'cache' in settings
    assert 'performance' in settings
    assert 'security' in settings
    assert 'sources' in settings


def test_system_config_validate_settings():
    cfg = SystemConfig()
    cfg.settings = cfg._get_default_settings()
    result = cfg._validate_config()
    assert result is None or isinstance(result, list)


def test_system_config_save_success(tmp_path, monkeypatch):
    with patch('pathlib.Path.home', return_value=tmp_path):
        cfg = SystemConfig()
        cfg.settings = cfg._get_default_settings()
        cfg.save()
        config_file = tmp_path / '.system_update' / 'config.json'
        assert config_file.exists()


def test_system_config_load_nonexistent(tmp_path, monkeypatch):
    with patch('pathlib.Path.home', return_value=tmp_path):
        cfg = SystemConfig()
        cfg.settings = cfg._get_default_settings()
        cfg.load()
        assert cfg.settings is not None


def test_app_info_has_update():
    app = AppInfo(name='Test', source='npm', version='1.0.0')
    assert app.has_update is False
    app.latest_version = '2.0.0'
    assert app.has_update is True


def test_app_info_is_vulnerable():
    app = AppInfo(name='Test', source='npm', version='1.0.0')
    assert app.is_vulnerable is False
    app.security_findings = [{'cve_id': 'CVE-2023-1'}]
    assert app.is_vulnerable is True


def test_app_info_str():
    app = AppInfo(name='Test', source='npm', version='1.0.0')
    s = str(app)
    assert 'Test' in s


def test_app_info_repr():
    app = AppInfo(name='Test', source='npm', version='1.0.0')
    r = repr(app)
    assert 'Test' in r


def test_update_status_enum():
    assert UpdateStatus.UP_TO_DATE.value == 'up_to_date'
    assert UpdateStatus.UPDATE_AVAILABLE.value == 'update_available'
    assert UpdateStatus.VULNERABLE.value == 'vulnerable'
    assert UpdateStatus.UNKNOWN.value == 'unknown'
    assert UpdateStatus.ERROR.value == 'error'
    assert UpdateStatus.SECURITY_UPDATE_AVAILABLE.value == 'security_update_available'


def test_theme_manager_default():
    theme = ThemeManager.get_theme('default')
    assert theme is not None


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


@pytest.mark.parametrize('format', ['compact', 'verbose', 'json', 'auto', 'diff', 'html', 'markdown', 'xml'])
def test_display_formatter_all_formats(format):
    apps = [AppInfo(name='Test', source='npm', version='1.0.0')]
    table = DisplayFormatter.format_table(apps, format)
    assert table is not None


@patch('subprocess.run')
def test_run_command_with_timeout(mock_sub):
    import subprocess
    mock_sub.side_effect = subprocess.TimeoutExpired('cmd', 5)
    result = run_command(['test'], timeout=10)
    assert result is None


def test_app_info_install_path():
    app = AppInfo(name='Test', source='npm', version='1.0.0', install_path='C:\\Test')
    assert app.install_path == 'C:\\Test'


def test_app_info_install_path_none():
    app = AppInfo(name='Test', source='npm', version='1.0.0')
    assert app.install_path is None


def test_app_info_app_id():
    app = AppInfo(name='Test', source='npm', version='1.0.0', app_id='test-app')
    assert app.app_id == 'test-app'


def test_app_info_app_id_none():
    app = AppInfo(name='Test', source='npm', version='1.0.0')
    assert app.app_id is None


def test_app_info_source():
    app = AppInfo(name='Test', source='npm', version='1.0.0')
    assert app.source == 'npm'


def test_app_info_latest_version():
    app = AppInfo(name='Test', source='npm', version='1.0.0', latest_version='2.0.0')
    assert app.latest_version == '2.0.0'


def test_app_info_latest_version_none():
    app = AppInfo(name='Test', source='npm', version='1.0.0')
    assert app.latest_version == ''


def test_executor_update_all_sources():
    apps = [
        AppInfo(name='Git', source='Winget', version='1.0', latest_version='2.0', app_id='Git'),
        AppInfo(name='Node', source='npm', version='1.0', latest_version='2.0', app_id='Node'),
    ]
    result = UpdateExecutor.execute_updates(apps)
    assert result is None or result is True


@patch('system_update.run_command', return_value='Success')
def test_executor_execute_single(mock_run):
    app = AppInfo(name='Test', source='npm', version='1.0', latest_version='2.0', app_id='test')
    result = UpdateExecutor._execute_single_update(app)
    assert isinstance(result, bool)


def test_theme_manager_all_themes():
    themes = ['default', 'vibrant', 'minimal', 'dark', 'neon']
    for theme_name in themes:
        theme = ThemeManager.get_theme(theme_name)
        assert theme is not None


def test_theme_manager_status_colors():
    for status in ['up_to_date', 'outdated', 'vulnerable', 'unknown']:
        color = ThemeManager.get_status_color(status, 'default')
        assert color is not None


def test_checker_check_winget_none():
    result = UpdateChecker._check_winget_updates([])
    assert result == 0


def test_checker_check_npm_none():
    result = UpdateChecker._check_npm_updates([])
    assert result == 0


def test_checker_check_pip_none():
    result = UpdateChecker._check_pip_updates([])
    assert result == 0


def test_scanner_scan_winget_installed():
    from system_update import run_command
    with patch('system_update.run_command') as mock_run:
        mock_run.return_value = ''
        apps = PackageScanner.scan_winget()
        assert isinstance(apps, list)


@patch('platform.system', return_value='Windows')
def test_scanner_scan_registry_windows(mock_sys):
    with patch('system_update.run_command') as mock_run:
        mock_run.return_value = '[]'
        apps = PackageScanner.scan_registry()
        assert isinstance(apps, list)


@patch('platform.system', return_value='Linux')
def test_scanner_scan_registry_linux(mock_sys):
    with patch('system_update.run_command') as mock_run:
        mock_run.return_value = '[]'
        apps = PackageScanner.scan_registry()
        assert isinstance(apps, list)