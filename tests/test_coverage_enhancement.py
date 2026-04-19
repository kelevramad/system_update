import json
import subprocess
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta
from system_update import (
    AppInfo, UpdateStatus, NotificationManager, CacheManager,
    VulnerabilityHistory, SystemConfig, PackageScanner, run_command,
    CommandError, ErrorCategory,
    UpdateChecker, UpdateExecutor, SystemUpdateApp
)

# ═══════════════════════════════════════════════════════════════════════════════
# UNIT TESTS FOR CORE MODELS
# ═══════════════════════════════════════════════════════════════════════════════

def test_app_info_properties():
    app = AppInfo(name="Test App", source="Winget", version="1.0.0")
    assert app.has_update is False
    assert app.is_vulnerable is False
    assert "unknown" in app.status_display

    app.latest_version = "1.1.0"
    assert app.has_update is True

    app.security_findings = [{"id": "CVE-1"}]
    assert app.is_vulnerable is True

    app.update_status = UpdateStatus.UP_TO_DATE
    assert "✅" in app.status_display

    d = app.to_dict()
    assert d["name"] == "Test App"
    assert d["status"] == "up_to_date"


# FIX: removida duplicata exata de test_error_category_classification
# (que já existe em test_system_update.py via CLI + import direto).
# Mantido apenas o teste que usa a API diretamente — sem subprocess.

def test_command_error_all_categories():
    """Cobre todos os ErrorCategory via CommandError.classify."""
    cases = [
        (FileNotFoundError(), ErrorCategory.NOT_FOUND),
        (subprocess.TimeoutExpired("cmd", 10), ErrorCategory.TIMEOUT),
        (PermissionError(), ErrorCategory.PERMISSION_DENIED),
        (ValueError(), ErrorCategory.PARSE_ERROR),
        (Exception("unknown"), ErrorCategory.UNKNOWN),
    ]
    for exc, expected in cases:
        ce = CommandError.classify(exc, "cmd")
        assert ce.category == expected, f"Falhou para {type(exc).__name__}"


# ═══════════════════════════════════════════════════════════════════════════════
# UNIT TESTS FOR MANAGERS
# ═══════════════════════════════════════════════════════════════════════════════

def test_cache_manager_validation(tmp_path):
    cache_file = tmp_path / "cache.json"
    mgr = CacheManager(cache_file, duration_hours=1)

    assert mgr.is_valid() is False
    assert mgr.load() is None

    apps = [AppInfo(name="App1", source="Winget", version="1.0")]
    mgr.save(apps)
    assert mgr.is_valid() is True

    loaded = mgr.load()
    assert len(loaded) == 1
    assert loaded[0].name == "App1"

    # FIX: patch correto de datetime — fromisoformat precisa de side_effect,
    # não de atribuição direta, pois CacheManager chama datetime.fromisoformat()
    # em contexto onde datetime já foi substituído pelo mock.
    with patch('system_update.datetime') as mock_date:
        mock_date.now.return_value = datetime.now() + timedelta(hours=2)
        mock_date.fromisoformat.side_effect = lambda s: datetime.fromisoformat(s)
        assert mgr.is_valid() is False


def test_vulnerability_history_stats(tmp_path):
    history_file = tmp_path / "vuln_history.json"
    vh = VulnerabilityHistory(history_file)

    app = AppInfo(name="VulnApp", source="Pip", version="1.0")
    vuln = {"cve": "CVE-2023-1234", "severity": "HIGH", "cvss_score": 8.0, "description": "Test"}

    vh.record_vulnerability(app, vuln, "scan-1")
    stats = vh.get_statistics()
    assert stats["total_vulnerabilities"] == 1
    assert stats["open_vulnerabilities"] == 1

    vh.mark_resolved("VulnApp", "CVE-2023-1234")
    stats = vh.get_statistics()
    assert stats["open_vulnerabilities"] == 0
    assert stats["resolved_vulnerabilities"] == 1


def test_notification_manager_webhook_success():
    """FIX: mock correto do context manager de urlopen."""
    nm = NotificationManager()
    mock_response = MagicMock()
    mock_response.status = 200
    ctx = MagicMock()
    ctx.__enter__ = MagicMock(return_value=mock_response)
    ctx.__exit__ = MagicMock(return_value=False)
    with patch('urllib.request.urlopen', return_value=ctx):
        assert nm.send_webhook("http://test.com", {"key": "val"}) is True


def test_notification_manager_webhook_failure():
    nm = NotificationManager()
    with patch('urllib.request.urlopen', side_effect=Exception("Network error")):
        assert nm.send_webhook("http://test.com", {"key": "val"}) is False


def test_notification_manager_system_linux():
    nm = NotificationManager()
    with patch('platform.system', return_value='Linux'):
        # Sem notificador instalado → False (sem crash)
        result = nm.send_system_notification("Title", "Msg")
        assert result is False


# ═══════════════════════════════════════════════════════════════════════════════
# UNIT TESTS FOR SCANNERS
# ═══════════════════════════════════════════════════════════════════════════════

@patch('system_update.run_command')
def test_scan_winget_parsing(mock_run):
    header = "Name                           Id                                         Version          Available        Source"
    line1 = "Git                            Git.Git                                    2.40.0.windows.1 2.41.0.windows.1 winget"
    mock_run.return_value = f"{header}\n{'-' * 115}\n{line1}"
    apps = PackageScanner.scan_winget()
    assert len(apps) == 1
    assert apps[0].name == "Git"


@patch('system_update.run_command')
def test_scan_npm_parsing(mock_run):
    mock_run.return_value = json.dumps({"dependencies": {"npm": {"version": "9.5.0"}}})
    apps = PackageScanner.scan_npm()
    assert len(apps) == 1


@patch('system_update.run_command')
def test_scan_pip_parsing(mock_run):
    mock_run.return_value = json.dumps([{"name": "requests", "version": "2.28.1"}])
    apps = PackageScanner.scan_pip()
    assert len(apps) == 1


@patch('system_update.run_command')
def test_scan_chocolatey_parsing(mock_run):
    mock_run.return_value = "git|2.40.0"
    apps = PackageScanner.scan_chocolatey()
    assert len(apps) == 1


@patch('system_update.run_command')
@patch('platform.system', return_value='Windows')
def test_scan_registry_parsing(mock_platform, mock_run):
    mock_run.return_value = json.dumps([{"Name": "App", "Version": "1.0", "InstallLocation": "C:\\"}])
    apps = PackageScanner.scan_registry()
    assert len(apps) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# UNIT TESTS FOR UPDATE CHECKERS
# ═══════════════════════════════════════════════════════════════════════════════

@patch('system_update.run_command')
def test_check_winget_updates(mock_run):
    apps = [AppInfo(name="Git", source="Winget", version="2.40.0", app_id="Git.Git")]
    header = "Name                           Id                                         Version          Available        Source"
    line1 = "Git                            Git.Git                                    2.40.0           2.41.0           winget"
    mock_run.return_value = f"{header}\n{'-' * 115}\n{line1}"
    count = UpdateChecker._check_winget_updates(apps)
    assert count == 1
    assert apps[0].latest_version == "2.41.0"


# ═══════════════════════════════════════════════════════════════════════════════
# UNIT TESTS FOR UPDATE EXECUTOR
# ═══════════════════════════════════════════════════════════════════════════════

@patch('system_update.UpdateExecutor._execute_single_update', return_value=True)
def test_execute_updates(mock_exec):
    apps = [AppInfo(name="Git", source="Winget", version="2.40.0", latest_version="2.41.0")]
    UpdateExecutor.execute_updates(apps)
    assert mock_exec.called


@patch('system_update.run_command', return_value="Success")
def test_execute_single_update(mock_run):
    app = AppInfo(name="Git", source="Winget", version="2.40.0", latest_version="2.41.0", app_id="Git")
    assert UpdateExecutor._execute_single_update(app) is True


# ═══════════════════════════════════════════════════════════════════════════════
# UNIT TESTS FOR SYSTEM UPDATE APP
# ═══════════════════════════════════════════════════════════════════════════════

@patch('system_update.PackageScanner.scan_winget', return_value=[AppInfo(name="Git", source="Winget", version="1.0")])
def test_app_scan_system(mock_scan):
    app = SystemUpdateApp()
    app.config.settings['sources']['winget'] = True
    apps = app.scan_system(source_filter="winget")
    assert len(apps) == 1


def test_app_export_results(tmp_path):
    app = SystemUpdateApp()
    apps = [AppInfo(name="Git", source="Winget", version="1.0")]

    json_file = tmp_path / "export.json"
    app.export_results(apps, "json", str(json_file))
    assert json_file.exists()

    csv_file = tmp_path / "export.csv"
    app.export_results(apps, "csv", str(csv_file))
    assert csv_file.exists()


# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY SCANNER TESTS
# ═══════════════════════════════════════════════════════════════════════════════

@patch('urllib.request.urlopen')
def test_check_osv_vulnerabilities(mock_url):
    app_obj = SystemUpdateApp()
    apps = [AppInfo(name="requests", source="PIP", version="2.28.1")]

    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps({
        "vulns": [{
            "id": "GHSA-1234",
            "summary": "Test vuln",
            "severity": [{"type": "cvss_v3", "score": 9.8}],
        }]
    }).encode('utf-8')
    mock_url.return_value.__enter__.return_value = mock_resp

    vulns = app_obj.check_osv_vulnerabilities(apps)
    assert len(vulns) == 1
    assert apps[0].is_vulnerable is True


# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY TESTS
# ═══════════════════════════════════════════════════════════════════════════════

@patch('subprocess.run')
def test_run_command_success(mock_sub):
    mock_sub.return_value = MagicMock(returncode=0, stdout="Success", stderr="", text=True)
    assert run_command(["test"]) == "Success"


def test_system_config_lifecycle(tmp_path):
    with patch('pathlib.Path.home', return_value=tmp_path):
        cfg = SystemConfig()
        cfg.settings['performance']['max_workers'] = 10
        cfg.save()
        cfg2 = SystemConfig()
        assert cfg2.settings['performance']['max_workers'] == 10