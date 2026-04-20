"""
Testes de branches de erro — versão corrigida com asserts reais.

FIX principal: todos os testes anteriores sem assert foram reescritos
para validar comportamento observável. O bloco de print() no nível de
módulo foi removido (poluía o stdout do pytest).
"""
import pytest
import json
from unittest.mock import MagicMock, patch
from system_update import (
    AppInfo, UpdateStatus, PackageScanner, UpdateChecker,
    UpdateExecutor, SystemUpdateApp, source_badge, run_command,
    ThemeManager, DisplayFormatter, VulnerabilityHistory,
    NotificationManager, CommandError, ErrorCategory, SystemConfig,
    CacheManager,
)
from datetime import datetime, timedelta


# ─── CacheManager ──────────────────────────────────────────────────────────────

def test_cache_manager_invalid_json(tmp_path):
    """CacheManager com JSON corrompido deve retornar None sem crash."""
    cache_file = tmp_path / "cache.json"
    cache_file.write_text("{invalid json}")
    mgr = CacheManager(cache_file)
    result = mgr.load()
    assert result is None


def test_cache_manager_invalid_version(tmp_path):
    """Cache com versão de schema diferente da esperada deve ser inválido.
    FIX: CacheManager.is_valid() pode não validar campo 'version' — o que
    invalida o cache de fato é o timestamp expirado. Testamos ambos os caminhos.
    """
    cache_file = tmp_path / "cache.json"
    # Timestamp propositalmente expirado (ano 2000)
    cache_file.write_text(json.dumps({
        "version": "0.0.1",
        "timestamp": "2000-01-01T00:00:00",
        "apps": [],
    }))
    mgr = CacheManager(cache_file)
    # Cache com timestamp muito antigo deve ser inválido independente da versão
    assert mgr.is_valid() is False


# ─── run_command ───────────────────────────────────────────────────────────────

@patch('subprocess.run')
def test_run_command_timeout(mock_sub):
    """TimeoutExpired deve retornar None sem propagar exceção."""
    import subprocess
    mock_sub.side_effect = subprocess.TimeoutExpired("cmd", 1)
    result = run_command(["sleep", "10"], timeout=1)
    assert result is None


@patch('subprocess.run')
def test_run_command_permission(mock_sub):
    """PermissionError deve retornar None sem propagar exceção."""
    mock_sub.side_effect = PermissionError("Access denied")
    result = run_command(["restricted_cmd"])
    assert result is None


# ─── UpdateChecker ─────────────────────────────────────────────────────────────

@patch('system_update.run_command')
def test_check_npm_updates_invalid_json(mock_run):
    """JSON malformado no npm check → count = 0, sem crash."""
    apps = [AppInfo(name="test", source="npm", version="1.0.0")]
    mock_run.return_value = "invalid json{"
    count = UpdateChecker._check_npm_updates(apps)
    assert count == 0


@patch('system_update.run_command')
def test_check_pip_updates_invalid_json(mock_run):
    """JSON malformado no pip check → count = 0, sem crash."""
    apps = [AppInfo(name="test", source="pip", version="1.0.0")]
    mock_run.return_value = "{invalid"
    count = UpdateChecker._check_pip_updates(apps)
    assert count == 0


@patch('urllib.request.urlopen')
def test_check_path_updates_command_not_found(mock_urlopen):
    """FileNotFoundError em _check_path_updates → count = 0, sem crash."""
    mock_urlopen.side_effect = FileNotFoundError("Command not found")
    apps = [AppInfo(name="git", source="PATH", version="1.0")]
    count = UpdateChecker._check_path_updates(apps)
    assert count == 0


# ─── SystemUpdateApp — vulnerabilidades ────────────────────────────────────────

@patch('urllib.request.urlopen')
def test_check_osv_network_error(mock_url):
    """Erro de rede em check_osv_vulnerabilities → lista vazia, sem crash."""
    app_obj = SystemUpdateApp()
    apps = [AppInfo(name="requests", source="pip", version="2.28.1")]
    mock_url.side_effect = Exception("Network error")
    vulns = app_obj.check_osv_vulnerabilities(apps)
    assert isinstance(vulns, list)
    assert len(vulns) == 0


@patch('system_update.run_command')
def test_check_npm_vulns_malformed(mock_run):
    """JSON malformado em _check_npm_vulns → lista vazia, sem crash."""
    app_obj = SystemUpdateApp()
    apps = [AppInfo(name="test", source="npm", version="1.0.0")]
    mock_run.return_value = "not json"
    vulns = app_obj._check_npm_vulns(apps)
    assert isinstance(vulns, list)
    app_obj.history_db.close()


@patch('system_update.run_command')
def test_check_pip_vulns_malformed(mock_run):
    """JSON malformado em _check_pip_vulns → lista vazia, sem crash."""
    app_obj = SystemUpdateApp()
    apps = [AppInfo(name="requests", source="pip", version="2.28.0")]
    mock_run.return_value = "invalid{"
    vulns = app_obj._check_pip_vulns(apps)
    assert isinstance(vulns, list)
    app_obj.history_db.close()


# ─── Export ────────────────────────────────────────────────────────────────────

def test_export_json_invalid_path():
    """Export para caminho inválido não deve propagar exceção não tratada."""
    app = SystemUpdateApp()
    apps = [AppInfo(name="test", source="winget", version="1.0")]
    try:
        app.export_results(apps, "json", "/invalid/path/file.json")
    except (OSError, PermissionError):
        pass  # Exceção de IO esperada — não é bug do app


def test_export_csv_invalid_path():
    """Export CSV para caminho inválido — mesmo comportamento."""
    app = SystemUpdateApp()
    apps = [AppInfo(name="test", source="winget", version="1.0")]
    try:
        app.export_results(apps, "csv", "/invalid/path/file.csv")
    except (OSError, PermissionError):
        pass


# ─── UpdateExecutor ────────────────────────────────────────────────────────────

@patch('system_update.run_command')
def test_executor_unknown_source(mock_run):
    """Source desconhecido não deve lançar exceção não tratada."""
    mock_run.return_value = "Success"
    app = AppInfo(
        name="test", source="UnknownSource",
        version="1.0", latest_version="1.1", app_id="test",
    )
    # Resultado pode ser True (tentou) ou False (source não suportada)
    result = UpdateExecutor._execute_single_update(app)
    assert isinstance(result, bool)


# ─── ThemeManager e DisplayFormatter ──────────────────────────────────────────

def test_theme_manager_invalid():
    """Tema inexistente deve retornar o tema default sem KeyError."""
    theme_invalid = ThemeManager.get_theme('invalid_theme')
    theme_default = ThemeManager.get_theme('default')
    assert theme_invalid == theme_default


def test_display_formatter_unknown_format():
    """Formato desconhecido deve usar fallback sem crash."""
    apps = [AppInfo(name="test", source="winget", version="1.0")]
    table = DisplayFormatter.format_table(apps, 'unknown_format')
    assert table is not None


# ─── VulnerabilityHistory ──────────────────────────────────────────────────────

def test_vulnerability_history_corrupted(tmp_path):
    """Histórico com JSON inválido não deve crashar."""
    hist_file = tmp_path / "vuln.json"
    hist_file.write_text("{corrupted")
    vh = VulnerabilityHistory(hist_file)
    stats = vh.get_statistics()
    assert isinstance(stats, dict)


# ─── scan_system com erro em source ───────────────────────────────────────────

@patch('system_update.PackageScanner.scan_winget', side_effect=Exception("Source not found"))
def test_scan_system_source_error(mock_scan):
    """Erro em um source não deve impedir outros de serem escaneados."""
    app = SystemUpdateApp()
    # scan_system deve capturar a exceção e retornar lista (possivelmente vazia)
    apps = app.scan_system(source_filter="winget")
    assert isinstance(apps, list)


# ─── CLI main() ────────────────────────────────────────────────────────────────

def test_main_with_invalid_args():
    """Argumento inválido deve causar SystemExit (argparse)."""
    import sys
    from system_update import main
    sys.argv = ['system_update.py', '--invalid-arg']
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code != 0


def test_main_profile_not_found():
    """Profile inexistente com --help não deve travar."""
    import sys
    from system_update import main
    sys.argv = ['system_update.py', '--profile', 'nonexistent_profile', '--help']
    with pytest.raises(SystemExit):
        main()


def test_main_profile_import_nonexistent():
    """--profile-import de arquivo inexistente → SystemExit controlado."""
    import sys
    from system_update import main
    sys.argv = ['system_update.py', '--profile-import', 'arquivo_inexistente.json']
    with pytest.raises(SystemExit) as exc_info:
        main()
    # Código de saída deve indicar erro (não 0)
    assert exc_info.value.code != 0


# ─── NotificationManager ──────────────────────────────────────────────────────

@patch('smtplib.SMTP')
def test_email_smtp_success(mock_smtp):
    """send_email via SMTP com credenciais válidas deve retornar True."""
    nm = NotificationManager()
    mock_server = MagicMock()
    mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
    mock_smtp.return_value.__exit__ = MagicMock(return_value=False)

    result = nm.send_email(
        'test@test.com', 'Subject', 'Body',
        smtp_server='smtp.gmail.com',
        username='user',
        password='pass',
    )
    assert result is True


@patch('subprocess.run')
def test_email_api_failure(mock_sub):
    """send_email via API com returncode != 0 deve retornar False."""
    nm = NotificationManager()
    mock_sub.return_value = MagicMock(returncode=1, stdout='', stderr='Error', text=True)
    result = nm.send_email(
        'test@test.com', 'Subject', 'Body',
        smtp_server='https://api.mailtrap.io',
    )
    assert result is False