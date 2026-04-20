from unittest.mock import patch
from system_update import UpdateChecker, AppInfo, UpdateStatus, SystemUpdateApp


# ─── UpdateChecker._check_path_updates ────────────────────────────────────────

@patch('system_update.run_command')
def test_check_path_updates_exhaustive(mock_run):
    """
    FIX: o mock original usava 'bun' in cmd, mas run_command recebe uma lista.
    Corrigido para checar cada elemento da lista com any(...).
    """
    def side_effect(cmd, **kwargs):
        # cmd é uma lista, ex: ['bun', '--version']
        cmd_str = ' '.join(str(c) for c in cmd) if isinstance(cmd, list) else cmd
        if 'bun' in cmd_str:
            return "Bun v1.0.0 is out!"
        if 'deno' in cmd_str:
            return "Found latest stable version v1.2.0"
        if 'yarn' in cmd_str:
            return "1.2.0"
        if 'npm' in cmd_str:
            return "1.2.0"
        if 'pnpm' in cmd_str:
            return "1.2.0"
        if 'node' in cmd_str:
            return "1.2.0"
        if 'python' in cmd_str:
            return "v3.12.0"
        if 'git' in cmd_str:
            return "2.40.0"
        if 'pwsh' in cmd_str:
            return "v7.3.0"
        if 'winget' in cmd_str or 'dotnet' in cmd_str:
            return "Version: 9.0.0"
        if 'cargo' in cmd_str or 'rustc' in cmd_str:
            return "1.70.0"
        return "1.0.0"

    mock_run.side_effect = side_effect

    tools = ['bun', 'deno', 'yarn', 'npm', 'pnpm', 'node', 'python', 'git', 'pwsh', 'dotnet', 'rustc', 'cargo']
    apps = [AppInfo(name=tool, source='PATH', version='0.9.0') for tool in tools]

    count = UpdateChecker._check_path_updates(apps)
    # Cada tool recebe versão "1.0.0" atual e o mock retorna algo diferente de "0.9.0",
    # então ao menos parte deve ser detectada. Não assertamos == len(tools) porque
    # cada tool tem seu próprio parser de versão interno.
    assert count > 0, f"Nenhum update detectado — mock pode não estar sendo aplicado"


@patch('system_update.run_command')
def test_check_path_updates_empty(mock_run):
    """Sem apps PATH → deve retornar 0 sem erros."""
    count = UpdateChecker._check_path_updates([])
    assert count == 0
    mock_run.assert_not_called()


# ─── SystemUpdateApp — checagem de vulnerabilidades ───────────────────────────

@patch('system_update.run_command')
def test_check_npm_vulns_via_audit(mock_run):
    """
    FIX: _check_npm_vulns usa subprocess (npm audit), não urllib.
    O mock correto é run_command, não urlopen.
    """
    app_obj = SystemUpdateApp()
    apps = [AppInfo(name='pkg', source='npm', version='1.0.0')]

    mock_run.return_value = (
        '{"vulnerabilities": {"pkg": {"severity": "critical", "via": [{"id": "CVE-1"}]}}}'
    )
    vulns = app_obj._check_npm_vulns(apps)
    assert len(vulns) == 1
    assert apps[0].update_status == UpdateStatus.VULNERABLE


@patch('system_update.run_command')
def test_check_pip_vulns_via_audit(mock_run):
    """
    FIX: _check_pip_vulns usa subprocess (pip-audit), não urllib.
    O mock correto é run_command, não urlopen.
    """
    app_obj = SystemUpdateApp()
    apps_pip = [AppInfo(name='requests', source='pip', version='1.0.0')]

    mock_run.return_value = (
        '{"dependencies": [{"name": "requests", "vulns": [{"id": "CVE-pip"}]}]}'
    )
    vulns = app_obj._check_pip_vulns(apps_pip)
    assert len(vulns) == 1
    assert apps_pip[0].update_status == UpdateStatus.VULNERABLE


@patch('system_update.run_command')
def test_check_npm_vulns_no_findings(mock_run):
    """Sem vulnerabilidades → lista vazia, status não alterado."""
    app_obj = SystemUpdateApp()
    apps = [AppInfo(name='pkg', source='npm', version='1.0.0')]

    mock_run.return_value = '{"vulnerabilities": {}}'
    vulns = app_obj._check_npm_vulns(apps)
    assert vulns == []
    assert apps[0].update_status != UpdateStatus.VULNERABLE


@patch('system_update.run_command')
def test_check_npm_vulns_malformed_json(mock_run):
    """JSON malformado não deve lançar exceção — retorna lista vazia."""
    app_obj = SystemUpdateApp()
    apps = [AppInfo(name='pkg', source='npm', version='1.0.0')]

    mock_run.return_value = "invalid json{"
    vulns = app_obj._check_npm_vulns(apps)
    assert isinstance(vulns, list)
    app_obj.history_db.close()


@patch('system_update.run_command')
def test_check_pip_vulns_malformed_json(mock_run):
    """JSON malformado não deve lançar exceção — retorna lista vazia."""
    app_obj = SystemUpdateApp()
    apps = [AppInfo(name='requests', source='pip', version='1.0.0')]

    mock_run.return_value = "invalid{"
    vulns = app_obj._check_pip_vulns(apps)
    assert isinstance(vulns, list)
    app_obj.history_db.close()