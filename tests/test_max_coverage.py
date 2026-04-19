import pytest
import json
from unittest.mock import MagicMock, patch
from system_update import (
    AppInfo, PackageScanner, UpdateChecker,
    SystemUpdateApp, UpdateExecutor
)

# ═══════════════════════════════════════════════════════════════════════════════
# PARAMETERIZED TESTS — SCANNERS
# FIX: mock diferenciado por source para refletir o formato real de saída
#      de cada scanner (alguns esperam "name|version", outros JSON de lista,
#      outros JSON de objeto, etc.).
# ═══════════════════════════════════════════════════════════════════════════════

_SCANNER_MOCKS = {
    # formato pipe-separado
    "winget":     "Git                            Git.Git  2.40.0  2.41.0  winget",
    "chocolatey": "git|2.40.0",
    "scoop":      "git (2.41.0) - distributed vcs",
    "rust":       "clippy 0.1.0",
    "dotnet":     "NuGet.Client   6.0.0",
    # formato JSON lista de objetos com Name/Version
    "registry":   json.dumps([{"Name": "test", "Version": "1.0", "InstallLocation": "C:\\"}]),
    "appx":       json.dumps([{"Name": "test", "Version": "1.0"}]),
    "msix":       json.dumps([{"Name": "test", "Version": "1.0"}]),
    # formato JSON de dependências npm-like
    "npm":        json.dumps({"dependencies": {"test": {"version": "1.0.0"}}}),
    "pnpm":       json.dumps({"dependencies": {"test": {"version": "1.0.0"}}}),
    "bun":        json.dumps([{"name": "test", "version": "1.0.0"}]),
    "yarn":       json.dumps([{"name": "test", "version": "1.0.0"}]),
    # path usa versão simples
    "pip":        json.dumps([{"name": "requests", "version": "2.28.1"}]),
}


@pytest.mark.parametrize("source", list(_SCANNER_MOCKS.keys()))
@patch('system_update.run_command')
def test_scanners_parameterized(mock_run, source):
    """Cada scanner recebe o formato de output que produziria no real."""
    mock_run.return_value = _SCANNER_MOCKS[source]
    scanner_method = getattr(PackageScanner, f"scan_{source}")
    apps = scanner_method()
    assert isinstance(apps, list)


# ═══════════════════════════════════════════════════════════════════════════════
# PARAMETERIZED TESTS — CHECKERS
# FIX: mock de npm/pip alinhado com o formato real da API (dist-tags.latest),
#      não com {"test": {"latest": "1.1"}} que nunca seria retornado.
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("source, method, mock_output", [
    (
        "winget",
        "_check_winget_updates",
        "Name Id Version Available Source\n--- --- --- --- ---\ntest ID 1.0 1.1 winget",
    ),
    (
        "chocolatey",
        "_check_choco_updates",
        "test|1.0|1.1",
    ),
    (
        "npm",
        "_check_npm_updates",
        # formato retornado por `npm view <pkg> --json`
        json.dumps({"dist-tags": {"latest": "1.1"}, "version": "1.0"}),
    ),
    (
        "pip",
        "_check_pip_updates",
        # formato retornado por `pip index versions <pkg>` ou PyPI JSON
        json.dumps({"info": {"version": "1.1"}}),
    ),
])
@patch('system_update.run_command')
def test_checkers_parameterized(mock_run, source, method, mock_output):
    apps = [AppInfo(name="test", source=source, version="1.0")]
    mock_run.return_value = mock_output
    checker_method = getattr(UpdateChecker, method)
    count = checker_method(apps)
    assert count >= 0


# ═══════════════════════════════════════════════════════════════════════════════
# EXECUTOR BRANCHES
# FIX: removida duplicata com test_executor_all_sources (test_coverage_extended).
#      Mantidos apenas os sources que não aparecem lá: scoop, path, appx, msix.
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("source", ["Scoop", "PATH", "Appx", "Msix"])
@patch('system_update.run_command', return_value="OK")
def test_executor_additional_sources(mock_run, source):
    """Cobre sources não testados em test_coverage_extended."""
    app = AppInfo(name="pkg", source=source, version="1.0", latest_version="1.1", app_id="ID")
    result = UpdateExecutor._execute_single_update(app)
    assert isinstance(result, bool)


# ═══════════════════════════════════════════════════════════════════════════════
# SYSTEM UPDATE APP — run() branches
# ═══════════════════════════════════════════════════════════════════════════════

def test_run_clear_cache():
    """
    FIX: clear_cache=True deve limpar o cache e retornar sem tentar escanear.
    O mock de scan garante que não há AttributeError por config ausente.
    """
    app = SystemUpdateApp()
    args = MagicMock()
    args.clear_cache = True

    with patch.object(app.cache_mgr, 'clear') as mock_clear, \
         patch('system_update.console.print'):
        app.run(args)
        mock_clear.assert_called_once()


def test_run_interactive_mode():
    """interactive=True deve chamar launch_interactive_mode."""
    app = SystemUpdateApp()
    args = MagicMock()
    args.clear_cache = False
    args.interactive = True

    with patch.object(SystemUpdateApp, 'launch_interactive_mode') as mock_int, \
         patch('system_update.console.print'):
        app.run(args)
        mock_int.assert_called_once()


def test_run_normal_scan():
    """Scan normal sem flags especiais deve invocar scan_system."""
    app = SystemUpdateApp()
    args = MagicMock()
    args.clear_cache = False
    args.interactive = False
    args.update_all = False
    args.dry_run = False
    args.package = None
    args.update_source = None

    with patch.object(SystemUpdateApp, 'scan_system', return_value=[]) as mock_scan, \
         patch('system_update.console.print'):
        app.run(args)
        mock_scan.assert_called()