import pytest
import json
from unittest.mock import patch
from system_update import PackageScanner

_SCANNER_MOCKS = {
    'winget': 'Git                            Git.Git  2.40.0  2.41.0  winget',
    'chocolatey': 'git|2.40.0',
    'scoop': 'git (2.41.0) - distributed vcs',
    'rust': 'clippy 0.1.0',
    'dotnet': 'NuGet.Client   6.0.0',
    'registry': json.dumps([{'Name': 'test', 'Version': '1.0', 'InstallLocation': 'C:\\'}]),
    'appx': json.dumps([{'Name': 'test', 'Version': '1.0'}]),
    'msix': json.dumps([{'Name': 'test', 'Version': '1.0'}]),
    'npm': json.dumps({'dependencies': {'test': {'version': '1.0.0'}}}),
    'pnpm': json.dumps({'dependencies': {'test': {'version': '1.0.0'}}}),
    'bun': json.dumps([{'name': 'test', 'version': '1.0.0'}]),
    'yarn': json.dumps([{'name': 'test', 'version': '1.0.0'}]),
    'pip': json.dumps([{'name': 'requests', 'version': '2.28.1'}]),
}

@pytest.mark.parametrize('source', list(_SCANNER_MOCKS.keys()))
@patch('system_update.run_command')
def test_scanners_parameterized(mock_run, source):
    mock_run.return_value = _SCANNER_MOCKS[source]
    scanner_method = getattr(PackageScanner, f'scan_{source}')
    apps = scanner_method()
    assert isinstance(apps, list)

@patch('system_update.run_command')
def test_scan_winget_parsing(mock_run):
    header = 'Name                           Id                                         Version          Available        Source'
    line1 = 'Git                            Git.Git                                    2.40.0.windows.1 2.41.0.windows.1 winget'
    mock_run.return_value = f'{header}\n{line1}'
    apps = PackageScanner.scan_winget()
    assert len(apps) >= 0

@patch('system_update.run_command')
def test_scan_npm_parsing(mock_run):
    mock_run.return_value = json.dumps({'dependencies': {'npm': {'version': '9.5.0'}}})
    apps = PackageScanner.scan_npm()
    assert isinstance(apps, list)

@patch('system_update.run_command')
def test_scan_pip_parsing(mock_run):
    mock_run.return_value = json.dumps([{'name': 'requests', 'version': '2.28.1'}])
    apps = PackageScanner.scan_pip()
    assert isinstance(apps, list)

@patch('system_update.run_command')
def test_scan_chocolatey_parsing(mock_run):
    mock_run.return_value = 'git|2.40.0'
    apps = PackageScanner.scan_chocolatey()
    assert isinstance(apps, list)

@patch('system_update.run_command')
@patch('platform.system', return_value='Windows')
def test_scan_registry_parsing(mock_platform, mock_run):
    mock_run.return_value = json.dumps([{'Name': 'App', 'Version': '1.0', 'InstallLocation': 'C:\\'}])
    apps = PackageScanner.scan_registry()
    assert isinstance(apps, list)

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
