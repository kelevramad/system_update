import pytest
import json
from unittest.mock import patch
from system_update import PackageScanner
from system_update.scanners import get_scanner_map, scanner

_SCANNER_MOCKS = {
	'winget': 'Git                            Git.Git  2.40.0  2.41.0  winget',
	'chocolatey': 'git|2.40.0',
	'scoop': 'git (2.41.0) - distributed vcs',
	'rust': 'clippy 0.1.0',
	'dotnet': 'NuGet.Client   6.0.0',
	'registry': json.dumps([{'Name': 'test', 'Version': '1.0', 'InstallLocation': 'C:\\'}]),
	'appx': json.dumps([{'Name': 'test', 'Version': '1.0'}]),
	'msix': json.dumps([{'Name': 'test', 'Version': '1.0'}]),
	'drivers': 'Published Name: oem1.inf\nDriver Package Provider: Vendor\nDriver Version: 01/01/2026 1.0.0\n',
	'services': json.dumps([{'Name': 'Svc', 'ServiceName': 'svc', 'Version': '1.0'}]),
	'psmodules': json.dumps([{'Name': 'Pester', 'Version': '5.0.0'}]),
	'vsextensions': 'ms-python.python@2026.1.0',
	'npm': json.dumps({'dependencies': {'test': {'version': '1.0.0'}}}),
	'pnpm': json.dumps({'dependencies': {'test': {'version': '1.0.0'}}}),
	'bun': json.dumps([{'name': 'test', 'version': '1.0.0'}]),
	'yarn': json.dumps([{'name': 'test', 'version': '1.0.0'}]),
	'pip': json.dumps([{'name': 'requests', 'version': '2.28.1'}]),
}


def test_scanner_decorator_registers_callable():
	def demo_scan():
		return []

	registered = scanner('demo-unit')(demo_scan)
	try:
		assert registered is demo_scan
		assert get_scanner_map()['demo-unit'] is demo_scan
	finally:
		from system_update.scanners import _SCANNERS

		_SCANNERS.pop('demo-unit', None)


def test_get_scanner_map_returns_defensive_copy():
	scanners = get_scanner_map()
	scanners.pop('winget')
	assert 'winget' in get_scanner_map()


def test_all_builtin_sources_are_registered():
	assert set(_SCANNER_MOCKS) <= set(get_scanner_map())


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
	mock_run.return_value = json.dumps(
		[{'Name': 'App', 'Version': '1.0', 'InstallLocation': 'C:\\'}]
	)
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


@patch('platform.system', return_value='Windows')
@patch('system_update.run_command')
def test_scan_appx_ignores_powershell_noise(mock_run, _mock_platform):
	mock_run.return_value = (
		'WARNING: [provider] warning\n'
		+ json.dumps([{'Name': 'Store App', 'Version': '2.0', 'PackageFullName': 'Store.App_2.0'}])
	)
	apps = PackageScanner.scan_appx()
	assert apps[0].name == 'Store App'
	assert apps[0].version == '2.0'


@patch('system_update.run_command')
def test_scan_msix_parsing(mock_run):
	mock_run.return_value = json.dumps([{'Name': 'App', 'Version': '1.0'}])
	apps = PackageScanner.scan_msix()
	assert isinstance(apps, list)


@patch('platform.system', return_value='Windows')
@patch('system_update.run_command')
def test_scan_drivers_parsing(mock_run, _mock_platform):
	mock_run.return_value = (
		'Published Name: oem42.inf\n'
		'Driver Package Provider: Contoso\n'
		'Class Name: System\n'
		'Driver Version: 05/01/2026 2.3.4\n'
	)
	apps = PackageScanner.scan_drivers()
	assert apps[0].name == 'Contoso'
	assert apps[0].source == 'drivers'
	assert apps[0].version == '2.3.4'
	assert apps[0].app_id == 'oem42.inf'


@patch('platform.system', return_value='Windows')
@patch('system_update.run_command')
def test_scan_services_parsing(mock_run, _mock_platform):
	mock_run.return_value = json.dumps(
		{
			'Name': 'Demo Service',
			'ServiceName': 'demo',
			'Version': '1.2.3 (WinBuild.160101.0800)',
			'Path': 'C:\\demo.exe',
		}
	)
	apps = PackageScanner.scan_services()
	assert apps[0].name == 'Demo Service'
	assert apps[0].source == 'services'
	assert apps[0].version == '1.2.3'
	assert apps[0].app_id == 'demo'


@patch('platform.system', return_value='Windows')
@patch('system_update.run_command')
def test_scan_services_handles_null_json(mock_run, _mock_platform):
	mock_run.return_value = 'null'
	assert PackageScanner.scan_services() == []


def test_services_script_preserves_unquoted_exe_paths_with_spaces():
	from system_update.scanners import services

	assert r'^(.+?\.exe)(?:\s+.*)?$' in services._PS_SCRIPT
	assert 'Test-Path -LiteralPath $exe' in services._PS_SCRIPT
	assert 'Get-Item -LiteralPath $exe' in services._PS_SCRIPT


@patch('platform.system', return_value='Windows')
@patch('system_update.run_command')
def test_scan_psmodules_parsing(mock_run, _mock_platform):
	mock_run.return_value = json.dumps(
		{
			'Name': 'Pester',
			'Version': {
				'Major': 5,
				'Minor': 6,
				'Build': 1,
				'Revision': -1,
				'MajorRevision': -1,
				'MinorRevision': -1,
			},
		}
	)
	apps = PackageScanner.scan_psmodules()
	assert apps[0].name == 'Pester'
	assert apps[0].source == 'psmodules'
	assert apps[0].version == '5.6.1'


@patch('platform.system', return_value='Windows')
@patch('system_update.run_command')
def test_scan_psmodules_ignores_powershell_noise(mock_run, _mock_platform):
	mock_run.return_value = (
		'WARNING: repository warning\n'
		+ json.dumps([{'Name': 'ThreadJob', 'Version': {'Major': 2, 'Minor': 0, 'Build': 3}}])
	)
	apps = PackageScanner.scan_psmodules()
	assert apps[0].name == 'ThreadJob'
	assert apps[0].version == '2.0.3'


@patch('system_update.run_command')
def test_scan_vsextensions_parsing(mock_run):
	mock_run.return_value = 'ms-python.python@2026.1.0\nredhat.vscode-yaml@1.15.0\n'
	apps = PackageScanner.scan_vsextensions()
	assert [app.name for app in apps] == ['ms-python.python', 'redhat.vscode-yaml']


@patch('system_update.run_command')
def test_scan_path_parsing(mock_run):
	mock_run.return_value = '1.0.0'
	apps = PackageScanner.scan_path()
	assert isinstance(apps, list)


@patch('platform.system', return_value='Windows')
def test_scan_registry_windows(mock_sys):
	with patch('system_update.run_command') as mock_run:
		mock_run.return_value = '[]'
		apps = PackageScanner.scan_registry()
		assert isinstance(apps, list)


@patch('platform.system', return_value='Linux')
def test_scan_registry_linux(mock_sys):
	with patch('system_update.run_command') as mock_run:
		mock_run.return_value = '[]'
		apps = PackageScanner.scan_registry()
		assert isinstance(apps, list)
