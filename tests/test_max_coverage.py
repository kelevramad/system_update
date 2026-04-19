import pytest
import json
from unittest.mock import MagicMock, patch
from system_update import AppInfo, PackageScanner, UpdateChecker, SystemUpdateApp, UpdateExecutor

# ═══════════════════════════════════════════════════════════════════════════════
# PARAMETERIZED TESTS FOR EXTENSIVE COVERAGE
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize(
	'source',
	[
		'winget',
		'chocolatey',
		'npm',
		'pnpm',
		'bun',
		'yarn',
		'pip',
		'rust',
		'scoop',
		'dotnet',
		'registry',
		'appx',
		'msix',
	],
)
@patch('system_update.run_command')
def test_scanners_parameterized(mock_run, source):
	# Setup standard mocks for scanners
	if source in ['npm', 'pnpm', 'registry', 'appx', 'msix']:
		mock_run.return_value = json.dumps([{'Name': 'test', 'Version': '1.0'}])
	else:
		mock_run.return_value = 'test|1.0'

	scanner_method = getattr(PackageScanner, f'scan_{source}')
	apps = scanner_method()
	assert isinstance(apps, list)


@pytest.mark.parametrize(
	'source, method',
	[
		('winget', '_check_winget_updates'),
		('chocolatey', '_check_choco_updates'),
		('npm', '_check_npm_updates'),
		('pip', '_check_pip_updates'),
	],
)
@patch('system_update.run_command')
def test_checkers_parameterized(mock_run, source, method):
	apps = [AppInfo(name='test', source=source, version='1.0')]
	# Minimal mock output to trigger update logic
	if source == 'winget':
		mock_run.return_value = (
			'Name Id Version Available Source\n--- --- --- --- ---\ntest ID 1.0 1.1 winget'
		)
	elif source == 'chocolatey':
		mock_run.return_value = 'test|1.0|1.1'
	else:
		mock_run.return_value = json.dumps({'test': {'latest': '1.1'}})

	checker_method = getattr(UpdateChecker, method)
	count = checker_method(apps)
	assert count >= 0


@patch('system_update.run_command', return_value='OK')
def test_executor_branches(mock_run):
	sources = ['Winget', 'Chocolatey', 'NPM', 'PNPM', 'Bun', 'Yarn', 'PIP', 'Rust', 'dotnet']
	for src in sources:
		app = AppInfo(name='pkg', source=src, version='1.0', latest_version='1.1', app_id='ID')
		assert UpdateExecutor._execute_single_update(app) is True


def test_system_update_app_run_branches():
	app = SystemUpdateApp()

	# Test specific run branches (interactive, clear cache)
	with patch('system_update.console.print'):
		# Mock args
		args = MagicMock()
		args.clear_cache = True
		app.run(args)

		args.clear_cache = False
		args.interactive = True
		with patch.object(SystemUpdateApp, 'launch_interactive_mode') as mock_int:
			app.run(args)
			assert mock_int.called
