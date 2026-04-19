from unittest.mock import patch
from system_update import UpdateChecker, AppInfo, UpdateStatus, SystemUpdateApp


# Target: UpdateChecker._check_path_updates (lines 3164-3278)
@patch('system_update.run_command')
def test_check_path_updates_exhaustive(mock_run):
	# This mock side-effect should cover all tool branches
	def side_effect(cmd, **kwargs):
		if 'bun' in cmd:
			return 'Bun v1.0.0 is out!'  # branch 'bun'
		if 'deno' in cmd:
			return 'Found latest stable version v1.2.0'  # branch 'deno'
		if 'npm' in cmd:
			return '1.2.0'  # branches 'yarn', 'npm', 'pnpm', 'node'
		if 'python' in cmd:
			return 'v3.12.0'
		if 'git' in cmd:
			return '2.40.0'
		if 'pwsh' in cmd:
			return 'v7.3.0'
		if 'winget' in cmd:
			return 'Version: 9.0.0'  # dotnet branch
		if 'cargo' in cmd:
			return '1.70.0'
		return '1.0.0'

	mock_run.side_effect = side_effect

	# Create apps for all tools
	tools = [
		'bun',
		'deno',
		'yarn',
		'npm',
		'pnpm',
		'node',
		'python',
		'git',
		'pwsh',
		'dotnet',
		'rustc',
		'cargo',
	]
	apps = [AppInfo(name=tool, source='PATH', version='0.9.0') for tool in tools]

	count = UpdateChecker._check_path_updates(apps)
	assert count > 0


# Target: SystemUpdateApp security check branches (massive blocks in run())
# We will create a test that specifically targets these scenarios


@patch('system_update.run_command')
def test_system_update_app_security_checks(mock_run):
	app = SystemUpdateApp()
	apps = [AppInfo(name='pkg', source='npm', version='1.0.0')]

	# 1. npm audit failure scenario
	mock_run.return_value = (
		'{"vulnerabilities": {"pkg": {"severity": "critical", "via": [{"id": "CVE-1"}]}}}'
	)
	vulns = app._check_npm_vulns(apps)
	assert len(vulns) == 1
	assert apps[0].update_status == UpdateStatus.VULNERABLE

	# 2. pip-audit scenario
	apps_pip = [AppInfo(name='requests', source='pip', version='1.0.0')]
	mock_run.return_value = '{"dependencies": [{"name": "requests", "vulns": [{"id": "CVE-pip"}]}]}'
	vulns = app._check_pip_vulns(apps_pip)
	assert len(vulns) == 1
	assert apps_pip[0].update_status == UpdateStatus.VULNERABLE
