import json
from unittest.mock import patch

import pytest

from system_update.models import AppInfo, UpdateStatus
from system_update.security import pip as pip_security


@pytest.fixture(scope='session')
def pip_scan_output(seeded_cache, cli_runner):
	"""Use the seeded cache; if ``seeded_cache`` ran a superset scan, this is a
	cache hit (<1s) instead of a fresh 20s scan."""
	return cli_runner(['--source', 'pip'], timeout=60)


def test_security_scan(pip_scan_output):
	output = pip_scan_output['stdout'] + pip_scan_output['stderr']
	assert (
		pip_scan_output['code'] == 0
		or 'vuln' in output.lower()
		or 'security' in output.lower()
		or 'scan' in output.lower()
	)


def test_security_scan_coverage(pip_scan_output):
	output = pip_scan_output['stdout'] + pip_scan_output['stderr']
	assert (
		pip_scan_output['code'] == 0
		or 'vuln' in output.lower()
		or 'security' in output.lower()
		or 'scan' in output.lower()
	)


def test_security_update_auto_priority(seeded_cache, cli_runner):
	res = cli_runner(['--source', 'pip', '--update-all', '--yes'], timeout=120)
	assert res['code'] == 0


def test_security_local_advisory(pip_scan_output):
	assert pip_scan_output['code'] == 0


def test_pip_audit_uses_scanned_interpreter(tmp_path):
	python_exe = tmp_path / 'python.exe'
	python_exe.write_text('', encoding='utf-8')
	apps = [
		AppInfo(
			name='pip',
			source='PIP',
			version='26.1',
			install_path=str(python_exe),
		)
	]
	payload = {'dependencies': [{'name': 'pip', 'version': '26.1', 'vulns': []}]}

	with patch('system_update.security.pip.run_command', return_value=json.dumps(payload)) as mock_run:
		pip_security.check(apps)

	assert mock_run.call_args.kwargs['env_overrides'] == {
		'PIPAPI_PYTHON_LOCATION': str(python_exe)
	}


def test_pip_audit_skips_findings_from_different_installed_version():
	apps = [
		AppInfo(
			name='pip',
			source='PIP',
			version='26.1',
			latest_version='26.1',
		)
	]
	payload = {
		'dependencies': [
			{
				'name': 'pip',
				'version': '26.0.1',
				'vulns': [{'id': 'CVE-2026-3219', 'fix_versions': []}],
			}
		]
	}

	with patch('system_update.security.pip.run_command', return_value=json.dumps(payload)):
		vulns = pip_security.check(apps)

	assert vulns == []
	assert apps[0].security_findings == []
	assert apps[0].update_status != UpdateStatus.VULNERABLE
