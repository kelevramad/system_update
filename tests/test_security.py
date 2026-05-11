import json
import subprocess
from urllib.error import URLError
from unittest.mock import patch

import pytest

from system_update.models import AppInfo, UpdateStatus
from system_update.security import github as github_security
from system_update.security import npm as npm_security
from system_update.security import osv
from system_update.security.common import is_security_issue
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


def test_osv_network_failure_returns_visible_issue(caplog):
	apps = [AppInfo(name='pkg', source='npm', version='1.0.0')]

	with patch('system_update.security.osv.fetch_json', side_effect=URLError('offline')):
		result = osv.check(apps)

	assert len(result) == 1
	assert is_security_issue(result[0])
	assert result[0]['status'] == 'error'
	assert 'OSV check skipped' in result[0]['message']
	assert 'api.osv.dev' in caplog.text
	assert apps[0].security_findings == []
	assert apps[0].update_status != UpdateStatus.VULNERABLE


def test_osv_json_decode_failure_returns_visible_issue():
	apps = [AppInfo(name='pkg', source='npm', version='1.0.0')]
	error = json.JSONDecodeError('bad json', '{', 0)

	with patch('system_update.security.osv.fetch_json', side_effect=error):
		result = osv.check(apps)

	assert len(result) == 1
	assert is_security_issue(result[0])
	assert 'JSONDecodeError' in result[0]['message']


def test_osv_success_has_no_issue_marker():
	apps = [AppInfo(name='pkg', source='npm', version='1.0.0')]
	payload = {
		'results': [
			{
				'vulns': [
					{
						'id': 'OSV-2026-1',
						'summary': 'Bad package',
						'severity': [{'type': 'cvss_v3', 'score': 7.5}],
					}
				]
			}
		]
	}

	with patch('system_update.security.osv.fetch_json', return_value=payload):
		result = osv.check(apps)

	assert len(result) == 1
	assert not is_security_issue(result[0])
	assert result[0]['cve'] == 'OSV-2026-1'
	assert apps[0].update_status == UpdateStatus.VULNERABLE


def test_npm_audit_parses_vulnerabilities_from_local_package(tmp_path, monkeypatch):
	(tmp_path / 'package.json').write_text('{}', encoding='utf-8')
	monkeypatch.chdir(tmp_path)
	apps = [AppInfo(name='pkg', source='npm', version='1.0.0')]
	payload = {
		'vulnerabilities': {
			'pkg': {
				'severity': 'critical',
				'via': [{'id': 'CVE-2026-1', 'title': 'bad pkg'}],
			}
		}
	}
	result = subprocess.CompletedProcess(
		['npm', 'audit'],
		1,
		stdout=json.dumps(payload).encode('utf-8'),
		stderr=b'',
	)

	with patch('system_update.security.npm.subprocess.run', return_value=result):
		vulns = npm_security.check(apps)

	assert len(vulns) == 1
	assert not is_security_issue(vulns[0])
	assert vulns[0]['cve'] == 'CVE-2026-1'
	assert apps[0].update_status == UpdateStatus.VULNERABLE


def test_npm_audit_uses_global_root_when_local_package_missing(tmp_path, monkeypatch):
	monkeypatch.chdir(tmp_path)
	apps = [AppInfo(name='pkg', source='npm', version='1.0.0')]
	root_result = subprocess.CompletedProcess(
		['npm', 'root', '-g'],
		0,
		stdout=str(tmp_path / 'node_modules').encode('utf-8'),
		stderr=b'',
	)
	audit_result = subprocess.CompletedProcess(
		['npm', 'audit'],
		0,
		stdout=b'{"vulnerabilities": {}}',
		stderr=b'',
	)

	with patch(
		'system_update.security.npm.subprocess.run',
		side_effect=[root_result, audit_result],
	) as mock_run:
		vulns = npm_security.check(apps)

	assert vulns == []
	assert mock_run.call_args_list[1].args[0][-2:] == ['--prefix', str(tmp_path)]


def test_npm_audit_skipped_is_distinguishable_from_clean(tmp_path, monkeypatch):
	monkeypatch.chdir(tmp_path)
	apps = [AppInfo(name='pkg', source='npm', version='1.0.0')]
	root_result = subprocess.CompletedProcess(
		['npm', 'root', '-g'],
		1,
		stdout=b'',
		stderr=b'npm error',
	)

	with patch('system_update.security.npm.subprocess.run', return_value=root_result):
		vulns = npm_security.check(apps)

	assert len(vulns) == 1
	assert is_security_issue(vulns[0])
	assert vulns[0]['status'] == 'skipped'
	assert 'no package.json or global root reachable' in vulns[0]['message']


# ─── Hardening 4.5 — pip_apps indexed lookup ──────────────────────────────


def test_pip_security_indexed_lookup_is_case_insensitive():
	apps = [AppInfo(name='Requests', source='pip', version='2.0.0')]
	pip_audit_json = json.dumps({
		'dependencies': [
			{
				'name': 'requests',
				'version': '2.0.0',
				'vulns': [{'id': 'CVE-X', 'fix_versions': ['3.0.0']}],
			},
		],
	})

	with patch('system_update.security.pip.run_command', return_value=pip_audit_json):
		vulns = pip_security.check(apps)

	assert len(vulns) == 1
	assert vulns[0]['cve'] == 'CVE-X'
	assert apps[0].update_status == UpdateStatus.VULNERABLE


def test_pip_security_ignores_packages_not_in_inventory():
	apps = [AppInfo(name='requests', source='pip', version='2.0.0')]
	pip_audit_json = json.dumps({
		'dependencies': [
			{'name': 'not-installed', 'version': '1.0.0', 'vulns': [{'id': 'CVE-Y'}]},
		],
	})

	with patch('system_update.security.pip.run_command', return_value=pip_audit_json):
		vulns = pip_security.check(apps)

	assert vulns == []


# ─── Hardening 4.1 — parallel GitHub Advisory queries ────────────────────


def test_github_security_uses_thread_pool_for_queries():
	apps = [
		AppInfo(name='a', source='npm', version='1.0.0'),
		AppInfo(name='b', source='npm', version='1.0.0'),
		AppInfo(name='c', source='pip', version='1.0.0'),
	]
	advisory = {
		'severity': 'HIGH',
		'ghsa_id': 'GHSA-test',
		'cve_id': 'CVE-Z',
		'description': 'bad',
		'affected': [
			{'package': {'name': 'a'}, 'vulnerable_version_range': '<2.0.0'},
		],
	}

	def fake_fetch_json(url, **_kwargs):
		# Only the request for "a" returns the matching advisory.
		if 'package=a' in url:
			return [advisory]
		return []

	with patch.object(github_security, 'fetch_json', side_effect=fake_fetch_json) as fetch:
		vulns = github_security.check(apps)

	# One request per ecosystem-eligible candidate.
	assert fetch.call_count == 3
	assert len(vulns) == 1
	assert vulns[0]['cve'] == 'CVE-Z'
	# Only 'a' should be flagged as vulnerable.
	by_name = {a.name: a for a in apps}
	assert by_name['a'].update_status == UpdateStatus.VULNERABLE
	assert by_name['b'].update_status != UpdateStatus.VULNERABLE
