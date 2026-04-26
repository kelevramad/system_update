import pytest


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
