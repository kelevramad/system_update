import pytest


@pytest.fixture(scope='session')
def choco_scan_output(seeded_cache, cli_runner):
	return cli_runner(['--source', 'chocolatey'], timeout=60)


@pytest.fixture(scope='session')
def pip_scan_output(seeded_cache, cli_runner):
	return cli_runner(['--source', 'pip'], timeout=60)


@pytest.mark.parametrize('source', ['winget', 'npm', 'chocolatey'])
def test_source_scan(source, seeded_cache, cli_runner):
	res = cli_runner(['--source', source], timeout=60)
	assert res['code'] == 0


def test_source_chocolatey(choco_scan_output):
	assert choco_scan_output['code'] == 0


def test_source_pip(pip_scan_output):
	assert pip_scan_output['code'] == 0


def test_source_multiple_sources(seeded_cache, cli_runner):
	res = cli_runner(['--source', 'chocolatey,pip'], timeout=60)
	assert res['code'] == 0
