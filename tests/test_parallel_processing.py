import time

from system_update.models import AppInfo, UpdateStatus
from system_update.utils import dedupe_apps


def test_check_all_updates_runs_sources_in_parallel(monkeypatch):
	from system_update import checkers

	apps = [
		AppInfo(name='one', source='npm', version='1.0'),
		AppInfo(name='two', source='pip', version='1.0'),
	]

	def slow_update(source_apps):
		time.sleep(0.3)
		source_apps[0].latest_version = '2.0'
		source_apps[0].update_status = UpdateStatus.UPDATE_AVAILABLE
		return 1

	monkeypatch.setitem(checkers._SOURCE_CHECKERS, 'npm', slow_update)
	monkeypatch.setitem(checkers._SOURCE_CHECKERS, 'pip', slow_update)

	start = time.perf_counter()
	total = checkers.check_all_updates(apps, max_workers=2)
	elapsed = time.perf_counter() - start

	assert total == 2
	assert elapsed < 0.5


def test_check_all_updates_gracefully_handles_source_failure(monkeypatch):
	from system_update import checkers

	apps = [
		AppInfo(name='bad', source='npm', version='1.0'),
		AppInfo(name='good', source='pip', version='1.0'),
	]

	def fail(_source_apps):
		raise RuntimeError('boom')

	def succeed(source_apps):
		source_apps[0].latest_version = '2.0'
		source_apps[0].update_status = UpdateStatus.UPDATE_AVAILABLE
		return 1

	monkeypatch.setitem(checkers._SOURCE_CHECKERS, 'npm', fail)
	monkeypatch.setitem(checkers._SOURCE_CHECKERS, 'pip', succeed)

	assert checkers.check_all_updates(apps, max_workers=2) == 1
	assert apps[0].update_status == UpdateStatus.ERROR
	assert apps[1].update_status == UpdateStatus.UPDATE_AVAILABLE


def test_dedupe_apps_preserves_last_package_record():
	apps = [
		AppInfo(name='Git', source='winget', version='1.0', app_id='old'),
		AppInfo(name='Git', source='winget', version='1.0', app_id='new'),
		AppInfo(name='Git', source='path', version='1.0', app_id='path'),
	]

	result = dedupe_apps(apps)

	assert len(result) == 2
	assert result[0].app_id == 'new'
	assert result[1].source == 'path'
