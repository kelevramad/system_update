"""Tests for enhancement section 5.4 — Data Sharing."""

from __future__ import annotations

import csv
import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from system_update import data_sharing
from system_update.models import AppInfo, UpdateStatus


# ─── 5.4.1 — import ───────────────────────────────────────────────────────


def _sample_dict(name='git', source='winget', version='1.0', latest='1.1'):
	return {
		'name': name,
		'source': source,
		'version': version,
		'latestVersion': latest,
		'appId': 'Git.Git',
		'status': 'update_available',
		'scanTime': '2026-04-25T12:00:00.000Z',
	}


def test_import_from_json_list(tmp_path: Path):
	path = tmp_path / 'scan.json'
	path.write_text(json.dumps([_sample_dict(), _sample_dict('node', 'npm')]))
	apps = data_sharing.import_from_json(path)
	assert len(apps) == 2
	assert apps[0].name == 'git'
	assert apps[0].latest_version == '1.1'
	assert apps[0].update_status == UpdateStatus.UPDATE_AVAILABLE


def test_import_from_json_object_with_packages_key(tmp_path: Path):
	path = tmp_path / 'scan.json'
	path.write_text(json.dumps({'packages': [_sample_dict()]}))
	apps = data_sharing.import_from_json(path)
	assert len(apps) == 1
	assert apps[0].name == 'git'


def test_import_from_csv(tmp_path: Path):
	path = tmp_path / 'scan.csv'
	with path.open('w', encoding='utf-8', newline='') as f:
		writer = csv.writer(f)
		writer.writerow(['Name', 'Source', 'Version', 'Latest', 'Status'])
		writer.writerow(['git', 'winget', '1.0', '1.1', 'update_available'])
		writer.writerow(['node', 'npm', '20.0.0', '20.5.0', 'update_available'])
	apps = data_sharing.import_from_csv(path)
	assert [a.name for a in apps] == ['git', 'node']


def test_import_apps_auto_dispatches_by_extension(tmp_path: Path):
	json_path = tmp_path / 'a.json'
	json_path.write_text(json.dumps([_sample_dict()]))
	csv_path = tmp_path / 'b.csv'
	csv_path.write_text('Name,Source,Version,Latest,Status\nfoo,pip,1,2,unknown\n')

	assert data_sharing.import_apps(str(json_path))[0].name == 'git'
	assert data_sharing.import_apps(str(csv_path))[0].name == 'foo'


def test_import_missing_file_raises(tmp_path: Path):
	with pytest.raises(FileNotFoundError):
		data_sharing.import_apps(str(tmp_path / 'nope.json'))


def test_import_invalid_json_structure_raises(tmp_path: Path):
	path = tmp_path / 'bad.json'
	path.write_text(json.dumps({'not_a_list': True}))
	with pytest.raises(ValueError):
		data_sharing.import_from_json(path)


# ─── 5.4.2 — merge ────────────────────────────────────────────────────────


def _app(name, source, version, when, vulns=None):
	return AppInfo(
		name=name, source=source, version=version,
		scan_time=when, security_findings=vulns or [],
	)


def test_merge_apps_dedupes_by_source_name_version():
	now = datetime.now()
	a = _app('git', 'winget', '1.0', now)
	b = _app('git', 'WINGET', '1.0', now)  # case-insensitive dup
	c = _app('node', 'npm', '20', now)
	merged = data_sharing.merge_apps([a, b, c])
	assert len(merged) == 2


def test_merge_apps_prefers_latest_scan_time():
	old = _app('git', 'winget', '1.0', datetime(2026, 1, 1))
	new = _app('git', 'winget', '1.0', datetime(2026, 4, 1))
	new.latest_version = '2.0'
	merged = data_sharing.merge_apps([old], [new], prefer='latest')
	assert merged[0].latest_version == '2.0'


def test_merge_apps_prefer_first_keeps_initial():
	old = _app('git', 'winget', '1.0', datetime(2026, 1, 1))
	old.latest_version = 'OLD'
	new = _app('git', 'winget', '1.0', datetime(2026, 4, 1))
	new.latest_version = 'NEW'
	merged = data_sharing.merge_apps([old], [new], prefer='first')
	assert merged[0].latest_version == 'OLD'


def test_merge_apps_prefer_security_picks_vulnerable_entry():
	now = datetime.now()
	clean = _app('lib', 'pip', '1', now)
	vuln = _app('lib', 'pip', '1', now - timedelta(days=5),
	            vulns=[{'cve': 'CVE-1', 'severity': 'HIGH'}])
	merged = data_sharing.merge_apps([clean], [vuln], prefer='security')
	assert merged[0].security_findings


# ─── 5.4.3 — cloud sync (file backend) ────────────────────────────────────


def _settings(target: Path, kind='file'):
	return {
		'cloud_sync': {
			'enabled': True,
			'type': kind,
			'target': str(target),
			'filename': 'cache.json',
		}
	}


def test_cloud_push_pull_file_roundtrip(tmp_path: Path):
	cache = tmp_path / 'local_cache.json'
	cache.write_text('{"hello": "world"}', encoding='utf-8')
	remote_dir = tmp_path / 'remote'
	settings = _settings(remote_dir)

	target, size = data_sharing.cloud_push(cache, settings)
	assert size > 0
	assert (remote_dir / 'cache.json').exists()

	# Wipe local and pull back.
	cache.unlink()
	src, _ = data_sharing.cloud_pull(cache, settings)
	assert cache.read_text(encoding='utf-8') == '{"hello": "world"}'
	assert 'cache.json' in src


def test_cloud_status_reports_local_and_remote_state(tmp_path: Path):
	cache = tmp_path / 'cache.json'
	cache.write_text('{}')
	remote = tmp_path / 'remote'
	remote.mkdir()
	(remote / 'cache.json').write_text('{}')
	stat = data_sharing.cloud_status(cache, _settings(remote))
	assert stat['type'] == 'file'
	assert stat['local_cache_size'] >= 0
	assert stat['remote_size'] >= 0


def test_cloud_push_missing_target_raises(tmp_path: Path):
	settings = {'cloud_sync': {'type': 'file'}}  # no target
	with pytest.raises(ValueError):
		data_sharing.cloud_push(tmp_path / 'x.json', settings)


def test_cloud_pull_missing_remote_raises(tmp_path: Path):
	cache = tmp_path / 'cache.json'
	with pytest.raises(FileNotFoundError):
		data_sharing.cloud_pull(cache, _settings(tmp_path / 'no-such-dir'))


def test_cloud_unknown_type_raises(tmp_path: Path):
	settings = {'cloud_sync': {'type': 'ftp', 'target': 'foo'}}
	cache = tmp_path / 'cache.json'
	cache.write_text('{}')
	with pytest.raises(ValueError):
		data_sharing.cloud_push(cache, settings)
