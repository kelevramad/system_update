import os
import sys
import subprocess
import tempfile
import functools
from pathlib import Path

from system_update import AppInfo, UpdateStatus, export

PYTHON = sys.executable


@functools.lru_cache(maxsize=128)
def run_cli_cached(args_tuple, timeout=60):
	args = list(args_tuple)
	result = subprocess.run(
		[PYTHON, '-m', 'system_update'] + args,
		capture_output=True,
		text=True,
		timeout=timeout,
		encoding='utf-8',
		errors='ignore',
	)
	return {'code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}


def run_cli(args, timeout=60):
	return run_cli_cached(tuple(args), timeout)


def test_export_json():
	with tempfile.TemporaryDirectory() as tmpdir:
		output_file = os.path.join(tmpdir, 'export.json')
		res = run_cli(
			['--export', 'json', '--output', output_file, '--source', 'chocolatey'], timeout=120
		)
		assert os.path.exists(output_file) or res['code'] == 0


def test_export_csv():
	with tempfile.TemporaryDirectory() as tmpdir:
		output_file = os.path.join(tmpdir, 'export.csv')
		res = run_cli(
			['--export', 'csv', '--output', output_file, '--source', 'chocolatey'], timeout=120
		)
		assert os.path.exists(output_file) or res['code'] == 0


def test_export_html():
	with tempfile.TemporaryDirectory() as tmpdir:
		output_file = os.path.join(tmpdir, 'export.html')
		res = run_cli(
			['--export', 'html', '--output', output_file, '--source', 'chocolatey'], timeout=120
		)
		assert os.path.exists(output_file) or res['code'] == 0


def test_export_xml():
	with tempfile.TemporaryDirectory() as tmpdir:
		output_file = os.path.join(tmpdir, 'export.xml')
		res = run_cli(
			['--export', 'xml', '--output', output_file, '--source', 'chocolatey'], timeout=120
		)
		assert os.path.exists(output_file) or res['code'] == 0


def test_export_markdown():
	with tempfile.TemporaryDirectory() as tmpdir:
		output_file = os.path.join(tmpdir, 'export.md')
		res = run_cli(
			['--export', 'md', '--output', output_file, '--source', 'chocolatey'], timeout=120
		)
		assert os.path.exists(output_file) or res['code'] == 0


def test_export_diff():
	with tempfile.TemporaryDirectory() as tmpdir:
		output_file = os.path.join(tmpdir, 'export.diff')
		res = run_cli(
			['--export', 'diff', '--output', output_file, '--source', 'chocolatey'], timeout=120
		)
		assert os.path.exists(output_file) or res['code'] == 0


def test_exports_render_sources_lowercase(tmp_path):
	apps = [
		AppInfo(
			name='Demo',
			source='PIP',
			version='1.0.0',
			latest_version='1.1.0',
			update_status=UpdateStatus.UPDATE_AVAILABLE,
			security_findings=[{'cve': 'CVE-1', 'severity': 'LOW'}],
		)
	]
	for fmt, suffix in [
		('csv', 'csv'),
		('xml', 'xml'),
		('markdown', 'md'),
		('diff', 'txt'),
		('html', 'html'),
	]:
		out = tmp_path / f'export.{suffix}'
		export.export(apps, fmt, str(out))
		content = out.read_text(encoding='utf-8')
		assert 'pip' in content
		assert 'PIP' not in content


def test_xml_export_module_is_generation_only():
	"""Hardening 1.5.1: no untrusted XML input is parsed by export.py.

	defusedxml.ElementTree is allowed because it is a hardened, safe parser.
	"""
	source = Path(export.__file__).read_text(encoding='utf-8')
	for forbidden in (
		'xml.etree',
		'xml.dom',
		'xml.sax',
		'minidom',
		'fromstring',
	):
		assert forbidden not in source
	# ElementTree is allowed only when imported from defusedxml
	assert 'defusedxml import ElementTree' in source
	assert 'XML is generation-only' in source
