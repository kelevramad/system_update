import os
import sys
import subprocess
import tempfile
import functools

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
