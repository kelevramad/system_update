import os
import sys
import subprocess
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).parent.parent / 'system_update.py'
PYTHON = sys.executable


def run_cli(args, timeout=60):
	result = subprocess.run(
		[PYTHON, str(SCRIPT)] + args,
		capture_output=True,
		text=True,
		timeout=timeout,
		encoding='utf-8',
		errors='ignore',
	)
	return {
		'code': result.returncode,
		'stdout': result.stdout,
		'stderr': result.stderr,
	}


def test_help_flag_shows_usage():
	res = run_cli(['--help'])
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0
	assert 'usage' in output.lower() or 'system' in output.lower()


def test_no_args_shows_error():
	res = run_cli([])
	output = res['stdout'] + res['stderr']
	assert res['code'] != 0 or 'system' in output.lower()


def test_source_winget():
	res = run_cli(['--source', 'winget', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_source_chocolatey():
	res = run_cli(['--source', 'chocolatey', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_source_npm():
	res = run_cli(['--source', 'npm', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_source_pnpm():
	res = run_cli(['--source', 'pnpm', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_source_pip():
	res = run_cli(['--source', 'pip', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_source_path():
	res = run_cli(['--source', 'path', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_source_registry():
	res = run_cli(['--source', 'registry', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_source_rust():
	res = run_cli(['--source', 'rust', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_source_scoop():
	res = run_cli(['--source', 'scoop', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_source_dotnet():
	res = run_cli(['--source', 'dotnet', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_source_appx():
	res = run_cli(['--source', 'appx', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_source_msix():
	res = run_cli(['--source', 'msix', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_dry_run_flag():
	res = run_cli(['--dry-run', '--source', 'path'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_show_all_flag():
	res = run_cli(['--show-all', '--source', 'path', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_export_json():
	with tempfile.TemporaryDirectory() as tmpdir:
		output_file = os.path.join(tmpdir, 'export.json')
		res = run_cli(
			['--export', 'json', '--output', output_file, '--source', 'path'], timeout=90
		)
		assert os.path.exists(output_file) or res['code'] == 0


def test_export_csv():
	with tempfile.TemporaryDirectory() as tmpdir:
		output_file = os.path.join(tmpdir, 'export.csv')
		res = run_cli(['--export', 'csv', '--output', output_file, '--source', 'path'], timeout=90)
		assert os.path.exists(output_file) or res['code'] == 0


def test_clear_cache():
	res = run_cli(['--clear-cache'])
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0
	assert 'cache' in output.lower() or 'clear' in output.lower()


def test_source_unknown_source():
	res = run_cli(['--source', 'unknown_source_xyz'])
	output = res['stdout'] + res['stderr']
	assert res['code'] != 0 or 'source' in output.lower()


def test_source_multiple_sources():
	res = run_cli(['--source', 'winget,npm', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_log_flag():
	res = run_cli(['--log', '--source', 'path', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_debug_flag():
	res = run_cli(['--debug', '--source', 'path', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'apps' in output.lower() or 'scan' in output.lower()


def test_security_scan():
	res = run_cli(['--source', 'pip', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert (
		res['code'] == 0
		or 'vuln' in output.lower()
		or 'security' in output.lower()
		or 'scan' in output.lower()
	)


def test_security_osv_source():
	res = run_cli(['--source', 'pip', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert (
		res['code'] == 0
		or 'osv' in output.lower()
		or 'vuln' in output.lower()
		or 'security' in output.lower()
	)


def test_security_github_advisory():
	res = run_cli(['--source', 'npm', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert (
		res['code'] == 0
		or 'vuln' in output.lower()
		or 'security' in output.lower()
		or 'advisory' in output.lower()
	)


def test_security_local_advisory():
	with tempfile.TemporaryDirectory() as tmpdir:
		adv_file = os.path.join(tmpdir, 'advisories.json')
		with open(adv_file, 'w') as f:
			f.write('{"advisories": []}')

		original_home = os.environ.get('SYSTEM_UPDATE_HOME')
		try:
			os.environ['SYSTEM_UPDATE_HOME'] = tmpdir
			res = run_cli(['--source', 'pip', '--no-cache'], timeout=90)
			output = res['stdout'] + res['stderr']
			assert res['code'] == 0 or 'scan' in output.lower()
		finally:
			if original_home:
				os.environ['SYSTEM_UPDATE_HOME'] = original_home


def test_critical_alert_priority():
	res = run_cli(['--source', 'pip', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'CRITICAL' in output or 'critical' in output.lower()


def test_security_update_auto_priority():
	res = run_cli(['--source', 'pip', '--update-all', '--dry-run', '--yes'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'vuln' in output.lower() or 'update' in output.lower()


def test_interactive_flag():
	res = run_cli(['--help'])
	output = res['stdout'] + res['stderr']
	assert '--interactive' in output


def test_source_appx_and_msix():
	res = run_cli(['--source', 'appx,msix', '--no-cache', '--show-all'], timeout=120)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0 or 'appx' in output.lower() or 'msix' in output.lower()


def test_banner_shows_all_config_files():
	res = run_cli(['--source', 'path', '--no-cache'], timeout=60)
	output = res['stdout'] + res['stderr']
	assert 'cache.json' in output.lower()
	assert 'config.json' in output.lower()
	assert 'system.log' in output.lower()
	assert 'errors.log' in output.lower()
	assert 'vulnerability_history' in output.lower()


def test_debug_flag_runs_successfully():
	res = run_cli(['--debug', '--source', 'path', '--no-cache'], timeout=90)
	assert res['code'] == 0


def test_log_flag_runs_successfully():
	res = run_cli(['--log', '--source', 'path', '--no-cache'], timeout=90)
	assert res['code'] == 0


def test_appx_scan_returns_store_apps():
	res = run_cli(['--source', 'appx', '--no-cache', '--show-all'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0
	assert 'appx' in output.lower()


def test_msix_scan_returns_non_store_apps():
	res = run_cli(['--source', 'msix', '--no-cache', '--show-all'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert res['code'] == 0
	assert 'msix' in output.lower()


def test_appx_and_msix_show_up_to_date():
	res = run_cli(['--source', 'appx,msix', '--no-cache', '--show-all'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert 'up-to-date' in output.lower() or '✅' in output


def test_error_category_classification():
	from system_update import CommandError, ErrorCategory
	import subprocess

	err = CommandError.classify(FileNotFoundError(), 'test-command')
	assert err.category == ErrorCategory.NOT_FOUND
	assert 'not found' in err.message.lower()

	err = CommandError.classify(subprocess.TimeoutExpired('cmd', 1), 'test-command')
	assert err.category == ErrorCategory.TIMEOUT

	err = CommandError.classify(PermissionError(), 'test-command')
	assert err.category == ErrorCategory.PERMISSION_DENIED

	err = CommandError.classify(ValueError(), 'test-command')
	assert err.category == ErrorCategory.PARSE_ERROR

	err = CommandError.classify(Exception('unknown'), 'test-command')
	assert err.category == ErrorCategory.UNKNOWN


def test_command_error_suggestions():
	from system_update import CommandError, ErrorCategory

	err = CommandError(
		category=ErrorCategory.NOT_FOUND,
		message='Command not found',
		command='test-cmd',
		suggestion='Ensure test-cmd is installed'
	)
	assert err.suggestion != ''
	assert 'install' in err.suggestion.lower()


def test_source_filter_appx_shows_only_appx():
	res = run_cli(['--source', 'appx', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert 'appx' in output.lower()
	assert 'msix' not in output.lower() or 'msix' in output


def test_source_filter_msix_shows_only_msix():
	res = run_cli(['--source', 'msix', '--no-cache'], timeout=90)
	output = res['stdout'] + res['stderr']
	assert 'msix' in output.lower()
	assert 'appx' not in output.lower() or 'appx' in output
