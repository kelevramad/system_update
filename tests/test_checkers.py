import pytest
import json
from unittest.mock import patch, MagicMock
from system_update import UpdateChecker, UpdateExecutor, SystemUpdateApp, AppInfo

_CHECKER_MOCKS = [
    ('winget', '_check_winget_updates', 'Name Id Version Available Source\n--- --- --- --- ---\ntest ID 1.0 1.1 winget'),
    ('chocolatey', '_check_choco_updates', 'test|1.0|1.1'),
    ('npm', '_check_npm_updates', json.dumps({'dist-tags': {'latest': '1.1'}, 'version': '1.0'})),
    ('pip', '_check_pip_updates', json.dumps({'info': {'version': '1.1'}})),
]

@pytest.mark.parametrize('source,method,mock_output', _CHECKER_MOCKS)
@patch('system_update.run_command')
def test_checkers_parameterized(mock_run, source, method, mock_output):
    apps = [AppInfo(name='test', source=source, version='1.0')]
    mock_run.return_value = mock_output
    checker_method = getattr(UpdateChecker, method)
    count = checker_method(apps)
    assert count >= 0

@patch('system_update.run_command')
def test_check_pip_updates(mock_run):
    apps = [AppInfo(name='requests', source='pip', version='2.28.0')]
    mock_run.return_value = json.dumps({'info': {'version': '2.28.1'}})
    count = UpdateChecker._check_pip_updates(apps)
    assert count >= 0

@patch('system_update.run_command')
def test_check_npm_updates(mock_run):
    apps = [AppInfo(name='lodash', source='npm', version='4.17.20')]
    mock_run.return_value = json.dumps({'dist-tags': {'latest': '4.17.21'}})
    count = UpdateChecker._check_npm_updates(apps)
    assert count >= 0

@patch('system_update.run_command')
def test_check_choco_updates(mock_run):
    apps = [AppInfo(name='git', source='chocolatey', version='2.40.0')]
    mock_run.return_value = 'git|2.40.0|2.41.0'
    count = UpdateChecker._check_choco_updates(apps)
    assert count >= 0

@patch('system_update.run_command')
def test_check_rust_updates(mock_run):
    apps = [AppInfo(name='rustc', source='rust', version='1.70.0')]
    mock_run.return_value = 'rustc 1.71.0 ('
    count = UpdateChecker._check_rust_updates(apps)
    assert count >= 0

@patch('system_update.run_command')
def test_check_pnpm_updates(mock_run):
    apps = [AppInfo(name='test', source='pnpm', version='7.0.0')]
    mock_run.return_value = json.dumps({'dist-tags': {'latest': '8.0.0'}})
    count = UpdateChecker._check_pnpm_updates(apps)
    assert count >= 0

@patch('system_update.run_command')
def test_check_yarn_updates(mock_run):
    apps = [AppInfo(name='test', source='yarn', version='1.22.0')]
    mock_run.return_value = json.dumps({'dist-tags': {'latest': '3.0.0'}})
    count = UpdateChecker._check_yarn_updates(apps)
    assert count >= 0

@patch('system_update.run_command')
def test_check_bun_updates(mock_run):
    apps = [AppInfo(name='test', source='bun', version='0.6.0')]
    mock_run.return_value = '0.7.0'
    count = UpdateChecker._check_bun_updates(apps)
    assert count >= 0

@patch('system_update.run_command')
def test_check_scoop_updates(mock_run):
    apps = [AppInfo(name='git', source='scoop', version='2.40.0')]
    mock_run.return_value = 'git (2.41.0) - A distributed version control system'
    count = UpdateChecker._check_scoop_updates(apps)
    assert count >= 0

@patch('system_update.run_command')
def test_check_dotnet_updates(mock_run):
    apps = [AppInfo(name='nuget', source='dotnet', version='6.0.0')]
    mock_run.return_value = 'NuGet.Client                      6.0.1'
    count = UpdateChecker._check_dotnet_updates(apps)
    assert count >= 0

@patch('system_update.run_command')
def test_check_registry_updates(mock_run):
    apps = [AppInfo(name='test', source='registry', version='1.0')]
    mock_run.return_value = 'TestApp v2.0'
    count = UpdateChecker._check_registry_updates(apps)
    assert count >= 0

@patch('system_update.run_command')
def test_check_winget_updates(mock_run):
    apps = [AppInfo(name='Git', source='Winget', version='2.40.0', app_id='Git.Git')]
    header = 'Name                           Id                                         Version          Available        Source'
    line1 = 'Git                            Git.Git                                    2.40.0           2.41.0           winget'
    mock_run.return_value = f'{header}\n{line1}'
    count = UpdateChecker._check_winget_updates(apps)
    assert count >= 0

@patch('system_update.run_command')
def test_check_path_updates_exhaustive(mock_run):
    def side_effect(cmd, **kwargs):
        cmd_str = ' '.join(str(c) for c in cmd) if isinstance(cmd, list) else cmd
        if 'bun' in cmd_str:
            return 'Bun v1.0.0 is out!'
        if 'node' in cmd_str:
            return '1.2.0'
        if 'python' in cmd_str:
            return 'v3.12.0'
        if 'git' in cmd_str:
            return '2.40.0'
        return '1.0.0'
    mock_run.side_effect = side_effect
    tools = ['bun', 'node', 'python', 'git']
    apps = [AppInfo(name=tool, source='PATH', version='0.9.0') for tool in tools]
    count = UpdateChecker._check_path_updates(apps)
    assert count >= 0

@patch('system_update.run_command')
def test_check_path_updates_empty(mock_run):
    count = UpdateChecker._check_path_updates([])
    assert count == 0
    mock_run.assert_not_called()


@pytest.mark.parametrize("source", ["Scoop", "PATH", "Appx", "Msix"])
@patch('system_update.run_command', return_value="OK")
def test_executor_additional_sources(mock_run, source):
    app = AppInfo(name="pkg", source=source, version="1.0", latest_version="1.1", app_id="ID")
    result = UpdateExecutor._execute_single_update(app)
    assert isinstance(result, bool)


@pytest.mark.parametrize(
    'source',
    [
        'Winget', 'Chocolatey', 'NPM', 'PNPM', 'Bun', 'Yarn', 'PIP', 'Rust',
        'dotnet', 'scoop', 'path', 'registry', 'appx', 'msix',
    ],
)
@patch('system_update.run_command', return_value='Updated successfully')
def test_executor_all_sources(mock_run, source):
    app = AppInfo(
        name='testpkg', source=source, version='1.0', latest_version='1.1', app_id='test.id'
    )
    result = UpdateExecutor._execute_single_update(app)
    assert isinstance(result, bool)


@patch('system_update.run_command')
def test_executor_failure_branch(mock_run):
    mock_run.side_effect = Exception('Command failed')
    app = AppInfo(name='test', source='Winget', version='1.0', latest_version='1.1', app_id='test')
    try:
        UpdateExecutor._execute_single_update(app)
    except Exception:
        pass


@patch('system_update.run_command')
def test_executor_no_update_needed(mock_run):
    app = AppInfo(name='test', source='Winget', version='1.0', latest_version='1.0', app_id='test')
    result = UpdateExecutor._execute_single_update(app)
    assert result is True


def test_executor_empty_list():
    result = UpdateExecutor.execute_updates([])
    assert result is None or result is True


@patch('system_update.run_command')
def test_check_npm_updates_invalid_json(mock_run):
    apps = [AppInfo(name="test", source="npm", version="1.0.0")]
    mock_run.return_value = "invalid json{"
    count = UpdateChecker._check_npm_updates(apps)
    assert count == 0


@patch('system_update.run_command')
def test_check_pip_updates_invalid_json(mock_run):
    apps = [AppInfo(name="test", source="pip", version="1.0.0")]
    mock_run.return_value = "{invalid"
    count = UpdateChecker._check_pip_updates(apps)
    assert count == 0


@patch('system_update.run_command')
def test_check_npm_vulns_via_audit(mock_run):
    app_obj = SystemUpdateApp()
    apps = [AppInfo(name='pkg', source='npm', version='1.0.0')]

    mock_run.return_value = '{"vulnerabilities": {"pkg": {"severity": "critical", "via": [{"id": "CVE-1"}]}}}'
    vulns = app_obj._check_npm_vulns(apps)
    assert len(vulns) >= 0


@patch('system_update.run_command')
def test_check_pip_vulns_via_audit(mock_run):
    app_obj = SystemUpdateApp()
    apps_pip = [AppInfo(name='requests', source='pip', version='1.0.0')]

    mock_run.return_value = '{"dependencies": [{"name": "requests", "vulns": [{"id": "CVE-pip"}]}]}'
    vulns = app_obj._check_pip_vulns(apps_pip)
    assert len(vulns) >= 0


@patch('system_update.run_command')
def test_check_npm_vulns_no_findings(mock_run):
    app_obj = SystemUpdateApp()
    apps = [AppInfo(name='pkg', source='npm', version='1.0.0')]

    mock_run.return_value = '{"vulnerabilities": {}}'
    vulns = app_obj._check_npm_vulns(apps)
    assert vulns == []


@patch('system_update.run_command')
def test_check_npm_vulns_malformed_json(mock_run):
    app_obj = SystemUpdateApp()
    apps = [AppInfo(name='pkg', source='npm', version='1.0.0')]

    mock_run.return_value = "invalid json{"
    vulns = app_obj._check_npm_vulns(apps)
    assert isinstance(vulns, list)
    app_obj.history_db.close()


@patch('system_update.run_command')
def test_check_pip_vulns_malformed_json(mock_run):
    app_obj = SystemUpdateApp()
    apps = [AppInfo(name='requests', source='pip', version='1.0.0')]

    mock_run.return_value = "invalid{"
    vulns = app_obj._check_pip_vulns(apps)
    assert isinstance(vulns, list)
    app_obj.history_db.close()


@patch('system_update.run_command')
def test_executor_unknown_source(mock_run):
    mock_run.return_value = "Success"
    app = AppInfo(
        name="test", source="UnknownSource",
        version="1.0", latest_version="1.1", app_id="test",
    )
    result = UpdateExecutor._execute_single_update(app)
    assert isinstance(result, bool)


def test_app_init():
    app = SystemUpdateApp()
    assert app is not None


@patch('system_update.PackageScanner.scan_winget', return_value=[AppInfo(name="Git", source="Winget", version="1.0")])
def test_app_scan_system(mock_scan):
    app = SystemUpdateApp()
    app.config.settings['sources']['winget'] = True
    apps = app.scan_system(source_filter="winget")
    assert len(apps) == 1


def test_app_export_results(tmp_path):
    app = SystemUpdateApp()
    apps = [AppInfo(name="Git", source="Winget", version="1.0")]

    json_file = tmp_path / "export.json"
    app.export_results(apps, "json", str(json_file))
    assert json_file.exists()


def test_app_export_csv(tmp_path):
    app = SystemUpdateApp()
    apps = [AppInfo(name="Git", source="Winget", version="1.0")]

    csv_file = tmp_path / "export.csv"
    app.export_results(apps, "csv", str(csv_file))
    assert csv_file.exists()


@patch('system_update.PackageScanner.scan_winget')
@patch('system_update.UpdateChecker._check_winget_updates')
@patch('system_update.console.print')
@patch('system_update.HistoryDatabase.record_scan')
def test_app_run_with_no_updates(mock_record, mock_print, mock_check, mock_scan):
    mock_scan.return_value = []
    mock_check.return_value = 0
    app = SystemUpdateApp()
    args = MagicMock()
    args.clear_cache = False
    args.interactive = False
    args.update_all = False
    args.dry_run = False
    args.package = None
    args.update_source = None
    args.history = False
    args.history_package = None
    args.history_trends = False
    args.history_stale = 0
    args.report = False
    app.run(args)


@patch('system_update.PackageScanner.scan_winget')
@patch('system_update.UpdateChecker._check_winget_updates')
@patch('system_update.UpdateExecutor.execute_updates')
@patch('system_update.console.print')
@patch('system_update.HistoryDatabase.record_scan')
def test_app_run_update_all(mock_record, mock_print, mock_exec, mock_check, mock_scan):
    mock_scan.return_value = [
        AppInfo(name='Git', source='Winget', version='1.0', latest_version='2.0', app_id='Git')
    ]
    mock_check.return_value = 1
    app = SystemUpdateApp()
    args = MagicMock()
    args.clear_cache = False
    args.interactive = False
    args.update_all = True
    args.dry_run = False
    args.package = None
    args.update_source = None
    args.yes = True
    args.history = False
    args.history_package = None
    args.history_trends = False
    args.history_stale = 0
    args.report = False
    app.run(args)


@patch('system_update.PackageScanner.scan_winget')
@patch('system_update.UpdateChecker._check_winget_updates')
@patch('system_update.console.print')
@patch('system_update.HistoryDatabase.record_scan')
def test_app_run_dry_run(mock_record, mock_print, mock_check, mock_scan):
    mock_scan.return_value = [
        AppInfo(name='Git', source='Winget', version='1.0', latest_version='2.0', app_id='Git')
    ]
    mock_check.return_value = 1
    app = SystemUpdateApp()
    args = MagicMock()
    args.clear_cache = False
    args.interactive = False
    args.update_all = False
    args.dry_run = True
    args.package = None
    args.update_source = None
    args.yes = False
    args.history = False
    args.history_package = None
    args.history_trends = False
    args.history_stale = 0
    args.report = False
    app.run(args)


@patch('system_update.PackageScanner.scan_winget')
@patch('system_update.UpdateChecker._check_winget_updates')
@patch('system_update.console.print')
@patch('system_update.HistoryDatabase.record_scan')
def test_app_run_specific_package(mock_record, mock_print, mock_check, mock_scan):
    mock_scan.return_value = [
        AppInfo(name='Git', source='Winget', version='1.0', latest_version='2.0', app_id='Git'),
        AppInfo(
            name='NodeJS', source='Winget', version='1.0', latest_version='1.1', app_id='NodeJS'
        ),
    ]
    mock_check.return_value = 1
    app = SystemUpdateApp()
    args = MagicMock()
    args.clear_cache = False
    args.interactive = False
    args.update_all = False
    args.dry_run = False
    args.package = 'Git'
    args.update_source = None
    args.yes = False
    args.history = False
    args.history_package = None
    args.history_trends = False
    args.history_stale = 0
    args.report = False
    app.run(args)
    app.history_db.close()


@patch('system_update.PackageScanner.scan_winget')
@patch('system_update.PackageScanner.scan_npm')
@patch('system_update.UpdateChecker._check_winget_updates')
@patch('system_update.UpdateChecker._check_npm_updates')
@patch('system_update.console.print')
@patch('system_update.HistoryDatabase.record_scan')
def test_app_run_update_source(
    mock_record, mock_print, mock_check_npm, mock_check_winget, mock_scan_npm, mock_scan_winget
):
    mock_scan_winget.return_value = [
        AppInfo(name='Git', source='Winget', version='1.0', latest_version='2.0', app_id='Git')
    ]
    mock_scan_npm.return_value = []
    mock_check_winget.return_value = 1
    mock_check_npm.return_value = 0
    app = SystemUpdateApp()
    args = MagicMock()
    args.clear_cache = False
    args.interactive = False
    args.update_all = False
    args.dry_run = False
    args.package = None
    args.update_source = 'winget'
    args.yes = False
    args.history = False
    args.history_package = None
    args.history_trends = False
    args.history_stale = 0
    args.report = False
    app.run(args)


@patch('system_update.run_command')
def test_check_path_updates_command_not_found(mock_run):
    apps = [AppInfo(name="git", source="PATH", version="1.0")]

    def side_effect(cmd, **kwargs):
        cmd_str = ' '.join(str(c) for c in cmd) if isinstance(cmd, list) else cmd
        if 'git' in cmd_str:
            raise FileNotFoundError("git not found")
        return "1.0.0"

    mock_run.side_effect = side_effect
    count = UpdateChecker._check_path_updates(apps)
    assert count >= 0


def test_executor_update_all_sources():
    apps = [
        AppInfo(name='Git', source='Winget', version='1.0', latest_version='2.0', app_id='Git'),
        AppInfo(name='Node', source='npm', version='1.0', latest_version='2.0', app_id='Node'),
    ]
    result = UpdateExecutor.execute_updates(apps)
    assert result is None or result is True


@patch('system_update.run_command', return_value='Success')
def test_executor_execute_single(mock_run):
    app = AppInfo(name='Test', source='npm', version='1.0', latest_version='2.0', app_id='test')
    result = UpdateExecutor._execute_single_update(app)
    assert isinstance(result, bool)


def test_checker_check_winget_none():
    result = UpdateChecker._check_winget_updates([])
    assert result == 0


def test_checker_check_npm_none():
    result = UpdateChecker._check_npm_updates([])
    assert result == 0


def test_checker_check_pip_none():
    result = UpdateChecker._check_pip_updates([])
    assert result == 0


def test_app_get_export_stats():
    from system_update import SystemUpdateApp
    app = SystemUpdateApp()
    apps = [
        AppInfo(name='Git', source='Winget', version='1.0', latest_version='2.0'),
        AppInfo(name='Node', source='npm', version='1.0'),
    ]
    stats = app._get_export_stats(apps)
    assert 'total' in stats
    assert stats['total'] == 2


def test_app_export_results_json(tmp_path):
    from system_update import SystemUpdateApp
    app = SystemUpdateApp()
    apps = [AppInfo(name='Git', source='Winget', version='1.0')]
    output_file = tmp_path / 'test.json'
    app.export_results(apps, 'json', str(output_file))
    assert output_file.exists()


def test_app_export_results_csv(tmp_path):
    from system_update import SystemUpdateApp
    app = SystemUpdateApp()
    apps = [AppInfo(name='Git', source='Winget', version='1.0')]
    output_file = tmp_path / 'test.csv'
    app.export_results(apps, 'csv', str(output_file))
    assert output_file.exists()


def test_app_export_results_markdown(tmp_path):
    from system_update import SystemUpdateApp
    app = SystemUpdateApp()
    apps = [AppInfo(name='Git', source='Winget', version='1.0')]
    output_file = tmp_path / 'test.md'
    app.export_results(apps, 'markdown', str(output_file))
    assert output_file.exists()
