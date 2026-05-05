import json
from argparse import Namespace
from unittest.mock import patch

from system_update import AppInfo, UpdateStatus
from system_update import dependency_graph
from system_update.app import SystemUpdateApp


def test_dependency_graph_exports_dot_with_edges(tmp_path):
	apps = [
		AppInfo(
			name='parent',
			source='npm',
			version='1.0.0',
			latest_version='1.1.0',
			update_status=UpdateStatus.UPDATE_AVAILABLE,
		),
		AppInfo(name='child', source='npm', version='2.0.0'),
	]
	npm_tree = {
		'dependencies': {
			'parent': {
				'version': '1.0.0',
				'dependencies': {'child': {'version': '2.0.0'}},
			},
			'child': {'version': '2.0.0'},
		}
	}

	with patch('system_update.dependency_graph.run_command', return_value=json.dumps(npm_tree)):
		graph = dependency_graph.build_graph(apps)

	out = tmp_path / 'deps.dot'
	dependency_graph.export_dot(graph, str(out))
	text = out.read_text(encoding='utf-8')
	assert '"npm:parent" -> "npm:child";' in text
	assert 'parent\\nnpm\\n1.0.0' in text


def test_dependency_graph_detects_version_conflicts():
	graph = dependency_graph.build_graph(
		[
			AppInfo(name='requests', source='pip', version='2.31.0'),
			AppInfo(name='requests', source='npm', version='2.32.0'),
		],
		include_dependencies=False,
	)

	conflicts = dependency_graph.detect_conflicts(graph)
	assert len(conflicts) == 1
	assert conflicts[0].name == 'requests'
	assert sorted(conflicts[0].versions) == ['2.31.0', '2.32.0']


def test_dependency_graph_minimal_update_set_skips_dependency_candidate():
	apps = [
		AppInfo(
			name='parent',
			source='npm',
			version='1.0.0',
			latest_version='1.1.0',
			update_status=UpdateStatus.UPDATE_AVAILABLE,
		),
		AppInfo(
			name='child',
			source='npm',
			version='2.0.0',
			latest_version='2.1.0',
			update_status=UpdateStatus.UPDATE_AVAILABLE,
		),
		AppInfo(
			name='vulnerable-child',
			source='npm',
			version='3.0.0',
			latest_version='3.1.0',
			update_status=UpdateStatus.VULNERABLE,
			security_findings=[{'cve': 'CVE-1'}],
		),
	]
	graph = dependency_graph.build_graph(apps, include_dependencies=False)
	graph.add_edge('npm:parent', 'npm:child')
	graph.add_edge('npm:parent', 'npm:vulnerable-child')

	selected = dependency_graph.minimal_update_set(graph)
	assert [node.name for node in selected] == ['parent', 'vulnerable-child']


def test_dependency_graph_cli_action_exports_from_cache(tmp_path, capsys):
	app = SystemUpdateApp()
	app.history_db.close()
	apps = [AppInfo(name='requests', source='pip', version='2.31.0')]
	out = tmp_path / 'deps.dot'
	args = Namespace(
		source=None,
		exclude=None,
		update_source=None,
		update_all=False,
		dry_run=False,
		yes=True,
		no_cache=False,
		clear_cache=False,
		profile=None,
		profile_export=None,
		profile_import=None,
		save_config=False,
		format=None,
		theme=None,
		icons=False,
		interactive=False,
		show_all=True,
		notify=False,
		export=None,
		output=None,
		html_template=None,
		html_logo=None,
		html_title=None,
		html_company=None,
		package=None,
		version=None,
		history=False,
		history_package=None,
		history_trends=False,
		history_stale=0,
		report=None,
		report_output=None,
		dependency_graph='dot',
		graph_output=str(out),
		import_files=[],
		merge_with_cache=False,
		cloud_sync=None,
		schedule=None,
		rollback=None,
		snapshot=None,
	)

	with (
		patch.object(app.cache_mgr, 'load', return_value=apps),
		patch.object(app.ui, 'display_banner'),
		patch('system_update.dependency_graph.run_command', return_value=''),
	):
		app.run(args)

	output = capsys.readouterr().out
	assert 'Dependency graph exported' in output
	assert out.exists()
