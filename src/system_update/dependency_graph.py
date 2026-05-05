"""Dependency graph helpers — enhancement section 6.3.

Implements:

* 6.3.1 — Graphviz DOT export
* 6.3.2 — version conflict detection
* 6.3.3 — minimal update set suggestions
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Set

from system_update.models import AppInfo, UpdateStatus
from system_update.utils import run_command


@dataclass
class DependencyNode:
	"""A package node in the dependency graph."""

	key: str
	name: str
	source: str
	version: str = ''
	latest_version: str = ''
	status: str = ''
	vulnerable: bool = False
	external: bool = False


@dataclass(frozen=True)
class DependencyEdge:
	"""A directed dependency edge: ``parent`` depends on ``dependency``."""

	parent: str
	dependency: str
	requirement: str = ''


@dataclass
class DependencyGraph:
	"""In-memory graph with deterministic node and edge ordering."""

	nodes: Dict[str, DependencyNode] = field(default_factory=dict)
	edges: List[DependencyEdge] = field(default_factory=list)

	def add_node(self, node: DependencyNode) -> None:
		existing = self.nodes.get(node.key)
		if existing is None or (existing.external and not node.external):
			self.nodes[node.key] = node

	def add_edge(self, parent: str, dependency: str, requirement: str = '') -> None:
		edge = DependencyEdge(parent, dependency, requirement)
		if edge not in self.edges:
			self.edges.append(edge)


@dataclass
class VersionConflict:
	"""Same package name observed with multiple versions."""

	name: str
	versions: Dict[str, List[DependencyNode]]


def _norm_source(source: str) -> str:
	return (source or 'unknown').strip().lower() or 'unknown'


def _norm_name(name: str) -> str:
	return (name or '').strip().lower()


def _key(source: str, name: str) -> str:
	return f'{_norm_source(source)}:{_norm_name(name)}'


def _node_from_app(app: AppInfo) -> DependencyNode:
	return DependencyNode(
		key=_key(app.source, app.name),
		name=app.name,
		source=_norm_source(app.source),
		version=app.version or '',
		latest_version=app.latest_version or '',
		status=getattr(app.update_status, 'value', str(app.update_status)),
		vulnerable=app.is_vulnerable,
		external=False,
	)


def _external_node(source: str, name: str, version: str = '') -> DependencyNode:
	return DependencyNode(
		key=_key(source, name),
		name=name,
		source=_norm_source(source),
		version=version or '',
		external=True,
	)


def _pip_interpreter(app: AppInfo) -> str:
	hint = (app.install_path or '').strip()
	if hint and (hint.lower().endswith('python.exe') or hint.lower().endswith('python')):
		return hint
	return sys.executable


def _parse_npm_tree(graph: DependencyGraph, source: str, data: object, known: Set[str]) -> None:
	"""Parse ``npm/pnpm list --json``-style dependency trees."""
	if isinstance(data, list):
		for item in data:
			_parse_npm_tree(graph, source, item, known)
		return
	if not isinstance(data, dict):
		return
	dependencies = data.get('dependencies') or {}
	if not isinstance(dependencies, dict):
		return
	for parent_name, meta in dependencies.items():
		if not isinstance(meta, dict):
			continue
		parent_key = _key(source, parent_name)
		graph.add_node(_external_node(source, parent_name, str(meta.get('version') or '')))
		nested = meta.get('dependencies') or {}
		if not isinstance(nested, dict):
			continue
		for dep_name, dep_meta in nested.items():
			dep_version = ''
			if isinstance(dep_meta, dict):
				dep_version = str(dep_meta.get('version') or '')
			dep_key = _key(source, dep_name)
			if dep_key not in known:
				graph.add_node(_external_node(source, dep_name, dep_version))
			graph.add_edge(parent_key, dep_key)


def _load_node_dependencies(graph: DependencyGraph, apps: List[AppInfo]) -> None:
	import json

	known = set(graph.nodes)
	sources = {_norm_source(a.source) for a in apps}

	if 'npm' in sources:
		output = run_command(['npm', 'list', '-g', '--depth=1', '--json', '--silent'], allow_failure=True)
		if output:
			try:
				_parse_npm_tree(graph, 'npm', json.loads(output), known)
			except (json.JSONDecodeError, TypeError, ValueError):
				pass

	if 'pnpm' in sources:
		output = run_command(['pnpm', 'list', '-g', '--depth=1', '--json'], allow_failure=True)
		if output:
			try:
				_parse_npm_tree(graph, 'pnpm', json.loads(output), known)
			except (json.JSONDecodeError, TypeError, ValueError):
				pass

	pip_apps = [a for a in apps if _norm_source(a.source) == 'pip']
	for interpreter, group in _group_pip_by_interpreter(pip_apps).items():
		names = [a.name for a in group if a.name]
		if not names:
			continue
		output = run_command([interpreter, '-m', 'pip', 'show', *names], allow_failure=True, scrub_venv=True)
		if output:
			_parse_pip_show(graph, group, output, known)


def _group_pip_by_interpreter(apps: Iterable[AppInfo]) -> Dict[str, List[AppInfo]]:
	grouped: Dict[str, List[AppInfo]] = {}
	for app in apps:
		grouped.setdefault(_pip_interpreter(app), []).append(app)
	return grouped


def _parse_pip_show(
	graph: DependencyGraph,
	apps: List[AppInfo],
	output: str,
	known: Set[str],
) -> None:
	app_by_name = {_norm_name(a.name): a for a in apps}
	for block in re.split(r'\n---+\n', output.strip()):
		fields: Dict[str, str] = {}
		for line in block.splitlines():
			if ':' not in line:
				continue
			k, v = line.split(':', 1)
			fields[k.strip().lower()] = v.strip()
		parent_name = fields.get('name', '')
		if not parent_name or _norm_name(parent_name) not in app_by_name:
			continue
		parent_key = _key('pip', parent_name)
		requires = fields.get('requires', '')
		for dep_name in [p.strip() for p in requires.split(',') if p.strip()]:
			dep_key = _key('pip', dep_name)
			if dep_key not in known:
				graph.add_node(_external_node('pip', dep_name))
			graph.add_edge(parent_key, dep_key)


def build_graph(apps: List[AppInfo], include_dependencies: bool = True) -> DependencyGraph:
	"""Build a best-effort dependency graph for scanned packages."""
	graph = DependencyGraph()
	for app in apps:
		graph.add_node(_node_from_app(app))
	if include_dependencies:
		_load_node_dependencies(graph, apps)
	graph.edges.sort(key=lambda e: (e.parent, e.dependency, e.requirement))
	return graph


def detect_conflicts(graph: DependencyGraph) -> List[VersionConflict]:
	"""Return packages observed with more than one installed version."""
	grouped: Dict[str, Dict[str, List[DependencyNode]]] = {}
	for node in graph.nodes.values():
		if not node.version:
			continue
		grouped.setdefault(_norm_name(node.name), {}).setdefault(node.version, []).append(node)
	conflicts = [
		VersionConflict(name=name, versions=versions)
		for name, versions in grouped.items()
		if len(versions) > 1
	]
	return sorted(conflicts, key=lambda c: c.name)


def minimal_update_set(graph: DependencyGraph) -> List[DependencyNode]:
	"""Suggest the smallest direct update set from graph relationships.

	Vulnerable packages are always kept. Non-vulnerable update candidates that
	are dependencies of another selected update candidate are omitted because
	updating the parent usually refreshes that dependency relationship.
	"""
	candidates = {
		key: node
		for key, node in graph.nodes.items()
		if not node.external
		and (
			node.vulnerable
			or node.latest_version
			or node.status in {
				UpdateStatus.UPDATE_AVAILABLE.value,
				UpdateStatus.SECURITY_UPDATE_AVAILABLE.value,
				UpdateStatus.VULNERABLE.value,
			}
		)
	}
	dep_keys = {
		edge.dependency
		for edge in graph.edges
		if edge.parent in candidates and edge.dependency in candidates
	}
	selected = [
		node
		for key, node in candidates.items()
		if node.vulnerable or key not in dep_keys
	]
	return sorted(selected, key=lambda n: (n.source, n.name.lower()))


def export_dot(graph: DependencyGraph, output_file: str) -> str:
	"""Write a Graphviz DOT dependency graph and return the path."""
	path = Path(output_file)
	lines = [
		'digraph system_update_dependencies {',
		'  graph [rankdir=LR];',
		'  node [shape=box, style="rounded,filled", fontname="Segoe UI"];',
	]
	for key, node in sorted(graph.nodes.items()):
		label_parts = [node.name, node.source]
		if node.version:
			label_parts.append(node.version)
		label = '\\n'.join(_dot_escape(part) for part in label_parts)
		fill = '#ffd6d6' if node.vulnerable else '#fff3bf' if node.latest_version else '#e8f5e9'
		if node.external:
			fill = '#eeeeee'
		lines.append(f'  "{_dot_escape(key)}" [label="{label}", fillcolor="{fill}"];')
	for edge in graph.edges:
		label = f' [label="{_dot_escape(edge.requirement)}"]' if edge.requirement else ''
		lines.append(
			f'  "{_dot_escape(edge.parent)}" -> "{_dot_escape(edge.dependency)}"{label};'
		)
	lines.append('}')
	path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
	return str(path)


def _dot_escape(value: str) -> str:
	return str(value).replace('\\', '\\\\').replace('"', r'\"').replace('\n', r'\n')


__all__ = [
	'DependencyEdge',
	'DependencyGraph',
	'DependencyNode',
	'VersionConflict',
	'build_graph',
	'detect_conflicts',
	'export_dot',
	'minimal_update_set',
]
