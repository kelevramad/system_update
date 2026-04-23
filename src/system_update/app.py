"""Top-level orchestrator — scan → check → security → display → export → update.

:class:`SystemUpdateApp` composes every subsystem (config, cache, history,
scanners, update-checkers, executors, security, UI) and drives the full
workflow exactly like the legacy flat ``system_update.py`` did, so this
module is the one the typer CLI targets.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.request
from argparse import Namespace
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set

from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeElapsedColumn
from rich.prompt import Confirm

from system_update.cache import CacheManager
from system_update.checkers import UpdateChecker
from system_update.config import SystemConfig, setup_logging
from system_update.executors import UpdateExecutor
from system_update.history import HistoryDatabase, VulnerabilityHistory
from system_update.models import AppInfo, UpdateStatus
from system_update.notifications import NotificationManager
from system_update.scanners import PackageScanner
from system_update.security import SecurityChecker
from system_update.ui import DisplayFormatter, UISystem
from system_update.utils import console, source_badge

logger = logging.getLogger(__name__)


_SOURCE_ALIASES = {'choco': 'chocolatey'}

_SCAN_ORDER = (
	'winget', 'chocolatey', 'npm', 'pnpm', 'bun', 'yarn', 'pip',
	'path', 'registry', 'rust', 'scoop', 'dotnet', 'appx', 'msix',
)


def _build_scanner_map() -> Dict[str, Callable[[], List[AppInfo]]]:
	return {
		'winget': PackageScanner.scan_winget,
		'chocolatey': PackageScanner.scan_chocolatey,
		'npm': PackageScanner.scan_npm,
		'pnpm': PackageScanner.scan_pnpm,
		'bun': PackageScanner.scan_bun,
		'yarn': PackageScanner.scan_yarn,
		'pip': PackageScanner.scan_pip,
		'path': PackageScanner.scan_path,
		'registry': PackageScanner.scan_registry,
		'rust': PackageScanner.scan_rust,
		'scoop': PackageScanner.scan_scoop,
		'dotnet': PackageScanner.scan_dotnet,
		'appx': PackageScanner.scan_appx,
		'msix': PackageScanner.scan_msix,
	}


def _parse_source_filter(raw: Optional[str]) -> Set[str]:
	"""Turn a raw ``--source a,b,choco`` string into a set of canonical source names."""
	if not raw:
		return set()
	return {
		_SOURCE_ALIASES.get(item.strip().lower(), item.strip().lower())
		for item in raw.split(',')
		if item.strip()
	}


def _pypi_fallback_latest(apps: List[AppInfo]) -> None:
	"""Fill in ``latest_version`` for vulnerable PIP packages that UpdateChecker missed."""
	for app in apps:
		if not (app.is_vulnerable and not app.latest_version):
			continue
		try:
			url = f'https://pypi.org/pypi/{app.name}/json'
			req = urllib.request.Request(url, headers={'User-Agent': 'SystemUpdateCLI'})
			with urllib.request.urlopen(req, timeout=10) as response:
				data = json.loads(response.read().decode())
			if 'info' in data:
				app.latest_version = data['info'].get('version', '')
		except Exception:
			pass


def _count_updates(apps: List[AppInfo]) -> int:
	"""Total = regular updates + vulnerable packages that also have a newer version available."""
	regular = sum(1 for a in apps if a.update_status == UpdateStatus.UPDATE_AVAILABLE)
	security = sum(
		1 for a in apps if a.update_status == UpdateStatus.VULNERABLE and a.latest_version
	)
	return regular + security


class SystemUpdateApp:
	"""Main orchestrator — compose subsystems in :meth:`__init__`, drive them in :meth:`run`."""

	def __init__(self) -> None:
		self.config = SystemConfig()
		self.settings = self.config.settings
		self.ui = UISystem()
		self.scanner = PackageScanner()
		self.checker = UpdateChecker()
		self.executor = UpdateExecutor()
		self.security = SecurityChecker()
		self.cache_mgr = CacheManager(
			self.config.cache_file,
			self.settings.get('cache', {}).get('duration_hours', 2),
		)
		self.notifier = NotificationManager(self.config)
		self.history_db = HistoryDatabase(Path(self.config.config_dir) / 'history.db')
		self.vuln_history = VulnerabilityHistory(
			Path(self.config.config_dir) / 'vulnerability_history.json'
		)
		self._include_sources: Set[str] = set()

	def __del__(self) -> None:
		try:
			if getattr(self, 'history_db', None):
				self.history_db.close()
		except Exception:
			pass

	# ── scanning ────────────────────────────────────────────────────────────

	def scan_system(self, source_filter: Optional[str] = None) -> List[AppInfo]:
		"""Run every enabled source scanner in parallel with a per-source progress bar."""
		scanners = _build_scanner_map()

		include = set(self._include_sources)
		include.update(_parse_source_filter(source_filter))
		if include:
			scanners = {name: func for name, func in scanners.items() if name in include}

		enabled = self.settings.get('sources', {})
		selected = [
			(name, scanners[name])
			for name in _SCAN_ORDER
			if name in scanners and enabled.get(name, True)
		]

		max_workers = self.settings.get('performance', {}).get('max_workers', 4)
		all_apps: List[AppInfo] = []

		with Progress(
			TextColumn('{task.description}'),
			BarColumn(
				bar_width=16,
				complete_style='cyan',
				style='dim cyan',
				finished_style='cyan',
			),
			MofNCompleteColumn(),
			TimeElapsedColumn(),
			console=console,
		) as progress:
			tasks = {
				name: progress.add_task(f'🔎 {source_badge(name)}', total=1)
				for name, _ in selected
			}

			with ThreadPoolExecutor(max_workers=max_workers) as executor:
				future_to_source = {executor.submit(func): name for name, func in selected}
				for future in as_completed(future_to_source):
					name = future_to_source[future]
					try:
						apps = future.result()
						unique = list(
							{f'{a.source}|{a.name}|{a.version}'.lower(): a for a in apps}.values()
						)
						all_apps.extend(unique)
						icon = '✓' if len(unique) == 0 else '✅'
						progress.update(
							tasks[name],
							completed=1,
							description=f'{icon} {source_badge(name)} [{len(unique)}]',
						)
					except Exception as e:
						progress.update(
							tasks[name],
							completed=1,
							description=f'❌ {source_badge(name)} error',
						)
						console.print(f'  [red]✗[/red] {name}: {e}')

		return sorted(all_apps, key=lambda x: f'{x.source}{x.name}')

	# ── main workflow ──────────────────────────────────────────────────────

	def run(self, args: Namespace) -> None:
		"""Full flow: scan → check → security → cache → history → display → export → update."""
		setup_logging(
			self.config,
			debug=getattr(args, 'debug', False),
			enable_log=getattr(args, 'log', False),
		)

		# Apply UI overrides from CLI flags.
		if getattr(args, 'theme', None):
			self.settings.setdefault('ui', {})['theme'] = args.theme
		if getattr(args, 'format', None):
			self.settings.setdefault('ui', {})['display_format'] = args.format
		if getattr(args, 'icons', False):
			self.settings.setdefault('ui', {})['use_icons'] = True

		# Step 11 features (history/report/interactive) are routed here.
		if self._handle_meta_commands(args):
			return

		if getattr(args, 'clear_cache', False):
			self.cache_mgr.clear()
			console.print('[green]🗑️  Cache cleared successfully![/green]')
			return

		self.ui.display_banner(self.config)
		self._include_sources = set()

		# --update-source <s> is shorthand for --source <s> --update-all --yes.
		if getattr(args, 'update_source', None):
			args.source = args.update_source
			args.update_all = True
			args.yes = True

		if getattr(args, 'source', None):
			self._include_sources = _parse_source_filter(args.source)

		apps: Optional[List[AppInfo]] = None
		if not getattr(args, 'no_cache', False) and self.settings.get('cache', {}).get(
			'enabled', True
		):
			cached = self.cache_mgr.load()
			if cached:
				if self._include_sources:
					cached_sources = {s.lower() for s in self.cache_mgr.load_sources()}
					missing = self._include_sources - cached_sources
					if missing:
						console.print(
							f'[dim]💾 Cache missing source(s) {sorted(missing)} — '
							f'rescanning.[/dim]\n'
						)
					else:
						apps = [
							a for a in cached if a.source.lower() in self._include_sources
						]
						console.print(
							f'[dim]💾 Loaded {len(apps)} items from cache '
							f'(filter: {",".join(sorted(self._include_sources))})[/dim]\n'
						)
				else:
					apps = cached
					console.print(f'[dim]💾 Loaded {len(apps)} items from cache[/dim]\n')

		security_vulns: List[Dict] = []
		total_updates = 0

		if apps is None:
			start_time = time.time()

			# Phase 1 — scan.
			console.print('[bold cyan]🔎 Scanning sources...[/bold cyan]')
			apps = self.scan_system(getattr(args, 'source', None))
			console.print(f'\n📦 [bold]Discovered {len(apps)} unique apps.[/bold]')

			# Phase 2 — update checking.
			console.print('[bold cyan]🔄 Checking for updates...[/bold cyan]')
			self.checker.check_all_updates(apps)

			regular_updates = sum(
				1 for a in apps if a.update_status == UpdateStatus.UPDATE_AVAILABLE
			)
			security_updates = sum(
				1 for a in apps
				if a.update_status == UpdateStatus.VULNERABLE and a.latest_version
			)
			total_updates = regular_updates + security_updates

			if security_updates > 0:
				console.print(
					f'[bold magenta]📊 Detected {security_updates} '
					f'security updates (urgent).[/bold magenta]'
				)
			else:
				console.print(
					f'[bold magenta]📊 Detected {total_updates} update candidates.[/bold magenta]\n'
				)

			# Phase 3 — security vulnerability check.
			console.print('[bold magenta]🔒 Checking security vulnerabilities...[/bold magenta]')
			advisory_file = os.path.join(
				os.path.expanduser('~'), '.system_update', 'advisories.json'
			)
			security_vulns = self.security.check_all(apps, advisory_file)

			if security_vulns:
				console.print(
					f'[bold red]🔥 Found {len(security_vulns)} '
					f'security vulnerabilities.[/bold red]\n'
				)
			else:
				console.print(
					'[bold green]🛡️ No security vulnerabilities found.[/bold green]\n'
				)

			_pypi_fallback_latest(apps)

			# Persist findings + full scan to history stores.
			scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
			for app in apps:
				for finding in app.security_findings:
					self.vuln_history.record_vulnerability(app, finding, scan_id)

			scanned_sources = self._scanned_sources_label(args)
			scan_time = time.time() - start_time
			self.history_db.record_scan(apps, scan_id, scanned_sources, scan_time)

			self.ui.display_security_summary(self.ui.compute_security_stats(security_vulns))
			total_updates = _count_updates(apps)
			self.cache_mgr.save(apps)
		else:
			total_updates = _count_updates(apps)
			scan_time = 0.0

		# ── shared rendering path (cache hit OR fresh scan) ────────────────
		sources_count: Dict[str, int] = {}
		for app in apps:
			sources_count[app.source] = sources_count.get(app.source, 0) + 1

		self.ui.display_summary(
			len(apps), total_updates, scan_time, sources_count,
			show_all=getattr(args, 'show_all', False),
		)

		if getattr(args, 'package', None):
			self._handle_single_update(apps, args)
			return

		updates = [a for a in apps if a.update_status == UpdateStatus.UPDATE_AVAILABLE]
		vulnerable = [a for a in apps if a.update_status == UpdateStatus.VULNERABLE]

		console.print()
		ui_settings = self.settings.get('ui', {})
		apps_table = DisplayFormatter.format_table(
			apps,
			ui_settings.get('display_format', 'auto'),
			ui_settings.get('theme', 'default'),
			ui_settings.get('use_icons', False),
			show_all=getattr(args, 'show_all', False),
		)
		console.print(apps_table)

		if getattr(args, 'show_all', False):
			console.print('\n[dim]💾 Showing: all packages[/dim]')
		else:
			console.print('\n[dim]💾 Showing: updates only[/dim]')

		if updates or vulnerable:
			total_count = len(updates) + len(vulnerable)
			console.print(
				f'\n[bold yellow]🎯 Found {total_count} available updates[/bold yellow]'
			)

			if getattr(args, 'notify', False):
				self.notifier.notify_updates_available(total_count, len(vulnerable), force=True)

			if getattr(args, 'update_all', False):
				self._update_all_workflow(updates, vulnerable, args)
		else:
			console.print('\n[green]✨ System is up to date![/green]')

		if vulnerable:
			self._display_security_table(vulnerable)

		export_format = getattr(args, 'export', None)
		output_path = getattr(args, 'output', None)
		if isinstance(export_format, str) and export_format:
			from system_update import export as export_module

			path = export_module.export(
				apps, export_format, output_path if isinstance(output_path, str) else None
			)
			console.print(f'[green]✓[/green] Exported to {path}')

	# ── helpers ────────────────────────────────────────────────────────────

	def _scanned_sources_label(self, args: Namespace) -> str:
		"""Return the comma-separated label to record in the history DB for this scan."""
		if getattr(args, 'source', None):
			return args.source
		enabled = self.settings.get('sources', {})
		return ','.join(name for name in _SCAN_ORDER if enabled.get(name, True))

	def _update_all_workflow(
		self, updates: List[AppInfo], vulnerable: List[AppInfo], args: Namespace
	) -> None:
		"""Security-first update flow: vulnerable packages get their own confirmation + pass."""
		security_updates = [a for a in updates if a.update_status == UpdateStatus.VULNERABLE]
		regular_updates = [a for a in updates if a.update_status != UpdateStatus.VULNERABLE]
		dry_run = getattr(args, 'dry_run', False)
		yes = getattr(args, 'yes', False)

		if security_updates:
			console.print(
				f'\n[bold red]🔒 Priority: Updating {len(security_updates)} '
				f'vulnerable package(s) first...[/bold red]'
			)
			if yes or Confirm.ask('🚀 Proceed with security updates?'):
				self.executor.execute_updates(security_updates, dry_run)
			else:
				return

		if regular_updates:
			console.print(
				f'\n[bold yellow]⚡ Now updating {len(regular_updates)} '
				f'regular package(s)...[/bold yellow]'
			)
			if yes or Confirm.ask('🚀 Proceed with remaining updates?'):
				self.executor.execute_updates(regular_updates, dry_run)

	def _display_security_table(self, vulnerable: List[AppInfo]) -> None:
		"""Render the red ``🔥 Security Vulnerabilities Detected`` table at the end."""
		console.print()
		table = self.ui.create_security_table([])
		table.title = '[bold red]🔥 Security Vulnerabilities Detected[/bold red]'
		for app in vulnerable:
			entry = (
				app.security_findings[0]
				if app.security_findings
				else {
					'severity': 'HIGH',
					'cvss_score': None,
					'cve': 'N/A',
					'description': 'Update recommended',
				}
			)
			cvss_val = entry.get('cvss_score')
			cvss_display = f'{cvss_val:.1f}' if isinstance(cvss_val, (int, float)) else '-'
			table.add_row(
				app.name,
				entry.get('severity', 'HIGH'),
				cvss_display,
				entry.get('cve', 'N/A'),
				entry.get('description', 'Update recommended'),
			)
		console.print(table)

	def _handle_single_update(self, apps: List[AppInfo], args: Namespace) -> None:
		"""Update a single package by name — deferred to Step 11; warn and exit for now."""
		# TODO(step-11): port the disambiguation + version-pinning flow from the legacy file.
		console.print(
			'[yellow]--package is not yet available in the modular CLI. '
			'Run the legacy system_update.py for now.[/yellow]'
		)

	# ── security helpers (test-surface, delegate to SecurityChecker) ──────

	def _check_npm_vulns(self, apps: List[AppInfo]) -> List[Dict]:
		"""Return npm audit findings for ``apps`` (empty list on failure)."""
		try:
			return SecurityChecker.check_npm(apps)
		except Exception:
			return []

	def _check_pip_vulns(self, apps: List[AppInfo]) -> List[Dict]:
		"""Return pip-audit findings for ``apps`` (empty list on failure)."""
		try:
			return SecurityChecker.check_pip(apps)
		except Exception:
			return []

	# ── export surface ─────────────────────────────────────────────────────

	def _get_export_stats(self, apps: List[AppInfo]) -> Dict:
		"""Delegate to :func:`system_update.export.get_export_stats`."""
		from system_update import export as export_module

		return export_module.get_export_stats(apps)

	def export_results(
		self, apps: List[AppInfo], format_type: str, output_file: Optional[str] = None
	) -> str:
		"""Write ``apps`` to ``output_file`` in the given format and return the path."""
		from system_update import export as export_module

		return export_module.export(apps, format_type, output_file)

	# ── Step 11 placeholders ───────────────────────────────────────────────

	def _handle_meta_commands(self, args: Namespace) -> bool:
		"""Route history/report/interactive flags; return True if the command was consumed."""
		if getattr(args, 'history', False):
			console.print('[yellow]--history not yet ported to the modular CLI (Step 11).[/yellow]')
			return True
		if getattr(args, 'history_package', None):
			console.print(
				'[yellow]--history-package not yet ported to the modular CLI (Step 11).[/yellow]'
			)
			return True
		if getattr(args, 'history_trends', False):
			console.print(
				'[yellow]--history-trends not yet ported to the modular CLI (Step 11).[/yellow]'
			)
			return True
		if getattr(args, 'history_stale', 0) and args.history_stale > 0:
			console.print(
				'[yellow]--history-stale not yet ported to the modular CLI (Step 11).[/yellow]'
			)
			return True
		if getattr(args, 'report', None):
			console.print('[yellow]--report not yet ported to the modular CLI (Step 11).[/yellow]')
			return True
		if getattr(args, 'interactive', False):
			console.print(
				'[yellow]--interactive not yet ported to the modular CLI (Step 11).[/yellow]'
			)
			return True
		return False


__all__ = ['SystemUpdateApp']
