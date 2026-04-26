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
from typing import Callable, Dict, List, Optional, Set, Tuple

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

_KNOWN_SOURCES: Set[str] = set(_SCAN_ORDER) | set(_SOURCE_ALIASES.keys())


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


def _partition_sources(raw: Optional[str]) -> Tuple[Set[str], Set[str]]:
	"""Split ``--source a,b,xpto`` into (valid_canonical, invalid_raw_tokens)."""
	if not raw:
		return set(), set()
	valid: Set[str] = set()
	invalid: Set[str] = set()
	for item in raw.split(','):
		token = item.strip()
		if not token:
			continue
		lowered = token.lower()
		canonical = _SOURCE_ALIASES.get(lowered, lowered)
		if canonical in _KNOWN_SOURCES or lowered in _KNOWN_SOURCES:
			valid.add(canonical)
		else:
			invalid.add(token)
	return valid, invalid


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


def _parse_exclude_list(raw) -> List[str]:
	"""Normalize a comma-string or list into a clean list of exclude tokens."""
	if not raw:
		return []
	if isinstance(raw, str):
		items = raw.split(',')
	else:
		items = list(raw)
	return [item.strip() for item in items if str(item).strip()]


def _exclude_matches(app: AppInfo, tokens: List[str]) -> bool:
	"""Return True if ``app`` should be excluded based on any token.

	Tokens accept three shapes (case-insensitive):
	* ``source``             — every package from that known source
	  (e.g. ``--exclude pip`` drops all pip packages)
	* ``source:name``        — match only when source AND name/app_id both match
	  (e.g. ``--exclude pip:requests``)
	* ``source:*``           — same as bare ``source`` (explicit form)
	* ``name``               — match any package whose name/app_id equals name
	  (only when ``name`` is not also a known source — sources win)
	"""
	name = (app.name or '').lower()
	source = (app.source or '').lower()
	app_id = (app.app_id or '').lower()
	for token in tokens:
		t = token.strip().lower()
		if not t:
			continue
		if ':' in t:
			t_src, t_name = t.split(':', 1)
			if t_src == source and (t_name in ('*', '', name, app_id)):
				return True
		else:
			# Bare token: prefer source match (most users expect ``--exclude pip``
			# to drop all pip packages). Fall back to name/app_id otherwise.
			if t in _KNOWN_SOURCES:
				if t == source:
					return True
			elif t == name or t == app_id:
				return True
	return False


def _apply_excludes(apps: List[AppInfo], tokens: List[str]) -> List[AppInfo]:
	"""Drop apps matching any exclude token. No-op if ``tokens`` is empty."""
	if not tokens:
		return apps
	return [a for a in apps if not _exclude_matches(a, tokens)]


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
		# An explicit ``--source X`` request overrides ``sources.X: false`` in
		# the active profile — the user asking for X by name wins. Surface a
		# clear notice so it's obvious what happened.
		overridden = sorted(
			name for name in include
			if name in scanners and not enabled.get(name, True)
		)
		if overridden:
			console.print(
				f'[yellow]ℹ Source(s) disabled in config but requested via '
				f'--source:[/yellow] [bold]{", ".join(overridden)}[/bold] '
				f'[dim](scanning anyway — pass [cyan]--save-config[/cyan] '
				f'to make this permanent)[/dim]'
			)

		selected = [
			(name, scanners[name])
			for name in _SCAN_ORDER
			if name in scanners and (enabled.get(name, True) or name in include)
		]
		if not selected and include:
			# Filter passed but nothing left to scan — explain why.
			console.print(
				'[red]✗ Nothing to scan:[/red] '
				f'requested sources [bold]{", ".join(sorted(include))}[/bold] '
				'are not available (no scanner registered).'
			)
		elif not selected:
			# Bare run with everything disabled in config.
			console.print(
				'[red]✗ Nothing to scan:[/red] every source is disabled in '
				f'[cyan]{self.config.config_file}[/cyan]. '
				'[dim]Re-enable some via [cyan]sources.{name}: true[/cyan] '
				'or pass [cyan]--source X[/cyan].[/dim]'
			)

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

	# ── partial scan + cache merge ─────────────────────────────────────────

	def _scan_missing_and_merge(
		self, cached: List[AppInfo], missing: Set[str]
	) -> List[AppInfo]:
		"""Scan only ``missing`` sources, merge into ``cached``, save, return filtered view."""
		console.print(
			f'[dim]💾 Cache hit. Scanning missing source(s) '
			f'{sorted(missing)} and merging.[/dim]\n'
		)
		prev_include = self._include_sources
		self._include_sources = set(missing)
		try:
			console.print('[bold cyan]🔎 Scanning sources...[/bold cyan]')
			new_apps = self.scan_system(','.join(sorted(missing)))
			console.print(
				f'\n📦 [bold]Discovered {len(new_apps)} unique apps.[/bold]'
			)

			console.print('[bold cyan]🔄 Checking for updates...[/bold cyan]')
			self.checker.check_all_updates(new_apps)

			regular_updates = sum(
				1 for a in new_apps if a.update_status == UpdateStatus.UPDATE_AVAILABLE
			)
			security_updates = sum(
				1 for a in new_apps
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
					f'[bold magenta]📊 Detected {total_updates} '
					f'update candidates.[/bold magenta]\n'
				)

			console.print(
				'[bold magenta]🔒 Checking security vulnerabilities...[/bold magenta]'
			)
			advisory_file = os.path.join(
				os.path.expanduser('~'), '.system_update', 'advisories.json'
			)
			security_vulns = self.security.check_all(new_apps, advisory_file)
			if security_vulns:
				console.print(
					f'[bold red]🔥 Found {len(security_vulns)} '
					f'security vulnerabilities.[/bold red]\n'
				)
			else:
				console.print(
					'[bold green]🛡️ No security vulnerabilities found.[/bold green]\n'
				)
			_pypi_fallback_latest(new_apps)
		finally:
			self._include_sources = prev_include

		# Merge: drop any cached entries for newly-scanned sources, append fresh.
		merged = [a for a in cached if a.source.lower() not in missing] + new_apps
		merged = sorted(merged, key=lambda x: f'{x.source}{x.name}')
		self.cache_mgr.save(merged)
		console.print(
			f'[dim]💾 Cache updated ({len(merged)} items across '
			f'{len({a.source.lower() for a in merged})} sources).[/dim]\n'
		)
		return [a for a in merged if a.source.lower() in self._include_sources]

	# ── main workflow ──────────────────────────────────────────────────────

	def run(self, args: Namespace) -> None:
		"""Full flow: scan → check → security → cache → history → display → export → update."""
		# Activate the named profile BEFORE setup_logging so log/cache/history
		# all land in the right directory. SystemConfig.__init__ runs with the
		# default profile (we don't see args yet), so we re-init here.
		# Strict ``isinstance(str)`` so MagicMock attrs in unit tests don't
		# accidentally get treated as profile names.
		profile = getattr(args, 'profile', None)
		if isinstance(profile, str) and profile:
			self.config.reinit(profile)
			self.settings = self.config.settings
			# Re-bind any sub-system that captured an old path.
			from system_update.cache import CacheManager
			from system_update.history import HistoryDatabase, VulnerabilityHistory

			self.cache_mgr = CacheManager(
				self.config.cache_file,
				self.settings.get('cache', {}).get('duration_hours', 2),
			)
			try:
				if self.history_db:
					self.history_db.close()
			except Exception:
				pass
			self.history_db = HistoryDatabase(
				Path(self.config.config_dir) / 'history.db'
			)
			self.vuln_history = VulnerabilityHistory(
				Path(self.config.config_dir) / 'vulnerability_history.json'
			)
			console.print(
				f'[bold cyan]👤 Profile activated:[/bold cyan] '
				f'[bold]{profile}[/bold]'
			)

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

		# --save-config: fold this run's CLI overrides into config.json so the
		# next run uses them as defaults. Specifically: --source X,Y,Z sets
		# sources.* to True only for those sources (everything else False).
		if getattr(args, 'save_config', False):
			self._persist_cli_overrides(args)

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
			valid, invalid = _partition_sources(args.source)
			if invalid:
				available = ', '.join(sorted(_SCAN_ORDER))
				console.print(
					f'[yellow]⚠️  Unknown source(s): '
					f'{", ".join(sorted(invalid))}[/yellow]\n'
					f'[dim]   Available: {available}[/dim]'
				)
			if not valid:
				console.print(
					'[red]❌ No valid sources in --source. '
					'Nothing to do — cache left untouched.[/red]'
				)
				return
			if invalid:
				console.print(
					f'[dim]   Proceeding with: {", ".join(sorted(valid))}[/dim]\n'
				)
			self._include_sources = valid
			# Overwrite args.source with the sanitized CSV so downstream
			# helpers (scan_system, _scanned_sources_label, cache sources check)
			# see only valid tokens.
			args.source = ','.join(sorted(valid))

		apps: Optional[List[AppInfo]] = None

		# ── --import (5.4.1) / --merge (5.4.2) ─────────────────────────────
		import_files = getattr(args, 'import_files', None) or []
		if import_files:
			merge_flag = bool(getattr(args, 'merge_with_cache', False))
			imported = self._import_apps_from_files(import_files, merge_flag)
			if imported:
				apps = imported
				# Imported data short-circuits live scan; security checks
				# can still run on the imported set below.
				security_vulns = []
				total_updates = _count_updates(apps)

		if apps is None and not getattr(args, 'no_cache', False) and self.settings.get('cache', {}).get(
			'enabled', True
		):
			cached = self.cache_mgr.load()
			if cached:
				if self._include_sources:
					cached_sources = {s.lower() for s in self.cache_mgr.load_sources()}
					missing = self._include_sources - cached_sources
					if missing:
						apps = self._scan_missing_and_merge(cached, missing)
					else:
						apps = [
							a for a in cached if a.source.lower() in self._include_sources
						]
						console.print(
							f'[dim]💾 Loaded {len(apps)} items from cache '
							f'(filter: {",".join(sorted(self._include_sources))}) '
							f'{self._cache_expiry_hint()}[/dim]\n'
						)
				else:
					apps = cached
					console.print(
						f'[dim]💾 Loaded {len(apps)} items from cache '
						f'{self._cache_expiry_hint()}[/dim]\n'
					)
			elif cached is not None and self._include_sources:
				# Valid but empty cache + --source X: scan X silently via merge
				# path so the full-scan banners don't fire.
				apps = self._scan_missing_and_merge([], set(self._include_sources))

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

			total_updates = _count_updates(apps)
			if getattr(args, 'no_cache', False):
				console.print(
					'[dim]💾 --no-cache: skipping cache write '
					'(scan results not persisted).[/dim]\n'
				)
			else:
				self.cache_mgr.save(apps)
		else:
			total_updates = _count_updates(apps)
			scan_time = 0.0

		# ── apply exclude list (CLI > env > config) ────────────────────────
		exclude_tokens = _parse_exclude_list(getattr(args, 'exclude', None))
		if not exclude_tokens:
			exclude_tokens = _parse_exclude_list(self.settings.get('exclude'))
		if exclude_tokens:
			before = len(apps)
			apps = _apply_excludes(apps, exclude_tokens)
			dropped = before - len(apps)
			if dropped:
				console.print(
					f'[dim]🚫 Excluded {dropped} package(s) matching: '
					f'{", ".join(exclude_tokens)}[/dim]\n'
				)
			total_updates = _count_updates(apps)

		# ── shared rendering path (cache hit OR fresh scan) ────────────────
		sources_count: Dict[str, int] = {}
		for app in apps:
			sources_count[app.source] = sources_count.get(app.source, 0) + 1

		# Flatten security findings from AppInfo so cache-hit path also gets
		# a summary (security_vulns is only populated on fresh scan).
		# Dedupe by (package, cve) across sources (PyPI + pip-audit + OSV …).
		seen_keys: Set[str] = set()
		all_vulns: List[Dict] = []
		for a in apps:
			for f in a.security_findings or []:
				cve = f.get('cve') or f.get('cve_id') or 'N/A'
				key = f'{a.name.lower()}|{cve}'
				if key in seen_keys:
					continue
				seen_keys.add(key)
				entry = dict(f)
				entry.setdefault('package', a.name)
				all_vulns.append(entry)
		security_stats = self.ui.compute_security_stats(all_vulns)

		self.ui.display_summary(
			len(apps), total_updates, scan_time, sources_count,
			show_all=getattr(args, 'show_all', False),
			security_stats=security_stats,
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

			if getattr(args, 'interactive', False):
				self._interactive_update(updates, vulnerable, args)
			elif getattr(args, 'update_all', False):
				self._update_all_workflow(updates, vulnerable, args)
		else:
			console.print('\n[green]✨ System is up to date![/green]')

		if vulnerable:
			self._display_security_table(vulnerable)

		export_format = getattr(args, 'export', None)
		output_path = getattr(args, 'output', None)
		if isinstance(export_format, str) and export_format:
			from system_update import export as export_module

			branding = None
			template_path = None
			if export_format == 'html':
				from system_update.report_templates import resolve_branding

				cli_overrides = {
					'title': getattr(args, 'html_title', None),
					'company_name': getattr(args, 'html_company', None),
					'logo_path': getattr(args, 'html_logo', None),
				}
				branding = resolve_branding(self.settings, cli_overrides)
				template_path = getattr(args, 'html_template', None) or (
					self.settings.get('report', {}).get('template_path') or None
				)

			try:
				path = export_module.export(
					apps,
					export_format,
					output_path if isinstance(output_path, str) else None,
					branding=branding,
					template_path=template_path,
				)
			except ValueError as e:
				console.print(f'[red]✗ Export failed:[/red] {e}')
				import sys as _sys

				_sys.exit(2)
			else:
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
		"""Render the red ``🔥 Security Vulnerabilities Detected`` table — one row per CVE."""
		console.print()
		table = self.ui.create_security_table([])
		table.title = '[bold red]🔥 Security Vulnerabilities Detected[/bold red]'
		# create_security_table seeds 5 columns; add Fix as 6th.
		table.add_column('Fix', justify='center')

		_SEV_RANK = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, '': 0}
		total_vulns = 0
		pkg_count = 0
		for app in vulnerable:
			findings = list(app.security_findings or [])
			if not findings:
				findings = [{
					'severity': 'HIGH',
					'cvss_score': None,
					'cve': 'N/A',
					'description': 'Update recommended',
				}]

			# Dedupe by (package, cve): merge entries from multiple sources
			# (PyPI JSON, pip-audit, OSV, …) keeping richest metadata.
			merged: Dict[str, Dict] = {}
			for entry in findings:
				cve = entry.get('cve') or entry.get('cve_id') or 'N/A'
				key = f'{app.name.lower()}|{cve}'
				prev = merged.get(key)
				if prev is None:
					merged[key] = dict(entry)
					continue
				# Prefer higher severity.
				if _SEV_RANK.get((entry.get('severity') or '').upper(), 0) > _SEV_RANK.get(
					(prev.get('severity') or '').upper(), 0
				):
					prev['severity'] = entry.get('severity')
				# Prefer any numeric CVSS over None.
				if isinstance(entry.get('cvss_score'), (int, float)) and not isinstance(
					prev.get('cvss_score'), (int, float)
				):
					prev['cvss_score'] = entry['cvss_score']
				# Prefer longer description.
				if len(str(entry.get('description') or '')) > len(
					str(prev.get('description') or '')
				):
					prev['description'] = entry.get('description')

			pkg_count += 1
			for entry in merged.values():
				cvss_val = entry.get('cvss_score')
				cvss_display = (
					f'{cvss_val:.1f}' if isinstance(cvss_val, (int, float)) else '-'
				)
				table.add_row(
					f'{app.name} {app.version or ""}'.strip(),
					entry.get('severity', 'HIGH'),
					cvss_display,
					entry.get('cve') or entry.get('cve_id') or 'N/A',
					entry.get('description', 'Update recommended'),
					app.latest_version or '-',
				)
				total_vulns += 1
		console.print(table)
		if total_vulns:
			console.print(
				f'[bold red]Found {total_vulns} known vulnerabilities '
				f'in {pkg_count} package(s).[/bold red]'
			)

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

	# ── Meta commands (history / report / interactive) ─────────────────────

	def _handle_meta_commands(self, args: Namespace) -> bool:
		"""Route history/report/interactive flags; return True if the command was consumed."""
		if getattr(args, 'history', False):
			self._show_history()
			return True
		if getattr(args, 'history_package', None):
			self._show_package_history(args.history_package)
			return True
		if getattr(args, 'history_trends', False):
			self._show_trends()
			return True
		if getattr(args, 'history_stale', 0) and args.history_stale > 0:
			self._show_stale(args.history_stale)
			return True
		if getattr(args, 'report', None):
			self._generate_history_report(args.report, getattr(args, 'report_output', None))
			return True
		if getattr(args, 'cloud_sync', None):
			self._handle_cloud_sync(args.cloud_sync)
			return True
		if getattr(args, 'schedule', None):
			self._handle_schedule(args)
			return True
		if getattr(args, 'profile_export', None):
			self._export_profile(args.profile_export)
			return True
		if getattr(args, 'profile_import', None):
			self._import_profile(
				args.profile_import,
				target_name=getattr(args, 'profile', None),
			)
			return True
		return False

	# ── Cache helpers ──────────────────────────────────────────────────────

	def _cache_expiry_hint(self) -> str:
		"""Return ``(expires HH:MM:SS · in 1h 23m)`` style suffix, or empty."""
		expires = self.cache_mgr.expires_at()
		remaining = self.cache_mgr.time_remaining()
		if expires is None or remaining is None:
			return ''
		stamp = expires.strftime('%H:%M:%S')
		return f'(expires {stamp} · in {remaining})'

	# ── Persist CLI overrides ──────────────────────────────────────────────

	def _persist_cli_overrides(self, args: Namespace) -> None:
		"""Write current CLI overrides (sources, theme, format, icons) into config.json.

		Only ``--source`` rewrites the ``sources`` block — every named source
		gets ``true`` and every other one gets ``false``. UI flags merge into
		``ui``. Called when the user passes ``--save-config``.
		"""
		changed: List[str] = []

		raw_source = getattr(args, 'source', None)
		if raw_source:
			valid, _ = _partition_sources(raw_source)
			if valid:
				new_sources = {
					name: (name in valid) for name in self.settings.get('sources', {})
				}
				# Add any canonical names that weren't already in config.
				for name in valid:
					new_sources.setdefault(name, True)
				self.settings['sources'] = new_sources
				changed.append(f'sources → {", ".join(sorted(valid))}')

		raw_exclude = getattr(args, 'exclude', None)
		if raw_exclude:
			tokens = _parse_exclude_list(raw_exclude)
			self.settings['exclude'] = tokens
			changed.append(f'exclude → {", ".join(tokens)}')

		ui = self.settings.setdefault('ui', {})
		if getattr(args, 'theme', None):
			ui['theme'] = args.theme
			changed.append(f'ui.theme → {args.theme}')
		if getattr(args, 'format', None):
			ui['display_format'] = args.format
			changed.append(f'ui.display_format → {args.format}')
		if getattr(args, 'icons', False):
			ui['use_icons'] = True
			changed.append('ui.use_icons → true')

		if not changed:
			console.print(
				'[yellow]⚠ --save-config: nothing to persist[/yellow] '
				'[dim](no --source/--theme/--format/--icons supplied)[/dim]'
			)
			return

		try:
			self.config.save()
			profile_label = self.config.current_profile or 'default'
			console.print(
				f'[green]💾 Saved to[/green] [bold]{profile_label}[/bold] '
				f'profile: [cyan]{", ".join(changed)}[/cyan]'
			)
		except Exception as e:
			console.print(f'[red]✗ Save failed:[/red] {e}')

	# ── Profile import / export ────────────────────────────────────────────

	def _export_profile(self, output_path: str) -> None:
		"""Save the active profile (or default) settings to ``output_path``."""
		from pathlib import Path as _Path

		out = _Path(output_path).expanduser().resolve()
		ok = self.config.export_profile(str(out))
		if ok:
			profile_label = self.config.current_profile or 'default'
			console.print(
				f'[green]✓ Exported[/green] profile [bold]{profile_label}[/bold] '
				f'→ [cyan]{out}[/cyan]'
			)
		else:
			console.print(
				f'[red]✗ Export failed:[/red] could not write {out} '
				f'(check permissions / errors.log)'
			)

	def _import_profile(
		self, input_path: str, target_name: Optional[str] = None
	) -> None:
		"""Load profile JSON; if ``--profile NAME`` was passed, install under that name."""
		from pathlib import Path as _Path

		src = _Path(input_path).expanduser()
		if not src.is_file():
			console.print(f'[red]✗ Import failed:[/red] file not found: {src}')
			return
		ok = self.config.import_profile(str(src), profile_name=target_name)
		if ok:
			profile_label = self.config.current_profile or 'imported'
			# Re-bind subsystems to the new profile's paths.
			self.settings = self.config.settings
			from system_update.cache import CacheManager
			from system_update.history import HistoryDatabase, VulnerabilityHistory

			self.cache_mgr = CacheManager(
				self.config.cache_file,
				self.settings.get('cache', {}).get('duration_hours', 2),
			)
			try:
				if self.history_db:
					self.history_db.close()
			except Exception:
				pass
			self.history_db = HistoryDatabase(
				Path(self.config.config_dir) / 'history.db'
			)
			self.vuln_history = VulnerabilityHistory(
				Path(self.config.config_dir) / 'vulnerability_history.json'
			)
			console.print(
				f'[green]✓ Imported[/green] profile [bold]{profile_label}[/bold] '
				f'← [cyan]{src}[/cyan]'
			)
		else:
			console.print(
				f'[red]✗ Import failed:[/red] {src} '
				f'(invalid JSON or missing "settings" key)'
			)

	# ── Scheduled tasks (6.1) ──────────────────────────────────────────────

	def _handle_schedule(self, args: Namespace) -> None:
		"""Dispatch ``--schedule create|delete|list|status|run|eval|help``."""
		from system_update import scheduler, subhelp

		action = args.schedule.lower()
		name = getattr(args, 'schedule_name', None) or 'SystemUpdate_Scan'

		if action == 'help':
			subhelp.show('schedule')
			return

		if action == 'eval':
			self._evaluate_conditional_actions(args)
			return

		try:
			if action == 'create':
				spec = scheduler.ScheduleSpec(
					name=name,
					frequency=getattr(args, 'schedule_when', 'daily') or 'daily',
					time=getattr(args, 'schedule_time', '09:00') or '09:00',
					days=getattr(args, 'schedule_days', '') or '',
					command_args=getattr(args, 'schedule_args', '') or '',
				)
				result = scheduler.create_task(spec)
				console.print(
					f'[green]✓ Scheduled[/green] task [bold]{result["name"]}[/bold] '
					f'({result["frequency"]} @ {result["time"] or "n/a"})'
				)
				console.print(f'  [dim]command:[/dim] {result["command"]}')

			elif action == 'delete':
				scheduler.delete_task(name)
				console.print(f'[green]✓ Removed[/green] scheduled task [bold]{name}[/bold]')

			elif action == 'list':
				tasks = scheduler.list_tasks()
				if not tasks:
					console.print(
						'[yellow]No SystemUpdate scheduled tasks found.[/yellow]'
					)
					return
				from rich.table import Table

				t = Table(title='🗓️  Scheduled tasks', expand=True)
				t.add_column('Name', style='bold')
				t.add_column('Next run', style='cyan')
				t.add_column('Last run', style='yellow')
				t.add_column('Last result', style='green', justify='right')
				t.add_column('Status', style='magenta')
				for entry in tasks:
					last_run = entry.get('last_run', '') or ''
					# schtasks emits "30/11/1999 ..." as a "never run" sentinel.
					if not last_run or last_run.startswith('30/11/1999'):
						last_run_display = '[dim]Never[/dim]'
					else:
						last_run_display = last_run

					last_result = entry.get('last_result', '') or ''
					if not last_result:
						last_result_display = '[dim]—[/dim]'
					elif last_result.strip() in ('0', '0x0'):
						last_result_display = last_result
					else:
						last_result_display = f'[red]{last_result}[/red]'

					t.add_row(
						entry['name'],
						entry.get('next_run', ''),
						last_run_display,
						last_result_display,
						entry.get('status', ''),
					)
				console.print(t)

			elif action == 'status':
				info = scheduler.task_status(name)
				if not info:
					console.print(f'[yellow]Task not found: {name}[/yellow]')
					return
				console.print(f'[bold]🗓️  Task: {info["name"]}[/bold]')
				for key in (
					'status', 'schedule_type', 'next_run_time', 'last_run_time',
					'last_result', 'task_to_run', 'run_as_user',
				):
					console.print(f'  [cyan]{key}[/cyan]: {info.get(key, "")}')

			elif action == 'run':
				scheduler.run_task_now(name)
				console.print(f'[green]✓ Triggered[/green] task [bold]{name}[/bold]')

		except RuntimeError as e:
			console.print(f'[red]✗ Schedule error:[/red] {e}')
		except ValueError as e:
			console.print(f'[red]✗ Invalid schedule spec:[/red] {e}')

	def _evaluate_conditional_actions(self, args: Namespace) -> None:
		"""Run a scan, evaluate ``conditional_actions`` rules, fire matched actions.

		Used by scheduled tasks: configure ``--schedule-args "--schedule eval"``
		(or any combination) to have the task run a scan and act on the result
		without prompts.
		"""
		from system_update import conditions

		console.print('[bold cyan]🤖 Evaluating conditional actions...[/bold cyan]')
		apps = self.scan_system(getattr(args, 'source', None))
		try:
			from system_update.checkers import check_all_updates

			check_all_updates(apps)
		except Exception as e:
			logger.warning(f'check_all_updates failed during eval: {e}')

		matched = conditions.evaluate(apps, self.settings)
		if not matched:
			console.print('[green]✓ No conditional rules matched.[/green]')
			return

		console.print(f'[bold]Matched {len(matched)} rule(s).[/bold]')
		conditions.apply(
			matched, apps,
			notifier=self.notifier,
			executor=self.executor,
			console=console,
			dry_run=getattr(args, 'dry_run', False),
		)

	# ── Data sharing (5.4) ─────────────────────────────────────────────────

	def _handle_cloud_sync(self, action: str) -> None:
		"""Dispatch ``--cloud-sync push|pull|status|help`` to the data_sharing module."""
		from system_update import data_sharing, subhelp

		if action == 'help':
			subhelp.show('cloud-sync')
			return

		cache_path = Path(self.config.cache_file)
		try:
			if action == 'push':
				target, size = data_sharing.cloud_push(cache_path, self.settings)
				console.print(
					f'[green]✓ Pushed[/green] {size:,} bytes → [cyan]{target}[/cyan]'
				)
			elif action == 'pull':
				target, size = data_sharing.cloud_pull(cache_path, self.settings)
				console.print(
					f'[green]✓ Pulled[/green] {size:,} bytes ← [cyan]{target}[/cyan]'
				)
			elif action == 'status':
				stat = data_sharing.cloud_status(cache_path, self.settings)
				console.print('[bold]☁️  Cloud sync status[/bold]')
				for k, v in stat.items():
					console.print(f'  [cyan]{k}[/cyan]: {v}')
			else:
				console.print(f'[red]Unknown cloud-sync action: {action}[/red]')
		except FileNotFoundError as e:
			console.print(f'[red]✗ {e}[/red]')
		except ValueError as e:
			console.print(f'[red]✗ Cloud sync misconfigured:[/red] {e}')
		except Exception as e:
			console.print(f'[red]✗ Cloud sync failed:[/red] {e}')

	def _import_apps_from_files(
		self, paths: List[str], merge_with_cache: bool = False
	) -> List[AppInfo]:
		"""Load and merge AppInfo lists from one or more JSON/CSV files.

		If ``merge_with_cache`` is set and a valid cache exists, those entries
		are folded in too (latest scan_time wins per source|name|version key).
		"""
		from system_update import data_sharing

		batches: List[List[AppInfo]] = []
		for path in paths:
			try:
				batch = data_sharing.import_apps(path)
				console.print(
					f'[green]✓ Imported[/green] {len(batch)} package(s) from '
					f'[cyan]{path}[/cyan]'
				)
				batches.append(batch)
			except (FileNotFoundError, ValueError) as e:
				console.print(f'[red]✗ Import failed for {path}:[/red] {e}')
			except Exception as e:
				console.print(f'[red]✗ Unexpected import error for {path}:[/red] {e}')

		if merge_with_cache:
			cached = self.cache_mgr.load() or []
			if cached:
				console.print(
					f'[dim]🧬 Merging with cache ({len(cached)} cached package(s))[/dim]'
				)
				batches.append(cached)

		if not batches:
			return []

		merged = data_sharing.merge_apps(*batches, prefer='latest')
		console.print(
			f'[bold]🧬 Merge complete:[/bold] {len(merged)} unique package(s)'
		)
		# Persist merged result so subsequent runs use it.
		try:
			self.cache_mgr.save(merged)
			console.print('[dim]💾 Cache updated with merged data.[/dim]')
		except Exception as e:
			logger.warning(f'Failed to persist merged cache: {e}')
		return merged

	# ── Interactive picker ─────────────────────────────────────────────────

	def _interactive_update(
		self,
		updates: List[AppInfo],
		vulnerable: List[AppInfo],
		args: Namespace,
	) -> None:
		"""Show numbered list of update candidates, let user pick which to apply.

		Input syntax: ``all`` / ``none`` / comma-and-range list (e.g. ``1,3,5-7``).
		Vulnerable packages are listed first and pre-marked with [VULN].
		"""
		from rich.prompt import Prompt
		from rich.table import Table

		from system_update.executors import UpdateExecutor

		# Vulnerable first, then regular updates; dedup while preserving order.
		seen: Set[int] = set()
		ordered: List[AppInfo] = []
		for app in list(vulnerable) + list(updates):
			if id(app) in seen:
				continue
			seen.add(id(app))
			ordered.append(app)

		if not ordered:
			console.print('[yellow]Nothing to update.[/yellow]')
			return

		table = Table(
			title='🖱️  Interactive update picker',
			caption='Select packages to update — type [bold]all[/bold], [bold]none[/bold], or e.g. [bold]1,3,5-7[/bold].',
			expand=True,
		)
		table.add_column('#', justify='right', style='cyan', no_wrap=True)
		table.add_column('Package', style='bold')
		table.add_column('Source', style='magenta')
		table.add_column('Current', style='white')
		table.add_column('→ Latest', style='green')
		table.add_column('Status', no_wrap=True)
		for idx, app in enumerate(ordered, start=1):
			tag = (
				'[red]VULN[/red]'
				if app.update_status == UpdateStatus.VULNERABLE
				else '[yellow]update[/yellow]'
			)
			table.add_row(
				str(idx),
				app.name,
				app.source,
				app.version or '-',
				app.latest_version or '?',
				tag,
			)
		console.print(table)

		try:
			raw = Prompt.ask(
				'[bold]Select[/bold] [dim](all / none / 1,3,5-7)[/dim]',
				default='none',
			)
		except (EOFError, KeyboardInterrupt):
			console.print('\n[yellow]Cancelled.[/yellow]')
			return

		picks = self._parse_picker_input(raw, len(ordered))
		if picks is None:
			console.print('[red]✗ Invalid selection.[/red]')
			return
		if not picks:
			console.print('[yellow]No packages selected — exiting.[/yellow]')
			return

		chosen = [ordered[i - 1] for i in sorted(picks)]
		console.print(f'\n[cyan]Selected {len(chosen)} package(s):[/cyan]')
		for app in chosen:
			console.print(f'  • {app.name} [{app.source}] {app.version} → {app.latest_version}')

		if not getattr(args, 'yes', False):
			try:
				confirm = Prompt.ask(
					'[bold]Proceed with updates?[/bold] [dim](y/N)[/dim]', default='n'
				)
			except (EOFError, KeyboardInterrupt):
				console.print('\n[yellow]Cancelled.[/yellow]')
				return
			if confirm.strip().lower() not in ('y', 'yes'):
				console.print('[yellow]Aborted.[/yellow]')
				return

		dry_run = getattr(args, 'dry_run', False)
		console.print(
			f'\n[bold]{"🧪 Dry-run" if dry_run else "🚀 Updating"} '
			f'{len(chosen)} package(s)...[/bold]'
		)
		UpdateExecutor.execute_updates(chosen, dry_run=dry_run)

	@staticmethod
	def _parse_picker_input(raw: str, total: int) -> Optional[Set[int]]:
		"""Parse ``all`` / ``none`` / ``1,3,5-7`` into a set of 1-based indices.

		Returns ``None`` if any token is invalid.
		"""
		text = (raw or '').strip().lower()
		if text in ('', 'none', 'n', 'q', 'quit', 'cancel'):
			return set()
		if text in ('all', 'a', '*'):
			return set(range(1, total + 1))
		picks: Set[int] = set()
		for token in (t.strip() for t in text.replace(';', ',').split(',') if t.strip()):
			if '-' in token:
				try:
					lo_s, hi_s = token.split('-', 1)
					lo, hi = int(lo_s), int(hi_s)
				except ValueError:
					return None
				if lo > hi or lo < 1 or hi > total:
					return None
				picks.update(range(lo, hi + 1))
			else:
				try:
					n = int(token)
				except ValueError:
					return None
				if n < 1 or n > total:
					return None
				picks.add(n)
		return picks

	# ── History rendering ──────────────────────────────────────────────────

	def _show_history(self, limit: int = 10) -> None:
		"""Print a Rich table of the last ``limit`` scan headers."""
		from rich.table import Table

		scans = self.history_db.get_scans(limit=limit)
		if not scans:
			console.print('[yellow]No scan history yet.[/yellow]')
			return
		table = Table(title=f'📚 Last {len(scans)} scan(s)', expand=True)
		table.add_column('Timestamp', style='cyan')
		table.add_column('Source', style='magenta')
		table.add_column('Pkgs', justify='right')
		table.add_column('Updates', justify='right', style='yellow')
		table.add_column('Vulns', justify='right', style='red')
		table.add_column('Duration', justify='right', style='green')
		for s in scans:
			table.add_row(
				str(s.get('timestamp', '')),
				str(s.get('source', '') or '-')[:60],
				str(s.get('package_count', 0)),
				str(s.get('update_count', 0)),
				str(s.get('vulnerability_count', 0)),
				f'{float(s.get("duration_seconds", 0) or 0):.1f}s',
			)
		console.print(table)

	def _show_package_history(self, package: str) -> None:
		"""Print all version-history rows for ``package`` across sources."""
		from rich.table import Table

		rows = self.history_db.get_package_history(package)
		if not rows:
			console.print(f'[yellow]No history found for[/yellow] [bold]{package}[/bold].')
			return
		table = Table(title=f'🔍 Version history — {package}', expand=True)
		table.add_column('Timestamp', style='cyan')
		table.add_column('Source', style='magenta')
		table.add_column('Version', style='white')
		table.add_column('Change', style='yellow')
		for r in rows:
			table.add_row(
				str(r.get('timestamp', '')),
				str(r.get('source', '') or '-'),
				str(r.get('version', '') or '-'),
				str(r.get('change_type', '') or '-'),
			)
		console.print(table)

	def _show_trends(self, days: int = 30) -> None:
		"""Print update / scan trends per source over the last ``days``."""
		from rich.table import Table

		data = self.history_db.get_update_trends(days=days)
		stats = data.get('source_stats') or []
		console.print(
			f'[bold]📈 Update trends — last {data.get("period_days", days)} day(s)[/bold]'
		)
		console.print(f'Unique packages tracked: [cyan]{data.get("unique_packages", 0)}[/cyan]')
		if not stats:
			console.print('[yellow]No scan data in window.[/yellow]')
			return
		table = Table(expand=True)
		table.add_column('Source', style='magenta')
		table.add_column('Scans', justify='right')
		table.add_column('Total pkgs', justify='right')
		table.add_column('Total updates', justify='right', style='yellow')
		for row in stats:
			table.add_row(
				str(row.get('source', '') or '-')[:40],
				str(row.get('total_scans', 0)),
				str(row.get('total_packages', 0) or 0),
				str(row.get('total_updates', 0) or 0),
			)
		console.print(table)

	def _show_stale(self, days: int) -> None:
		"""Print packages whose last-seen version row is older than ``days``."""
		from rich.table import Table

		stale = self.history_db.get_stale_packages(days=days)
		if not stale:
			console.print(f'[green]✓ No packages stale beyond {days} day(s).[/green]')
			return
		table = Table(title=f'🕰️  Packages not updated in {days}+ day(s)', expand=True)
		table.add_column('Package', style='bold')
		table.add_column('Source', style='magenta')
		table.add_column('Last seen', style='cyan')
		for r in stale:
			table.add_row(
				str(r.get('package_name', '')),
				str(r.get('source', '') or '-'),
				str(r.get('last_seen', '')),
			)
		console.print(table)
		console.print(f'[yellow]Total stale:[/yellow] {len(stale)}')

	def _generate_history_report(
		self, fmt: str, output: Optional[str] = None
	) -> None:
		"""Write a text/json/html summary of scan + vulnerability history to disk (or stdout)."""
		import json as _json
		from datetime import datetime

		fmt = (fmt or 'text').lower()
		scans = self.history_db.get_scans(limit=50)
		trends = self.history_db.get_update_trends(days=30)
		stale = self.history_db.get_stale_packages(days=90)
		vuln_stats = self.vuln_history.get_statistics()
		generated = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

		if fmt == 'json':
			payload = {
				'generated': generated,
				'scans': scans,
				'trends': trends,
				'stale_packages': stale,
				'vulnerability_stats': vuln_stats,
			}
			content = _json.dumps(payload, indent=2, default=str)
		elif fmt == 'html':
			from system_update.report_templates import (
				ReportBranding,
			)

			# Re-use the HTML report renderer with a synthetic empty app list —
			# users mainly want the history tables here.
			content = self._render_history_html(
				scans, trends, stale, vuln_stats, generated, ReportBranding()
			)
		else:  # text
			lines = [
				f'System Update — History Report  ({generated})',
				'=' * 60,
				'',
				f'Recent scans (last {len(scans)}):',
			]
			for s in scans[:20]:
				lines.append(
					f'  [{s.get("timestamp", "")}] {s.get("source", "-"):<25} '
					f'pkgs={s.get("package_count", 0):>4}  '
					f'updates={s.get("update_count", 0):>3}  '
					f'vulns={s.get("vulnerability_count", 0):>3}'
				)
			lines += [
				'',
				f'Trends (last {trends.get("period_days", 30)} days):',
				f'  Unique packages tracked: {trends.get("unique_packages", 0)}',
			]
			for r in trends.get('source_stats') or []:
				lines.append(
					f'  - {r.get("source", "-"):<20} '
					f'scans={r.get("total_scans", 0):>3}  '
					f'updates={r.get("total_updates", 0) or 0:>4}'
				)
			lines += ['', f'Stale packages (>90d): {len(stale)}']
			for r in stale[:20]:
				lines.append(
					f'  - {r.get("package_name", ""):<30} '
					f'{r.get("source", "-"):<15} last_seen={r.get("last_seen", "")}'
				)
			lines += [
				'',
				'Vulnerabilities:',
				f'  total={vuln_stats.get("total_vulnerabilities", 0)} '
				f'open={vuln_stats.get("open_vulnerabilities", 0)} '
				f'resolved={vuln_stats.get("resolved_vulnerabilities", 0)}',
				f'  critical={vuln_stats.get("critical_count", 0)} '
				f'high={vuln_stats.get("high_count", 0)} '
				f'medium={vuln_stats.get("medium_count", 0)} '
				f'low={vuln_stats.get("low_count", 0)}',
				f'  packages_affected={vuln_stats.get("packages_affected", 0)} '
				f'persistent={vuln_stats.get("persistent_vulnerabilities", 0)}',
			]
			content = '\n'.join(lines)

		if output:
			from pathlib import Path as _Path

			out = _Path(output)
			out.parent.mkdir(parents=True, exist_ok=True)
			out.write_text(content, encoding='utf-8')
			console.print(f'[green]✓[/green] History report written to [cyan]{out}[/cyan]')
		else:
			if fmt == 'json':
				console.print_json(content)
			else:
				console.print(content)

	def _render_history_html(
		self,
		scans: List[Dict],
		trends: Dict,
		stale: List[Dict],
		vuln_stats: Dict,
		generated: str,
		branding,
	) -> str:
		"""Build a self-contained HTML history report."""

		def _esc(text) -> str:
			return (
				str(text)
				.replace('&', '&amp;')
				.replace('<', '&lt;')
				.replace('>', '&gt;')
				.replace('"', '&quot;')
			)

		scan_rows = '\n'.join(
			f'<tr><td>{_esc(s.get("timestamp", ""))}</td>'
			f'<td>{_esc(s.get("source", "-"))}</td>'
			f'<td>{s.get("package_count", 0)}</td>'
			f'<td>{s.get("update_count", 0)}</td>'
			f'<td>{s.get("vulnerability_count", 0)}</td></tr>'
			for s in scans[:50]
		)
		trend_rows = '\n'.join(
			f'<tr><td>{_esc(r.get("source", "-"))}</td>'
			f'<td>{r.get("total_scans", 0)}</td>'
			f'<td>{r.get("total_packages", 0) or 0}</td>'
			f'<td>{r.get("total_updates", 0) or 0}</td></tr>'
			for r in (trends.get('source_stats') or [])
		)
		stale_rows = '\n'.join(
			f'<tr><td>{_esc(r.get("package_name", ""))}</td>'
			f'<td>{_esc(r.get("source", "-"))}</td>'
			f'<td>{_esc(r.get("last_seen", ""))}</td></tr>'
			for r in stale[:100]
		)
		return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>{_esc(branding.title)} — History — {_esc(generated)}</title>
<style>
body {{ font-family: -apple-system, "Segoe UI", sans-serif; max-width: 1100px; margin: 0 auto; padding: 20px; background: {branding.background_color}; color: {branding.accent_color}; }}
h1, h2 {{ color: {branding.primary_color}; }}
table {{ width: 100%; border-collapse: collapse; background: white; box-shadow: 0 2px 4px rgba(0,0,0,0.08); margin: 12px 0 24px; border-radius: 8px; overflow: hidden; }}
th {{ background: {branding.primary_color}; color: white; padding: 10px; text-align: left; }}
td {{ padding: 8px 10px; border-bottom: 1px solid #eee; }}
.kpi {{ display: inline-block; margin-right: 18px; padding: 8px 14px; border-radius: 8px; background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
.kpi b {{ color: {branding.primary_color}; }}
.footer {{ margin-top: 30px; color: #666; font-size: 12px; text-align: center; }}
</style></head><body>
<h1>📚 History Report</h1>
<p><strong>Generated:</strong> {_esc(generated)}</p>

<h2>🛡️ Vulnerabilities</h2>
<div>
  <span class="kpi"><b>{vuln_stats.get('total_vulnerabilities', 0)}</b> total</span>
  <span class="kpi"><b>{vuln_stats.get('open_vulnerabilities', 0)}</b> open</span>
  <span class="kpi"><b>{vuln_stats.get('resolved_vulnerabilities', 0)}</b> resolved</span>
  <span class="kpi"><b>{vuln_stats.get('critical_count', 0)}</b> critical</span>
  <span class="kpi"><b>{vuln_stats.get('high_count', 0)}</b> high</span>
  <span class="kpi"><b>{vuln_stats.get('packages_affected', 0)}</b> packages affected</span>
  <span class="kpi"><b>{vuln_stats.get('persistent_vulnerabilities', 0)}</b> persistent</span>
</div>

<h2>📈 Trends — last {trends.get('period_days', 30)} day(s)</h2>
<p>Unique packages tracked: <b>{trends.get('unique_packages', 0)}</b></p>
<table><thead><tr><th>Source</th><th>Scans</th><th>Packages</th><th>Updates</th></tr></thead>
<tbody>{trend_rows or '<tr><td colspan="4">No data.</td></tr>'}</tbody></table>

<h2>🕰️ Stale packages (>90d)</h2>
<table><thead><tr><th>Package</th><th>Source</th><th>Last seen</th></tr></thead>
<tbody>{stale_rows or '<tr><td colspan="3">None.</td></tr>'}</tbody></table>

<h2>📜 Recent scans</h2>
<table><thead><tr><th>Timestamp</th><th>Source</th><th>Pkgs</th><th>Updates</th><th>Vulns</th></tr></thead>
<tbody>{scan_rows or '<tr><td colspan="5">No scans recorded.</td></tr>'}</tbody></table>

<div class="footer"><p>{_esc(branding.footer_text)}</p></div>
</body></html>"""


__all__ = ['SystemUpdateApp']
