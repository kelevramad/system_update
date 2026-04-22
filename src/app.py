"""Main application for system_update."""

import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from .cache import CacheManager, HistoryDatabase, VulnerabilityHistory
from .checkers import UpdateChecker
from .config import SystemConfig
from .models import AppInfo, UpdateStatus
from .notifications import NotificationManager
from .scanners import PackageScanner
from .ui import UISystem
from .security import SecurityChecker
from .utils import source_badge
from rich.console import Console
from rich.progress import (
	BarColumn,
	MofNCompleteColumn,
	Progress,
	TextColumn,
	TimeElapsedColumn,
)


console = Console()


class SystemUpdateApp:
	"""Main application controller."""

	def __init__(self, config: SystemConfig):
		"""Initialize SystemUpdateApp."""
		self.config = config
		self.settings = config.settings
		self.scanner = PackageScanner()
		self.checker = UpdateChecker()
		self.cache_mgr = CacheManager(config.cache_file, config.settings['cache']['duration_hours'])
		self.notifier = NotificationManager(config)
		self.history_db = HistoryDatabase(Path(config.config_dir) / 'history.db')
		self.vuln_history = VulnerabilityHistory(
			Path(config.config_dir) / 'vulnerability_history.json'
		)

	def __del__(self):
		"""Close database connections."""
		if hasattr(self, 'history_db') and self.history_db:
			self.history_db.close()

	def scan_system(self, source_filter: Optional[str] = None) -> List[AppInfo]:
		"""Perform comprehensive system scan."""
		scanners = {
			'winget': self.scanner.scan_winget,
			'chocolatey': self.scanner.scan_chocolatey,
			'npm': self.scanner.scan_npm,
			'pnpm': self.scanner.scan_pnpm,
			'bun': self.scanner.scan_bun,
			'yarn': self.scanner.scan_yarn,
			'pip': self.scanner.scan_pip,
			'path': self.scanner.scan_path,
			'registry': self.scanner.scan_registry,
			'rust': self.scanner.scan_rust,
			'scoop': self.scanner.scan_scoop,
			'dotnet': self.scanner.scan_dotnet,
			'appx': self.scanner.scan_appx,
			'msix': self.scanner.scan_msix,
		}

		aliases = {'choco': 'chocolatey'}
		include_sources = set()
		if source_filter and source_filter.strip():
			for item in source_filter.split(','):
				item = item.strip().lower()
				if item:
					include_sources.add(aliases.get(item, item))
		elif hasattr(self, '_include_sources') and self._include_sources:
			include_sources.update(self._include_sources)
		if include_sources:
			scanners = {name: func for name, func in scanners.items() if name in include_sources}

		selected = [
			(name, func)
			for name, func in scanners.items()
			if self.config.settings['sources'].get(name, True)
		]

		all_apps = []
		max_workers = self.config.settings['performance']['max_workers']

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
			source_tasks = {}
			for name, func in selected:
				source_tasks[name] = progress.add_task(
					f'🔎 {source_badge(name)}',
					total=1,
				)

			with ThreadPoolExecutor(max_workers=max_workers) as executor:
				future_to_source = {executor.submit(func): name for name, func in selected}

				for future in as_completed(future_to_source):
					source_name = future_to_source[future]
					try:
						apps = future.result()
						unique_apps = list(
							{f'{a.source}|{a.name}|{a.version}'.lower(): a for a in apps}.values()
						)
						all_apps.extend(unique_apps)
						emoji = '✓' if len(unique_apps) == 0 else '✅'
						progress.update(
							source_tasks[source_name],
							completed=1,
							description=f'{emoji} {source_badge(source_name)} [{len(unique_apps)}]',
						)
					except Exception as e:
						progress.update(
							source_tasks[source_name],
							completed=1,
							description=f'❌ {source_badge(source_name)} error',
						)
						console.print(f'  [red]✗[/red] {source_name}: {e}')

		return sorted(all_apps, key=lambda x: f'{x.source}{x.name}')

	def check_security(self, apps: List[AppInfo]) -> List:
		"""Check vulnerabilities for apps."""
		security_vulns = []
		unique_apps_by_source = {}
		for app in apps:
			src = app.source.lower()
			if src not in unique_apps_by_source:
				unique_apps_by_source[src] = []
			unique_apps_by_source[src].append(app)

		security_sources = ['npm', 'pip', 'osv', 'github']
		active_security = [
			(name, unique_apps_by_source.get(name, []))
			for name in security_sources
			if unique_apps_by_source.get(name, [])
		]

		local_advisories = {}
		local_advisory_file = os.path.join(
			os.path.expanduser('~'), '.system_update', 'advisories.json'
		)
		if os.path.isfile(local_advisory_file):
			local_advisories = self.load_local_advisories(local_advisory_file)
		if local_advisories:
			local_apps = [app for apps_list in unique_apps_by_source.values() for app in apps_list]
			if local_apps:
				active_security.append(('local', local_apps))

		if 'pip' in unique_apps_by_source:
			active_security.append(('pypi', unique_apps_by_source['pip']))

		with Progress(
			TextColumn('{task.description}'),
			BarColumn(
				bar_width=16,
				complete_style='red',
				style='dim red',
				finished_style='red',
			),
			MofNCompleteColumn(),
			TimeElapsedColumn(),
			console=console,
		) as progress:
			source_tasks = {}
			for name, apps_list in active_security:
				source_tasks[name] = progress.add_task(
					f'🔒 {name}',
					total=1,
				)

			for source_name, source_apps in active_security:
				source_vulns = []
				try:
					if source_name == 'npm':
						source_vulns = SecurityChecker.check_npm_vulns(source_apps)
					elif source_name == 'pip':
						source_vulns = SecurityChecker.check_pip_vulns(source_apps)
					elif source_name == 'pypi':
						source_vulns = SecurityChecker.check_pypi_json_vulnerabilities(source_apps)
					elif source_name == 'osv':
						source_vulns = SecurityChecker.check_osv_vulnerabilities(source_apps)
					elif source_name == 'github':
						source_vulns = SecurityChecker.check_github_advisory_vulnerabilities(
							source_apps
						)
					elif source_name == 'local':
						source_vulns = self.check_local_advisory_vulnerabilities(
							source_apps, local_advisories
						)
				except Exception:
					pass

				security_vulns.extend(source_vulns)

				if source_vulns:
					progress.update(
						source_tasks[source_name],
						completed=1,
						description=f'🔥 {source_name} [{len(source_vulns)}]',
					)
				else:
					progress.update(
						source_tasks[source_name],
						completed=1,
						description=f'✓ {source_name} [0]',
					)

		return security_vulns

	def load_local_advisories(self, file_path: str) -> dict:
		"""Load local advisory data from a JSON file."""
		import json

		if not os.path.isfile(file_path):
			return {}

		try:
			with open(file_path, 'r', encoding='utf-8') as f:
				data = json.load(f)
			return data
		except Exception:
			return {}

	def check_local_advisory_vulnerabilities(
		self, apps: List[AppInfo], local_data: dict
	) -> List[dict]:
		"""Check vulnerabilities against loaded local advisory data."""
		vulns = []
		advisories = local_data.get('advisories', [])
		unique_apps = {a.name.lower(): a for a in apps}

		for adv in advisories:
			pkg_name = adv.get('package', '').lower()
			app = unique_apps.get(pkg_name)
			if not app:
				continue

			item = {
				'package': adv.get('package', ''),
				'severity': (adv.get('severity') or 'MEDIUM').upper(),
				'cvss_score': adv.get('cvss_score'),
				'cve': adv.get('cve', 'N/A'),
				'description': adv.get('description', '')[:200],
				'source': adv.get('source', 'Local'),
				'affected_versions': adv.get('affected_versions', []),
				'published_date': adv.get('published_date', ''),
				'advisory_url': adv.get('advisory_url', ''),
				'fix_available': adv.get('fix_available', False),
			}
			app.security_findings.append(item)
			app.update_status = UpdateStatus.VULNERABLE
			vulns.append(item)

		return vulns

	def run(self, args):
		"""Main application entry point."""
		from src.config import setup_logging
		from src.executor import UpdateExecutor
		from rich.prompt import Confirm
		import json

		setup_logging(
			debug=getattr(args, 'debug', False),
			enable_log=getattr(args, 'log', False),
			log_file=self.config.log_file,
			config_dir=self.config.config_dir,
		)

		ui_theme = getattr(args, 'theme', None) or self.settings['ui'].get('theme', 'default')
		if ui_theme:
			self.settings['ui']['theme'] = ui_theme
		display_format = getattr(args, 'format', None) or self.settings['ui'].get(
			'display_format', 'auto'
		)
		if display_format:
			self.settings['ui']['display_format'] = display_format
		use_icons = getattr(args, 'icons', False) or self.settings['ui'].get('use_icons', False)
		if use_icons:
			self.settings['ui']['use_icons'] = True

		if args.clear_cache:
			self.cache_mgr.clear()
			console.print('[green]🗑️  Cache cleared successfully![/green]')
			return

		UISystem.display_banner(self.config.config_dir)
		self._include_sources = set()

		if getattr(args, 'source', None):
			aliases = {'choco': 'chocolatey'}
			self._include_sources = {
				aliases.get(item.strip().lower(), item.strip().lower())
				for item in args.source.split(',')
				if item.strip()
			}
 
	apps = None
	cached_sources = None
	all_apps = None
	missing_sources = None
	original_cached_sources = None
	had_partial_scan = False
	loaded_from_cache = False
	apps_to_cache = None
	
	if not args.no_cache and self.config.settings['cache']['enabled']:
		all_apps, cached_sources = self.cache_mgr.load()
		original_cached_sources = cached_sources
		if all_apps is not None and all_apps:
			loaded_from_cache = True
			requested_sources = {s.lower() for s in (self._include_sources or set())}
			cached_set = {s.lower() for s in cached_sources} if cached_sources else set()
			needs_full_scan = False
			
			if not requested_sources and cached_set:
				missing_sources = set()
			elif requested_sources and not cached_set:
				missing_sources = requested_sources
			elif requested_sources and cached_set:
				missing_sources = requested_sources - cached_set
			
			if missing_sources:
				had_partial_scan = True
				console.print('[bold cyan]🔎 Scanning sources...[/bold cyan]')
				console.print(
					f'[dim]💾 Cache has some sources. Scanning missing: {sorted(missing_sources)}[/dim]\n'
				)
				start_time = time.time()
				new_apps = self.scan_system(','.join(missing_sources))
				console.print(
					f'\n📦 [bold]Discovered {len(new_apps)} new apps from {sorted(missing_sources)}.[/bold]'
				)
				console.print('[bold cyan]🔄 Checking for updates...[/bold cyan]')
				self.checker.check_all_updates(new_apps)
				all_apps.extend(new_apps)
				apps = all_apps
				apps_to_cache = all_apps
				console.print(
					f'[dim]💾 Combined cache with new sources ({len(apps)} total apps)[/dim]\n'
				)
			elif not needs_full_scan:
				apps = all_apps
				apps_to_cache = all_apps
				src_desc = cached_sources if cached_sources else 'all sources'
				console.print(
					f'[dim]💾 Loaded {len(apps)} items from cache (sources: {src_desc})[/dim]\n'
				)
			else:
				apps = None
	
	if apps is not None and self._include_sources:
		apps = [
			a for a in apps if a.source.lower() in [s.lower() for s in self._include_sources]
		]
	
	if apps is None or (not apps and apps_to_cache is None):
		start_time = time.time()
		console.print('[bold cyan]🔎 Scanning sources...[/bold cyan]')
		apps = self.scan_system(args.source)
		apps_to_cache = apps

regular_updates = sum(
1 for a in apps if a.update_status == UpdateStatus.UPDATE_AVAILABLE
)
security_updates = sum(
1 for a in apps if a.update_status == UpdateStatus.VULNERABLE and a.latest_version
)
		total_updates = regular_updates + security_updates
		if security_updates > 0:
		console.print(
		f'[bold magenta]📊 Detected {security_updates} security updates (urgent).[/bold magenta]'
		)
		else:
		console.print(
		f'[bold magenta]📊 Detected {total_updates} update candidates.[/bold magenta]\n'
		)
		console.print('[bold magenta]🔒 Checking security vulnerabilities...[/bold magenta]')
		security_vulns = self.check_security(apps)
		if security_vulns:
		console.print(
		f'[bold red]🔥 Found {len(security_vulns)} security vulnerabilities.[/bold red]\n'
				)
			else:
				console.print('[bold green]🛡️ No security vulnerabilities found.[/bold green]\n')

			for app in apps:
				if app.is_vulnerable and not app.latest_version:
					try:
						import urllib.request

						url = f'https://pypi.org/pypi/{app.name}/json'
						req = urllib.request.Request(url, headers={'User-Agent': 'SystemUpdateCLI'})
						with urllib.request.urlopen(req, timeout=10) as response:
							data = json.loads(response.read().decode())
							if 'info' in data:
								app.latest_version = data['info'].get('version', '')
					except Exception:
						pass

			scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
			for app in apps:
				if app.security_findings:
					for finding in app.security_findings:
						self.vuln_history.record_vulnerability(app, finding, scan_id)

			scanned_sources = (
				args.source
				if args.source
				else ','.join(
					s
					for s in self.config.settings['sources']
					if self.config.settings['sources'].get(s, True)
				)
			)
			scan_time = time.time() - start_time
			self.history_db.record_scan(apps, scan_id, scanned_sources, scan_time)

			current_stats = UISystem.compute_security_stats(security_vulns)
			UISystem.display_security_summary(current_stats)

			regular = sum(1 for a in apps if a.update_status == UpdateStatus.UPDATE_AVAILABLE)
			security = sum(
				1 for a in apps if a.update_status == UpdateStatus.VULNERABLE and a.latest_version
			)
			total_updates = regular + security

			sources_to_save = set()
			cache_apps = apps_to_cache if apps_to_cache else apps
			for app in cache_apps:
				src = app.source.lower()
				sources_to_save.add(src)
 			if (had_partial_scan or loaded_from_cache) and original_cached_sources:
 				for src in original_cached_sources:
 					sources_to_save.add(src.lower())
 			self.cache_mgr.save(cache_apps, sorted(sources_to_save))
		else:
			regular = sum(1 for a in apps if a.update_status == UpdateStatus.UPDATE_AVAILABLE)
			security = sum(
				1 for a in apps if a.update_status == UpdateStatus.VULNERABLE and a.latest_version
			)
			total_updates = regular + security
			scan_time = 0.0

			sources_to_save = set()
			cache_apps = apps_to_cache if apps_to_cache else apps
			for app in cache_apps:
				src = app.source.lower()
				sources_to_save.add(src)
 		if loaded_from_cache and original_cached_sources:
 			for src in original_cached_sources:
 				sources_to_save.add(src.lower())
 		self.cache_mgr.save(cache_apps, sorted(sources_to_save))

		sources_count = {}
		for app in apps:
			sources_count[app.source] = sources_count.get(app.source, 0) + 1

		UISystem.display_summary(
			len(apps), total_updates, scan_time, sources_count, show_all=args.show_all
		)

		if args.package:
			self._handle_single_update(apps, args)
			return

		updates = [a for a in apps if a.update_status == UpdateStatus.UPDATE_AVAILABLE]
		vulnerable = [a for a in apps if a.update_status == UpdateStatus.VULNERABLE]

		console.print()
		apps_table = UISystem.create_apps_table(
			apps,
			show_all=args.show_all,
			theme=self.settings['ui'].get('theme', 'default'),
			use_icons=self.settings['ui'].get('use_icons', False),
		)
		console.print(apps_table)

		if args.show_all:
			console.print('\n[dim]💾 Showing: all packages[/dim]')
		else:
			console.print('\n[dim]💾 Showing: updates only[/dim]')

		if updates or vulnerable:
			total_count = len(updates) + len(vulnerable)
			console.print(f'\n[bold yellow]🎯 Found {total_count} available updates[/bold yellow]')

			if getattr(args, 'notify', False):
				self.notifier.notify_updates_available(total_count, len(vulnerable), force=True)

			if args.update_all:
				security_updates = [
					a for a in updates if a.update_status == UpdateStatus.VULNERABLE
				]
				regular_updates = [a for a in updates if a.update_status != UpdateStatus.VULNERABLE]

				if security_updates:
					console.print(
						f'\n[bold red]🔒 Priority: Updating {len(security_updates)} vulnerable package(s) first...[/bold red]'
					)
					if args.yes or Confirm.ask('🚀 Proceed with security updates?'):
						UpdateExecutor.execute_updates(security_updates, args.dry_run)
					else:
						return

				if regular_updates:
					console.print(
						f'\n[bold yellow]⚡ Now updating {len(regular_updates)} regular package(s)...[/bold yellow]'
					)
					if args.yes or Confirm.ask('🚀 Proceed with remaining updates?') or args.yes:
						UpdateExecutor.execute_updates(regular_updates, args.dry_run)
		else:
			console.print('\n[green]✨ System is up to date![/green]')

		if vulnerable:
			console.print()
			console.print('[bold red]👮🏻‍♂️ Security Vulnerabilities Detected:[/bold red]\n')
			for app in vulnerable:
				for finding in app.security_findings:
					cvss_val = finding.get('cvss_score')
					cvss_display = f'{cvss_val:.1f}' if isinstance(cvss_val, (int, float)) else '-'
					sev = finding.get('severity', 'UNKNOWN')
					cve = finding.get('cve', 'N/A')
					desc = finding.get('description', '')
					if desc:
						desc = f' - {desc}'
					else:
						desc = ''
					console.print(
						f'[bold red]🔥[/bold red] {app.name} - {sev} (CVSS: {cvss_display}): {cve}{desc}\n'
					)

		if getattr(args, 'export', None):
			self.export_results(apps, args.export, args.output)

	def _handle_single_update(self, apps: List[AppInfo], args):
		"""Handle single package update request."""
		from src.executor import UpdateExecutor
		from rich.prompt import Confirm

		target_name = args.package.lower()
		target_source = args.source.lower() if args.source else None

		candidates = [
			app
			for app in apps
			if app.name.lower() == target_name
			and (not target_source or app.source.lower() == target_source)
		]

		if not candidates:
			console.print(f"[red]❌ Package '{args.package}' not found[/red]")
			return

		if len(candidates) > 1 and not args.source:
			console.print('[yellow]⚠️  Multiple packages found:[/yellow]')
			for i, c in enumerate(candidates):
				console.print(f'  {i + 1}. {c.name} ({c.source}) - {c.version}')
			console.print('[yellow]💡 Please specify --source to target one[/yellow]')
			return

		target_app = candidates[0]

		if args.version:
			target_app.latest_version = args.version
			console.print(f'[cyan]🎯 Targeting version: {args.version}[/cyan]')
		elif not target_app.has_update and not args.version:
			console.print(
				f'[green]✅ {target_app.name} is up to date ({target_app.version})[/green]'
			)
			if not (args.yes or Confirm.ask('🔄 Force reinstall?')):
				return

		UpdateExecutor.execute_updates([target_app], args.dry_run)

	def export_results(self, apps: List[AppInfo], format_type: str, output_file: Optional[str]):
		"""Export scan results in various formats.

		format_type: Export format ("json", "csv", "html", "xml", "markdown", or "diff").
		output_file: Optional output filename. If None, generates filename
		    with timestamp (e.g., "system_update_20240101_120000.json").

		Formats:
		    - json: Full application data with all fields in JSON format
		    - csv: Tabular data with Name, Source, Version, Latest, Status columns
		    - html: Styled HTML report with tables and status indicators
		    - xml: Enterprise-compatible XML format
		    - markdown: GitHub-compatible markdown tables
		    - diff: Line-by-line version changes
		"""
		import csv
		import json

		if not output_file:
			timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
			ext_map = {'markdown': 'md'}
			ext = ext_map.get(format_type, format_type)
			output_file = f'system_update_{timestamp}.{ext}'

		try:
			if format_type == 'json':
				stats = self._get_export_stats(apps)
				sec_stats = {
					'critical': sum(
						1
						for a in apps
						for f in a.security_findings
						if f.get('severity') == 'CRITICAL'
					),
					'high': sum(
						1 for a in apps for f in a.security_findings if f.get('severity') == 'HIGH'
					),
					'medium': sum(
						1
						for a in apps
						for f in a.security_findings
						if f.get('severity') == 'MEDIUM'
					),
					'low': sum(
						1 for a in apps for f in a.security_findings if f.get('severity') == 'LOW'
					),
				}
				data = {
					'scan_time': datetime.now().isoformat(),
					'summary': {
						'total_apps': len(apps),
						'up_to_date': stats['up_to_date'],
						'update_available': stats['update_available'],
						'vulnerable': stats['vulnerable'],
						'unknown': stats['unknown'],
					},
					'security_summary': {
						'total_vulns': sum(len(a.security_findings) for a in apps),
						'packages_affected': len([a for a in apps if a.security_findings]),
						'critical': sec_stats['critical'],
						'high': sec_stats['high'],
						'medium': sec_stats['medium'],
						'low': sec_stats['low'],
					},
					'sources': stats['source_counts'],
					'apps': [app.to_dict() for app in apps],
				}
				with open(output_file, 'w', encoding='utf-8') as f:
					json.dump(data, f, indent=2)

			elif format_type == 'csv':
				stats = self._get_export_stats(apps)
				with open(output_file, 'w', newline='', encoding='utf-8') as f:
					writer = csv.writer(f)
					writer.writerow(['Name', 'Source', 'Version', 'Latest', 'Status'])
					for app in apps:
						writer.writerow(
							[
								app.name,
								app.source,
								app.version,
								app.latest_version,
								app.update_status.value,
							]
						)
					if [a for a in apps if a.security_findings]:
						writer.writerow([])
						writer.writerow(['Security Vulnerabilities Detected'])
						writer.writerow(['Package', 'Source', 'Version', 'CVE', 'Severity'])
						for app in apps:
							for finding in app.security_findings:
								writer.writerow(
									[
										app.name,
										app.source,
										app.version,
										finding.get('cve', 'N/A'),
										finding.get('severity', 'UNKNOWN'),
									]
								)
					sec_stats = {
						'critical': sum(
							1
							for a in apps
							for f in a.security_findings
							if f.get('severity') == 'CRITICAL'
						),
						'high': sum(
							1
							for a in apps
							for f in a.security_findings
							if f.get('severity') == 'HIGH'
						),
						'medium': sum(
							1
							for a in apps
							for f in a.security_findings
							if f.get('severity') == 'MEDIUM'
						),
						'low': sum(
							1
							for a in apps
							for f in a.security_findings
							if f.get('severity') == 'LOW'
						),
					}
					if (
						sec_stats['critical']
						or sec_stats['high']
						or sec_stats['medium']
						or sec_stats['low']
					):
						writer.writerow([])
						writer.writerow(['Security Summary'])
						writer.writerow(['Critical', sec_stats['critical']])
						writer.writerow(['High', sec_stats['high']])
						writer.writerow(['Medium', sec_stats['medium']])
						writer.writerow(['Low', sec_stats['low']])
					writer.writerow([])
					writer.writerow(['Sources'])
					for src, cnt in sorted(stats['source_counts'].items()):
						writer.writerow([src, cnt])

			elif format_type == 'html':
				self._export_html(apps, output_file)

			elif format_type == 'xml':
				self._export_xml(apps, output_file)

			elif format_type in ('markdown', 'md'):
				self._export_markdown(apps, output_file)

			elif format_type == 'diff':
				self._export_diff(apps, output_file)

			console.print(f'[green]✅ Exported to {output_file}[/green]')

		except Exception as e:
			console.print(f'[red]❌ Export failed: {e}[/red]')

	def _export_html(self, apps: List[AppInfo], output_file: str):
		"""Export results as styled HTML report."""
		scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
		stats = self._get_export_stats(apps)

		status_class_map = {
			UpdateStatus.UP_TO_DATE: 'status-up-to-date',
			UpdateStatus.UPDATE_AVAILABLE: 'status-update',
			UpdateStatus.SECURITY_UPDATE_AVAILABLE: 'status-update',
			UpdateStatus.VULNERABLE: 'status-vulnerable',
			UpdateStatus.UNKNOWN: 'status-unknown',
			UpdateStatus.ERROR: 'status-error',
		}

		html = [
			'<!DOCTYPE html>',
			'<html lang="en">',
			'<head>',
			'    <meta charset="UTF-8">',
			'    <meta name="viewport" content="width=device-width, initial-scale=1.0">',
			f'    <title>System Update Report - {scan_time}</title>',
			'    <style>',
			'        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: #f5f5f5; }',
			'        h1 { color: #333; border-bottom: 2px solid #0066cc; padding-bottom: 10px; }',
			'        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }',
			'        .stat { background: white; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }',
			'        .stat-value { font-size: 24px; font-weight: bold; }',
			'        .stat-label { color: #666; font-size: 14px; margin-top: 5px; }',
			'        .up-to-date { color: #28a745; }',
			'        .update-available { color: #ffc107; }',
			'        .vulnerable { color: #dc3545; }',
			'        .unknown { color: #6c757d; }',
			'        table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }',
			'        th { background: #0066cc; color: white; padding: 12px; text-align: left; }',
			'        td { padding: 10px 12px; border-bottom: 1px solid #eee; }',
			'        tr:hover { background: #f8f9fa; }',
			'        .status { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500; }',
			'        .status-up-to-date { background: #d4edda; color: #155724; }',
			'        .status-update { background: #fff3cd; color: #856404; }',
			'        .status-vulnerable { background: #f8d7da; color: #721c24; }',
			'        .status-unknown { background: #e2e3e5; color: #383d41; }',
			'        .status-error { background: #f8d7da; color: #721c24; }',
			'        .footer { margin-top: 20px; color: #666; font-size: 12px; text-align: center; }',
			'    </style>',
			'</head>',
			'<body>',
			'    <h1>System Update Report</h1>',
			f'    <p><strong>Generated:</strong> {scan_time}</p>',
			'    <div class="summary">',
			f'        <div class="stat"><div class="stat-value">{stats["total"]}</div><div class="stat-label">Total Packages</div></div>',
			f'        <div class="stat"><div class="stat-value up-to-date">{stats["up_to_date"]}</div><div class="stat-label">Up to Date</div></div>',
			f'        <div class="stat"><div class="stat-value update-available">{stats["update_available"]}</div><div class="stat-label">Updates Available</div></div>',
			f'        <div class="stat"><div class="stat-value vulnerable">{stats["vulnerable"]}</div><div class="stat-label">Vulnerable</div></div>',
			f'        <div class="stat"><div class="stat-value unknown">{stats["unknown"]}</div><div class="stat-label">Unknown</div></div>',
			'    </div>',
			'    <table>',
			'        <thead>',
			'            <tr>',
			'                <th>Package</th><th>Source</th><th>Current Version</th><th>Latest Version</th><th>Status</th>',
			'            </tr>',
			'        </thead>',
			'        <tbody>',
		]

		for app in apps:
			status_class = status_class_map.get(app.update_status, 'status-unknown')
			status_text = (
				app.status_display.split(' ')[0]
				if ' ' in app.status_display
				else app.update_status.value
			)
			html.append(
				f'            <tr>'
				f'<td><strong>{app.name}</strong></td>'
				f'<td>{app.source}</td>'
				f'<td>{app.version or "-"}</td>'
				f'<td>{app.latest_version or "-"}</td>'
				f'<td><span class="status {status_class}">{status_text}</span></td>'
				f'</tr>'
			)

		html.extend(
			[
				'        </tbody>',
				'    </table>',
			]
		)

		vuln_apps = [app for app in apps if app.security_findings]
		if vuln_apps or stats['vulnerable'] > 0:
			html.extend(
				[
					'',
					'    <h2>Security Vulnerabilities Detected</h2>',
					'    <table>',
					'        <thead>',
					'            <tr>',
					'                <th>Package</th><th>Source</th><th>Version</th><th>CVE</th><th>Severity</th><th>Description</th>',
				]
			)
			for app in vuln_apps:
				for finding in app.security_findings:
					desc = self._html_escape(finding.get('description', '-'))
					html.append(
						f'            <tr>'
						f'<td><strong>{app.name}</strong></td>'
						f'<td>{app.source}</td>'
						f'<td>{app.version}</td>'
						f'<td>{finding.get("cve", "N/A")}</td>'
						f'<td><span class="status status-vulnerable">{finding.get("severity", "UNKNOWN")}</span></td>'
						f'<td>{desc}</td>'
						f'</tr>'
					)
			html.extend(['        </tbody>', '    </table>'])

		sec_stats = {
			'critical': sum(
				1 for a in apps for f in a.security_findings if f.get('severity') == 'CRITICAL'
			),
			'high': sum(
				1 for a in apps for f in a.security_findings if f.get('severity') == 'HIGH'
			),
			'medium': sum(
				1 for a in apps for f in a.security_findings if f.get('severity') == 'MEDIUM'
			),
			'low': sum(1 for a in apps for f in a.security_findings if f.get('severity') == 'LOW'),
		}
		vuln_count = sum(len(a.security_findings) for a in apps)
		packages_affected = len([a for a in apps if a.security_findings])

		if sec_stats['critical'] or sec_stats['high'] or sec_stats['medium'] or sec_stats['low']:
			html.extend(
				[
					'',
					'    <h2>Security Summary</h2>',
					'    <div class="summary">',
					f'        <div class="stat"><div class="stat-value">{vuln_count}</div><div class="stat-label">Total Vulns</div></div>',
					f'        <div class="stat"><div class="stat-value">{packages_affected}</div><div class="stat-label">Packages Affected</div></div>',
					f'        <div class="stat"><div class="stat-value">{sec_stats["critical"]}</div><div class="stat-label">Critical</div></div>',
					f'        <div class="stat"><div class="stat-value vulnerable">{sec_stats["high"]}</div><div class="stat-label">High</div></div>',
					f'        <div class="stat"><div class="stat-value update-available">{sec_stats["medium"]}</div><div class="stat-label">Medium</div></div>',
					f'        <div class="stat"><div class="stat-value unknown">{sec_stats["low"]}</div><div class="stat-label">Low</div></div>',
					'    </div>',
				]
			)

		if stats['source_counts']:
			source_parts = [f'{src}:{cnt}' for src, cnt in sorted(stats['source_counts'].items())]
			html.extend(
				[
					'',
					'    <h2>Sources</h2>',
					f'    <p><strong>Sources:</strong> {", ".join(source_parts)}</p>',
				]
			)

		html.extend(
			[
				'    <div class="footer"><p>Generated by System Update CLI</p></div>',
				'</body>',
				'</html>',
			]
		)

		with open(output_file, 'w', encoding='utf-8') as f:
			f.write('\n'.join(html))

	def _export_xml(self, apps: List[AppInfo], output_file: str):
		"""Export results as XML format."""
		scan_time = datetime.now().isoformat()
		stats = self._get_export_stats(apps)

		xml_lines = ['<?xml version="1.0" encoding="UTF-8"?>']
		xml_lines.append('<system_update>')
		xml_lines.append(f'  <scan_time>{scan_time}</scan_time>')
		xml_lines.append(f'  <total_packages>{len(apps)}</total_packages>')
		xml_lines.append('  <packages>')

		for app in apps:
			xml_lines.append('    <package>')
			xml_lines.append(f'      <name>{self._xml_escape(app.name)}</name>')
			xml_lines.append(f'      <source>{self._xml_escape(app.source)}</source>')
			xml_lines.append(
				f'      <current_version>{self._xml_escape(app.version or "-")}</current_version>'
			)
			xml_lines.append(
				f'      <latest_version>{self._xml_escape(app.latest_version or "-")}</latest_version>'
			)
			xml_lines.append(f'      <status>{app.update_status.value}</status>')
			if app.app_id:
				xml_lines.append(f'      <app_id>{self._xml_escape(app.app_id)}</app_id>')
			if app.security_findings:
				xml_lines.append('      <vulnerabilities>')
				for finding in app.security_findings:
					xml_lines.append('        <vulnerability>')
					xml_lines.append(
						f'          <cve>{self._xml_escape(finding.get("cve", "N/A"))}</cve>'
					)
					xml_lines.append(
						f'          <severity>{self._xml_escape(finding.get("severity", "UNKNOWN"))}</severity>'
					)
					xml_lines.append(
						f'          <description>{self._xml_escape(finding.get("description", "-"))}</description>'
					)
					xml_lines.append('        </vulnerability>')
				xml_lines.append('      </vulnerabilities>')
			xml_lines.append('    </package>')

		xml_lines.append('  </packages>')

		vuln_apps = [app for app in apps if app.security_findings]
		if vuln_apps or stats['vulnerable'] > 0:
			xml_lines.append('  <security_vulnerabilities>')
			for app in vuln_apps:
				for finding in app.security_findings:
					xml_lines.append('    <vulnerability>')
					xml_lines.append(f'      <package>{self._xml_escape(app.name)}</package>')
					xml_lines.append(f'      <source>{self._xml_escape(app.source)}</source>')
					xml_lines.append(f'      <version>{self._xml_escape(app.version)}</version>')
					xml_lines.append(
						f'      <cve>{self._xml_escape(finding.get("cve", "N/A"))}</cve>'
					)
					xml_lines.append(
						f'      <severity>{self._xml_escape(finding.get("severity", "UNKNOWN"))}</severity>'
					)
					xml_lines.append(
						f'      <description>{self._xml_escape(finding.get("description", "-"))}</description>'
					)
					xml_lines.append('    </vulnerability>')
			xml_lines.append('  </security_vulnerabilities>')

		sec_stats = {
			'critical': sum(
				1 for a in apps for f in a.security_findings if f.get('severity') == 'CRITICAL'
			),
			'high': sum(
				1 for a in apps for f in a.security_findings if f.get('severity') == 'HIGH'
			),
			'medium': sum(
				1 for a in apps for f in a.security_findings if f.get('severity') == 'MEDIUM'
			),
			'low': sum(1 for a in apps for f in a.security_findings if f.get('severity') == 'LOW'),
		}
		vuln_count = sum(len(a.security_findings) for a in apps)
		packages_affected = len([a for a in apps if a.security_findings])

		if sec_stats['critical'] or sec_stats['high'] or sec_stats['medium'] or sec_stats['low']:
			xml_lines.append('  <security_summary>')
			xml_lines.append(f'    <total_vulns>{vuln_count}</total_vulns>')
			xml_lines.append(f'    <packages_affected>{packages_affected}</packages_affected>')
			xml_lines.append(f'    <critical>{sec_stats["critical"]}</critical>')
			xml_lines.append(f'    <high>{sec_stats["high"]}</high>')
			xml_lines.append(f'    <medium>{sec_stats["medium"]}</medium>')
			xml_lines.append(f'    <low>{sec_stats["low"]}</low>')
			xml_lines.append('  </security_summary>')

		if stats['source_counts']:
			xml_lines.append('  <sources>')
			for src, cnt in sorted(stats['source_counts'].items()):
				xml_lines.append(f'    <source name="{self._xml_escape(src)}">{cnt}</source>')
			xml_lines.append('  </sources>')

		xml_lines.append('</system_update>')

		with open(output_file, 'w', encoding='utf-8') as f:
			f.write('\n'.join(xml_lines))

	def _export_markdown(self, apps: List[AppInfo], output_file: str):
		"""Export results as GitHub-compatible markdown."""
		scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
		stats = self._get_export_stats(apps)

		md_lines = [
			'# System Update Report',
			'',
			f'**Generated:** {scan_time}',
			'',
			'## Summary',
			'',
			'| Total | Up to Date | Updates | Vulnerable | Unknown |',
			'|------:|----------:|-------:|----------:|--------:|',
			f'| {stats["total"]} | {stats["up_to_date"]} | {stats["update_available"]} | {stats["vulnerable"]} | {stats["unknown"]} |',
			'',
			'## Packages',
			'',
			'| Package | Source | Version | Latest | Status |',
			'|--------|--------|--------|--------|--------|',
		]

		for app in apps:
			status_icon = {
				UpdateStatus.UP_TO_DATE: '',
				UpdateStatus.UPDATE_AVAILABLE: '',
				UpdateStatus.SECURITY_UPDATE_AVAILABLE: '',
				UpdateStatus.VULNERABLE: '',
				UpdateStatus.UNKNOWN: '',
				UpdateStatus.ERROR: '',
			}.get(app.update_status, '')

			md_lines.append(
				f'| {app.name} | {app.source} | {app.version or "-"} | '
				f'{app.latest_version or "-"} | {status_icon} {app.update_status.value} |'
			)

		vuln_apps = [app for app in apps if app.security_findings]
		if vuln_apps or stats['vulnerable'] > 0:
			md_lines.extend(
				[
					'',
					'## Security Vulnerabilities Detected',
					'',
					'| Package | Source | Version | CVE | Severity | Description |',
					'|--------|--------|--------|-----|-----------|------------|',
				]
			)
			for app in vuln_apps:
				for finding in app.security_findings:
					desc = finding.get('description', '-')
					md_lines.append(
						f'| {app.name} | {app.source} | {app.version} | '
						f'{finding.get("cve", "N/A")} | {finding.get("severity", "UNKNOWN")} | {desc} |'
					)

		sec_stats = {
			'critical': sum(
				1 for a in apps for f in a.security_findings if f.get('severity') == 'CRITICAL'
			),
			'high': sum(
				1 for a in apps for f in a.security_findings if f.get('severity') == 'HIGH'
			),
			'medium': sum(
				1 for a in apps for f in a.security_findings if f.get('severity') == 'MEDIUM'
			),
			'low': sum(1 for a in apps for f in a.security_findings if f.get('severity') == 'LOW'),
		}
		vuln_count = sum(len(a.security_findings) for a in apps)
		packages_affected = len([a for a in apps if a.security_findings])

		if sec_stats['critical'] or sec_stats['high'] or sec_stats['medium'] or sec_stats['low']:
			md_lines.extend(
				[
					'',
					'## Security Summary',
					'',
					'| Total Vulns | Packages Affected | Critical | High | Medium | Low |',
					'|-------------|-------------------|----------|------|--------|-----|',
					f'| {vuln_count} | {packages_affected} | {sec_stats["critical"]} | {sec_stats["high"]} | {sec_stats["medium"]} | {sec_stats["low"]} |',
				]
			)

		if stats['source_counts']:
			md_lines.extend(['', '## Sources', ''])
			for src, cnt in sorted(stats['source_counts'].items()):
				md_lines.append(f'- {src}: {cnt}')

		with open(output_file, 'w', encoding='utf-8') as f:
			f.write('\n'.join(md_lines))

	def _export_diff(self, apps: List[AppInfo], output_file: str):
		"""Export results as version diff."""
		scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
		stats = self._get_export_stats(apps)

		diff_lines = [
			f'System Update Diff - {scan_time}',
			'=' * 50,
			'',
		]

		updated = [a for a in apps if a.has_update]
		vulnerable = [a for a in apps if a.is_vulnerable]
		up_to_date = [a for a in apps if a.update_status == UpdateStatus.UP_TO_DATE]

		if updated:
			diff_lines.append('Updated Packages:')
			diff_lines.append('-' * 30)
			for app in updated:
				diff_lines.append(f'{app.name} ({app.source})')
				diff_lines.append(f'  {app.version} -> {app.latest_version}')
				diff_lines.append('')
			diff_lines.append('')

		if vulnerable:
			diff_lines.append('Vulnerable Packages:')
			diff_lines.append('-' * 30)
			for app in vulnerable:
				diff_lines.append(f'{app.name} ({app.source})')
				diff_lines.append(f'  Version: {app.version}')
				for finding in app.security_findings:
					desc = finding.get('description', '')
					if desc:
						desc = f' - {desc}'
					diff_lines.append(
						f'  ! {finding.get("severity", "UNKNOWN")}: {finding.get("cve", "N/A")}{desc}'
					)
				diff_lines.append('')
			diff_lines.append('')

		if up_to_date:
			diff_lines.append('Up to Date Packages:')
			diff_lines.append('-' * 30)
			for app in up_to_date:
				diff_lines.append(f'  {app.name} ({app.source}) v{app.version}')
			diff_lines.append('')

		diff_lines.append(
			f'Summary: {len(updated)} updates, {len(vulnerable)} vulnerable, {len(up_to_date)} up to date'
		)

		sec_stats = {
			'critical': sum(
				1 for a in apps for f in a.security_findings if f.get('severity') == 'CRITICAL'
			),
			'high': sum(
				1 for a in apps for f in a.security_findings if f.get('severity') == 'HIGH'
			),
			'medium': sum(
				1 for a in apps for f in a.security_findings if f.get('severity') == 'MEDIUM'
			),
			'low': sum(1 for a in apps for f in a.security_findings if f.get('severity') == 'LOW'),
		}
		vuln_count = sum(len(a.security_findings) for a in apps)
		packages_affected = len([a for a in apps if a.security_findings])

		if sec_stats['critical'] or sec_stats['high'] or sec_stats['medium'] or sec_stats['low']:
			diff_lines.extend(['', 'Security Summary:', '=' * 30])
			diff_lines.append(f'  Total Vulns: {vuln_count}')
			diff_lines.append(f'  Packages Affected: {packages_affected}')
			diff_lines.append(f'  Critical: {sec_stats["critical"]}')
			diff_lines.append(f'  High: {sec_stats["high"]}')
			diff_lines.append(f'  Medium: {sec_stats["medium"]}')
			diff_lines.append(f'  Low: {sec_stats["low"]}')

		if stats['source_counts']:
			diff_lines.extend(['', 'Sources:', '=' * 30])
			for src, cnt in sorted(stats['source_counts'].items()):
				diff_lines.append(f'  {src}: {cnt}')

		with open(output_file, 'w', encoding='utf-8') as f:
			f.write('\n'.join(diff_lines))

	@staticmethod
	def _html_escape(text: str) -> str:
		"""Escape HTML special characters."""
		return (
			text.replace('&', '&amp;')
			.replace('<', '&lt;')
			.replace('>', '&gt;')
			.replace('"', '&quot;')
		)

	@staticmethod
	def _xml_escape(text: str) -> str:
		"""Escape XML special characters."""
		return (
			text.replace('&', '&amp;')
			.replace('<', '&lt;')
			.replace('>', '&gt;')
			.replace('"', '&quot;')
			.replace("'", '&apos;')
		)

	def _get_export_stats(self, apps: List[AppInfo]) -> dict:
		"""Get export statistics."""
		from src.models import UpdateStatus

		source_counts = {}
		for app in apps:
			source_counts[app.source] = source_counts.get(app.source, 0) + 1

		return {
			'total': len(apps),
			'up_to_date': sum(1 for a in apps if a.update_status == UpdateStatus.UP_TO_DATE),
			'update_available': sum(
				1
				for a in apps
				if a.update_status
				in (UpdateStatus.UPDATE_AVAILABLE, UpdateStatus.SECURITY_UPDATE_AVAILABLE)
			),
			'vulnerable': sum(1 for a in apps if a.update_status == UpdateStatus.VULNERABLE),
			'unknown': sum(1 for a in apps if a.update_status == UpdateStatus.UNKNOWN),
			'source_counts': source_counts,
		}
