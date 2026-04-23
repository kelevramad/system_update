"""Typer-based CLI entry point.

This is the *new* command-line front-end that targets the modularised API in
:mod:`system_update.scanners`, :mod:`system_update.checkers`,
:mod:`system_update.executors`, :mod:`system_update.ui`, and
:mod:`system_update.export`. It replaces the argparse layer that lived in the
flat ``system_update.py`` entry script.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import List, Optional

import typer

from system_update import export as export_module
from system_update.cache import CacheManager
from system_update.checkers import UpdateChecker
from system_update.config import SystemConfig, setup_logging
from system_update.executors import UpdateExecutor
from system_update.history import HistoryDatabase
from system_update.models import AppInfo
from system_update.scanners import PackageScanner
from system_update.ui import UISystem
from system_update.utils import console

app = typer.Typer(
	name='system-update',
	help='Cross-platform package manager scanner and updater.',
	no_args_is_help=False,
	add_completion=False,
)


def _active_sources(config: SystemConfig, source_filter: Optional[str]) -> List[str]:
	"""Return the list of source names to scan based on ``source_filter`` + config."""
	available = [
		'winget', 'chocolatey', 'npm', 'pnpm', 'bun', 'yarn', 'pip',
		'path', 'registry', 'rust', 'scoop', 'dotnet', 'appx', 'msix',
	]
	aliases = {'choco': 'chocolatey'}
	if source_filter:
		wanted = aliases.get(source_filter.lower(), source_filter.lower())
		return [wanted] if wanted in available else []
	enabled = config.settings.get('sources', {})
	return [s for s in available if enabled.get(s, False)]


def _scan(config: SystemConfig, sources: List[str]) -> List[AppInfo]:
	"""Call the per-source scanners sequentially and deduplicate by (source, name, version)."""
	scanners = {
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

	seen: dict[str, AppInfo] = {}
	for name in sources:
		func = scanners.get(name)
		if func is None:
			continue
		for item in func():
			key = f'{item.source.lower()}|{item.name.lower()}|{item.version}'
			seen.setdefault(key, item)
	return sorted(seen.values(), key=lambda a: (a.source, a.name))


@app.command()
def main(
	source: Optional[str] = typer.Option(None, '--source', '-s', help='Limit scan to one source.'),
	update_all: bool = typer.Option(False, '--update-all', '-U', help='Apply every available update.'),
	dry_run: bool = typer.Option(False, '--dry-run', help='Preview without executing updates.'),
	no_cache: bool = typer.Option(False, '--no-cache', help='Bypass the scan result cache.'),
	clear_cache: bool = typer.Option(False, '--clear-cache', help='Delete the cache before scanning.'),
	profile: Optional[str] = typer.Option(None, '--profile', help='Named config profile to activate.'),
	format_mode: str = typer.Option('auto', '--format', help='Display format: auto, compact, verbose, json.'),
	theme: str = typer.Option('default', '--theme', help='UI theme name.'),
	icons: bool = typer.Option(False, '--icons', help='Show source icons in tables.'),
	show_all: bool = typer.Option(False, '--all', help='Show up-to-date packages too.'),
	export_format: Optional[str] = typer.Option(None, '--export', help='Export format: json, csv, html, xml, markdown, diff.'),
	export_file: Optional[Path] = typer.Option(None, '--output', '-o', help='Export destination file.'),
	debug: bool = typer.Option(False, '--debug', help='Verbose debug logging.'),
	log: bool = typer.Option(False, '--log', help='Write INFO logs to system.log.'),
) -> None:
	"""Scan the system, show available updates, and optionally apply them."""
	config = SystemConfig(profile_name=profile)
	setup_logging(config, debug=debug, enable_log=log)

	cache = CacheManager(
		config.cache_file, config.settings.get('cache', {}).get('duration_hours', 2)
	)
	if clear_cache:
		cache.clear()

	sources = _active_sources(config, source)
	if not sources:
		console.print('[red]No enabled sources to scan.[/red]')
		raise typer.Exit(code=1)

	UISystem.display_banner(config)

	apps = None if no_cache else cache.load()
	if apps is None:
		start = time.time()
		apps = _scan(config, sources)
		UpdateChecker.check_all_updates(apps)
		cache.save(apps)
		scan_time = time.time() - start
	else:
		scan_time = 0.0

	counts: dict[str, int] = {}
	for a in apps:
		counts[a.source.lower()] = counts.get(a.source.lower(), 0) + 1

	updates = [a for a in apps if a.has_update or a.is_vulnerable]
	UISystem.display_summary(len(apps), len(updates), scan_time, counts, show_all=show_all)
	console.print(UISystem.create_apps_table(apps, show_all=show_all, theme=theme, use_icons=icons))

	if export_format:
		path = export_module.export(apps, export_format, str(export_file) if export_file else None)
		console.print(f'[green]✓[/green] Exported to {path}')

	if updates and (update_all or dry_run):
		UpdateExecutor.execute_updates(updates, dry_run=dry_run)

	with HistoryDatabase(Path(config.config_dir) / 'history.db') as db:
		db.record_scan(apps, scan_time, len(updates))


if __name__ == '__main__':
	app()
