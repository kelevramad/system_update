"""Typer-based CLI entry point.

Translates the CLI flags into an :class:`argparse.Namespace` and delegates
to :class:`system_update.app.SystemUpdateApp`, which drives the whole
scan → check → security → display → export → update workflow.
"""

from __future__ import annotations

from argparse import Namespace
from typing import Optional

import typer


app = typer.Typer(
	name='system-update',
	help='Cross-platform package manager scanner and updater.',
	no_args_is_help=False,
	add_completion=False,
)


@app.command()
def main(
	source: Optional[str] = typer.Option(None, '--source', '-s', help='Limit scan to one source (or comma-separated list).'),
	update_source: Optional[str] = typer.Option(None, '--update-source', help='Update all packages from a specific source.'),
	update_all: bool = typer.Option(False, '--update-all', '-U', help='Apply every available update.'),
	dry_run: bool = typer.Option(False, '--dry-run', help='Preview without executing updates.'),
	yes: bool = typer.Option(False, '--yes', '-y', help='Skip confirmation prompts.'),
	no_cache: bool = typer.Option(False, '--no-cache', help='Bypass the scan result cache.'),
	clear_cache: bool = typer.Option(False, '--clear-cache', help='Delete the cache before scanning.'),
	profile: Optional[str] = typer.Option(None, '--profile', help='Named config profile to activate.'),
	profile_export: Optional[str] = typer.Option(None, '--profile-export', help='Export current profile to a JSON file.'),
	profile_import: Optional[str] = typer.Option(None, '--profile-import', help='Import profile from a JSON file.'),
	format_mode: Optional[str] = typer.Option(None, '--format', help='Display format: auto, compact, verbose, json.'),
	theme: Optional[str] = typer.Option(None, '--theme', help='UI theme (default, vibrant, minimal, dark, neon).'),
	icons: bool = typer.Option(False, '--icons', help='Show source/status icons.'),
	interactive: bool = typer.Option(False, '--interactive', help='Interactive TUI for package selection.'),
	show_all: bool = typer.Option(False, '--show-all', help='Show up-to-date packages too.'),
	notify: bool = typer.Option(False, '--notify', help='Send notification when updates are available.'),
	export_format: Optional[str] = typer.Option(None, '--export', help='Export format: json, csv, html, xml, markdown, md, diff.'),
	export_file: Optional[str] = typer.Option(None, '--output', '-o', help='Export destination file.'),
	package: Optional[str] = typer.Option(None, '--package', help='Update specific package by name.'),
	version: Optional[str] = typer.Option(None, '--version', help='Target version for package update.'),
	history: bool = typer.Option(False, '--history', help='Show scan history from SQLite database.'),
	history_package: Optional[str] = typer.Option(None, '--history-package', help='Show version history for a specific package.'),
	history_trends: bool = typer.Option(False, '--history-trends', help='Show update trends over time.'),
	history_stale: int = typer.Option(0, '--history-stale', help='Show packages not updated in N days.'),
	report: Optional[str] = typer.Option(None, '--report', help='Generate a history report (text, html, json).'),
	report_output: Optional[str] = typer.Option(None, '--report-output', help='Output file for report.'),
	debug: bool = typer.Option(False, '--debug', help='Verbose debug logging.'),
	log: bool = typer.Option(False, '--log', help='Write INFO logs to system.log.'),
) -> None:
	"""Scan the system, show available updates, and optionally apply them."""
	from system_update.app import SystemUpdateApp

	args = Namespace(
		source=source,
		update_source=update_source,
		update_all=update_all,
		dry_run=dry_run,
		yes=yes,
		no_cache=no_cache,
		clear_cache=clear_cache,
		profile=profile,
		profile_export=profile_export,
		profile_import=profile_import,
		format=format_mode,
		theme=theme,
		icons=icons,
		interactive=interactive,
		show_all=show_all,
		notify=notify,
		export=export_format,
		output=export_file,
		package=package,
		version=version,
		history=history,
		history_package=history_package,
		history_trends=history_trends,
		history_stale=history_stale,
		report=report,
		report_output=report_output,
		debug=debug,
		log=log,
	)

	SystemUpdateApp().run(args)


if __name__ == '__main__':
	app()
