"""Typer-based CLI entry point.

Translates the CLI flags into an :class:`argparse.Namespace` and delegates
to :class:`system_update.app.SystemUpdateApp`, which drives the whole
scan → check → security → display → export → update workflow.
"""

from __future__ import annotations

from argparse import Namespace
from typing import Optional

import typer


# Rich-help panel labels (emoji-grouped categories)
PANEL_SCAN = '🔎 Scanning & Sources'
PANEL_UPDATE = '⚙️ Updates & Actions'
PANEL_EXPORT = '📤 Export & Reports'
PANEL_UI = '🎨 UI & Display'
PANEL_PROFILE = '🧭 Profiles & Config'
PANEL_HISTORY = '📜 History & Trends'
PANEL_LOG = '🪵 Logging & Debug'


APP_HELP = """[bold cyan]system-update[/bold cyan] — cross-platform package scanner & updater.

Scans [yellow]winget, choco, scoop, npm, pnpm, yarn, bun, pip, cargo, PATH, registry[/yellow],
checks for updates, runs [red]security audits[/red] (OSV, pip-audit, npm audit, PyPI, GH Advisory),
and can [green]apply updates[/green] or export branded [magenta]HTML/JSON/CSV/XML/Markdown[/magenta] reports.
"""


EPILOG = """
[bold]Examples[/bold]

  [dim]# Basic scan (uses cache if warm)[/dim]
  [cyan]system-update[/cyan]

  [dim]# Force fresh scan, show everything[/dim]
  [cyan]system-update --no-cache --show-all[/cyan]

  [dim]# Scan only specific sources[/dim]
  [cyan]system-update -s winget,npm,pip[/cyan]

  [dim]# Preview all updates without applying[/dim]
  [cyan]system-update --update-all --dry-run[/cyan]

  [dim]# Apply every update, skip prompts[/dim]
  [cyan]system-update -U -y[/cyan]

  [dim]# Update a single package[/dim]
  [cyan]system-update --package aiohttp --version 3.9.5[/cyan]

  [dim]# Update every npm package[/dim]
  [cyan]system-update --update-source npm -y[/cyan]

  [dim]# Interactive TUI picker[/dim]
  [cyan]system-update --interactive[/cyan]

  [dim]# Branded HTML report[/dim]
  [cyan]system-update --export html -o report.html \\
      --html-title "Fleet Audit" --html-company "Acme" --html-logo ./logo.png[/cyan]

  [dim]# Custom HTML template[/dim]
  [cyan]system-update --export html -o report.html --html-template ./tmpl.html[/cyan]

  [dim]# JSON for CI pipelines[/dim]
  [cyan]system-update --export json -o scan.json --no-cache[/cyan]

  [dim]# History & trends[/dim]
  [cyan]system-update --history-trends[/cyan]
  [cyan]system-update --history-package aiohttp[/cyan]
  [cyan]system-update --history-stale 30[/cyan]

  [dim]# Switch profile[/dim]
  [cyan]system-update --profile work[/cyan]

[bold]Data dir[/bold] [yellow]~/.system_update/[/yellow]  ·  [bold]Docs[/bold] [blue]https://github.com/kelevramad/system_update[/blue]
"""


app = typer.Typer(
	name='system-update',
	help=APP_HELP,
	no_args_is_help=False,
	add_completion=False,
	rich_markup_mode='rich',
)


@app.command(epilog=EPILOG)
def main(
	# 🔎 Scanning & Sources
	source: Optional[str] = typer.Option(
		None, '--source', '-s',
		help='🎯 Limit scan to one or more sources (comma-separated, e.g. [cyan]winget,npm[/cyan]).',
		rich_help_panel=PANEL_SCAN,
	),
	no_cache: bool = typer.Option(
		False, '--no-cache',
		help='🚫 Bypass scan cache and force a fresh scan.',
		rich_help_panel=PANEL_SCAN,
	),
	clear_cache: bool = typer.Option(
		False, '--clear-cache',
		help='🧹 Delete cache file before scanning.',
		rich_help_panel=PANEL_SCAN,
	),
	show_all: bool = typer.Option(
		False, '--show-all',
		help='👀 Include up-to-date packages in output (default hides them).',
		rich_help_panel=PANEL_SCAN,
	),
	# ⚙️ Updates & Actions
	update_all: bool = typer.Option(
		False, '--update-all', '-U',
		help='🚀 Apply every available update.',
		rich_help_panel=PANEL_UPDATE,
	),
	update_source: Optional[str] = typer.Option(
		None, '--update-source',
		help='📦 Update all packages from a specific source (e.g. [cyan]npm[/cyan]).',
		rich_help_panel=PANEL_UPDATE,
	),
	package: Optional[str] = typer.Option(
		None, '--package',
		help='🎯 Update a specific package by name.',
		rich_help_panel=PANEL_UPDATE,
	),
	version: Optional[str] = typer.Option(
		None, '--version',
		help='🔖 Target a specific version (used with [cyan]--package[/cyan]).',
		rich_help_panel=PANEL_UPDATE,
	),
	dry_run: bool = typer.Option(
		False, '--dry-run',
		help='🧪 Preview updates without executing them.',
		rich_help_panel=PANEL_UPDATE,
	),
	yes: bool = typer.Option(
		False, '--yes', '-y',
		help='✅ Auto-confirm every prompt.',
		rich_help_panel=PANEL_UPDATE,
	),
	interactive: bool = typer.Option(
		False, '--interactive',
		help='🖱️  Interactive TUI to select packages to update.',
		rich_help_panel=PANEL_UPDATE,
	),
	notify: bool = typer.Option(
		False, '--notify',
		help='🔔 Send a system notification when updates are available.',
		rich_help_panel=PANEL_UPDATE,
	),
	# 📤 Export & Reports
	export_format: Optional[str] = typer.Option(
		None, '--export',
		help='📄 Export format: [cyan]json, csv, html, xml, markdown, md, diff[/cyan].',
		rich_help_panel=PANEL_EXPORT,
	),
	export_file: Optional[str] = typer.Option(
		None, '--output', '-o',
		help='💾 Destination file for the export.',
		rich_help_panel=PANEL_EXPORT,
	),
	html_template: Optional[str] = typer.Option(
		None, '--html-template',
		help='🧩 Custom HTML template path (overrides built-in).',
		rich_help_panel=PANEL_EXPORT,
	),
	html_logo: Optional[str] = typer.Option(
		None, '--html-logo',
		help='🖼️  Logo image (PNG/JPG/SVG) embedded as base64 in HTML.',
		rich_help_panel=PANEL_EXPORT,
	),
	html_title: Optional[str] = typer.Option(
		None, '--html-title',
		help='📝 Override report title on HTML export.',
		rich_help_panel=PANEL_EXPORT,
	),
	html_company: Optional[str] = typer.Option(
		None, '--html-company',
		help='🏢 Company name shown in HTML header.',
		rich_help_panel=PANEL_EXPORT,
	),
	# 🎨 UI & Display
	format_mode: Optional[str] = typer.Option(
		None, '--format',
		help='🎛️  Display mode: [cyan]auto, compact, verbose, json[/cyan].',
		rich_help_panel=PANEL_UI,
	),
	theme: Optional[str] = typer.Option(
		None, '--theme',
		help='🌈 UI theme: [cyan]default, vibrant, minimal, dark, neon[/cyan].',
		rich_help_panel=PANEL_UI,
	),
	icons: bool = typer.Option(
		False, '--icons',
		help='✨ Show source and status icons in tables.',
		rich_help_panel=PANEL_UI,
	),
	# 🧭 Profiles & Config
	profile: Optional[str] = typer.Option(
		None, '--profile',
		help='👤 Activate a named config profile.',
		rich_help_panel=PANEL_PROFILE,
	),
	profile_export: Optional[str] = typer.Option(
		None, '--profile-export',
		help='📤 Export active profile to a JSON file.',
		rich_help_panel=PANEL_PROFILE,
	),
	profile_import: Optional[str] = typer.Option(
		None, '--profile-import',
		help='📥 Import profile from a JSON file.',
		rich_help_panel=PANEL_PROFILE,
	),
	# 📜 History & Trends
	history: bool = typer.Option(
		False, '--history',
		help='📚 Show scan history from the SQLite database.',
		rich_help_panel=PANEL_HISTORY,
	),
	history_package: Optional[str] = typer.Option(
		None, '--history-package',
		help='🔍 Show version history for a specific package.',
		rich_help_panel=PANEL_HISTORY,
	),
	history_trends: bool = typer.Option(
		False, '--history-trends',
		help='📈 Show update trends over time.',
		rich_help_panel=PANEL_HISTORY,
	),
	history_stale: int = typer.Option(
		0, '--history-stale',
		help='🕰️  Show packages not updated in N days.',
		rich_help_panel=PANEL_HISTORY,
	),
	report: Optional[str] = typer.Option(
		None, '--report',
		help='🧾 Generate a history report: [cyan]text, html, json[/cyan].',
		rich_help_panel=PANEL_HISTORY,
	),
	report_output: Optional[str] = typer.Option(
		None, '--report-output',
		help='💾 Output file for the history report.',
		rich_help_panel=PANEL_HISTORY,
	),
	# 🪵 Logging & Debug
	debug: bool = typer.Option(
		False, '--debug',
		help='🐛 Verbose debug logging to stderr.',
		rich_help_panel=PANEL_LOG,
	),
	log: bool = typer.Option(
		False, '--log',
		help='🗒️  Write INFO logs to [yellow]~/.system_update/system.log[/yellow].',
		rich_help_panel=PANEL_LOG,
	),
) -> None:
	"""Scan the system, display available updates, and optionally apply them."""
	from system_update.app import SystemUpdateApp

	# ── Friendly validation for choice-style flags ─────────────────────────
	# Catch typos like ``--export hmlt`` before they reach the export layer
	# (which would otherwise raise ValueError → traceback). Uses
	# ``typer.BadParameter`` so Typer renders it inside its standard
	# rich error panel — matches the look of "No such option: --foo".
	import difflib

	def _bail(flag: str, value: str, valid: list[str]) -> None:
		hint = difflib.get_close_matches(value, valid, n=1)
		suggestion = f" Did you mean '{hint[0]}'?" if hint else ''
		raise typer.BadParameter(
			f"{value!r} is not one of {valid}.{suggestion}",
			param_hint=flag,
		)

	_VALID_EXPORTS = ['json', 'csv', 'html', 'xml', 'markdown', 'md', 'diff']
	_VALID_REPORTS = ['text', 'html', 'json']
	_VALID_FORMATS = ['auto', 'compact', 'verbose', 'json']
	_VALID_THEMES = ['default', 'vibrant', 'minimal', 'dark', 'neon']

	if export_format and export_format not in _VALID_EXPORTS:
		_bail('--export', export_format, _VALID_EXPORTS)
	if report and report not in _VALID_REPORTS:
		_bail('--report', report, _VALID_REPORTS)
	if format_mode and format_mode not in _VALID_FORMATS:
		_bail('--format', format_mode, _VALID_FORMATS)
	if theme and theme not in _VALID_THEMES:
		_bail('--theme', theme, _VALID_THEMES)

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
		html_template=html_template,
		html_logo=html_logo,
		html_title=html_title,
		html_company=html_company,
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
