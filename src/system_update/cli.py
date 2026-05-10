"""Typer-based CLI entry point.

Translates the CLI flags into :class:`system_update.cli_options.CLIOptions` and delegates
to :class:`system_update.app.SystemUpdateApp`, which drives the whole
scan → check → security → display → export → update workflow.
"""

from __future__ import annotations

import io
import shutil
import sys
from importlib.metadata import PackageNotFoundError, version as _pkg_version
from typing import List, Optional

import typer
import typer.rich_utils as typer_rich_utils


def _resolve_version() -> str:
	"""Best-effort package version, with fallback to the UI constant."""
	try:
		return _pkg_version('system-update-cli')
	except PackageNotFoundError:
		try:
			from system_update.ui.system import _VERSION

			return _VERSION
		except Exception:
			return '0.0.0'


_APP_VERSION = _resolve_version()

# Force UTF-8 on stdout/stderr so emoji-rich help/sub-help renders on
# Windows cp1252 consoles. Applied here so it covers both the
# ``python -m system_update`` entry point and the installed
# ``system-update`` script entry-point.
for _stream in (sys.stdout, sys.stderr):
	if isinstance(_stream, io.TextIOWrapper):
		try:
			_stream.reconfigure(encoding='utf-8', errors='replace')
		except Exception:
			pass


def _configure_rich_help_width() -> None:
	"""Keep Rich/Typer help panels away from the terminal's clipping edge."""
	columns = shutil.get_terminal_size(fallback=(120, 24)).columns
	typer_rich_utils.MAX_WIDTH = max(80, min(120, columns - 2))


_configure_rich_help_width()


# Rich-help panel labels (emoji-grouped categories)
PANEL_SCAN = '🔎 Scanning & Sources'
PANEL_UPDATE = '⚙️ Updates & Actions'
PANEL_EXPORT = '📤 Export & Reports'
PANEL_UI = '🎨 UI & Display'
PANEL_PROFILE = '🧭 Profiles & Config'
PANEL_HISTORY = '📜 History & Trends'
PANEL_DATA = '🔄 Data Sharing'
PANEL_SCHEDULE = '🗓️  Scheduled Tasks'
PANEL_ROLLBACK = '⏪ Snapshots & Rollback'
PANEL_REMOTE = '🌐 Remote Management'
PANEL_LOG = '🪵 Logging & Debug'


APP_HELP = """[bold cyan]system-update[/bold cyan] — cross-platform package scanner & updater.

Scans [yellow]winget, choco, scoop, npm, pnpm, yarn, bun, pip, cargo, PATH, registry, AppX, drivers, services[/yellow],
checks for updates, runs [red]security audits[/red] (OSV, pip-audit, npm audit, PyPI, GH Advisory),
and can [green]apply updates[/green] or export branded [magenta]HTML/JSON/CSV/XML/Markdown[/magenta] reports.
"""


def print_banner() -> None:
	"""Print the unified System Update panel before Typer renders help.

	Reuses the same panel builder as the runtime banner so ``--help`` and
	the regular run show identical context (version, runtime, profile,
	data dir contents, cache TTL, sources, security, repo). The banner
	is rendered with ``force_terminal=True`` and the same width Typer
	uses, so its right edge aligns with the help panels.
	"""
	from rich.console import Console

	from system_update.config import SystemConfig
	from system_update.ui.system import build_system_panel

	try:
		config = SystemConfig()
	except Exception:
		config = None  # fall back to defaults inside build_system_panel
	Console(force_terminal=True, width=typer_rich_utils.MAX_WIDTH).print(
		build_system_panel(config)
	)


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
  [cyan]system-update --update-package aiohttp --version 3.9.5[/cyan]

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

[bold]Tip[/bold] flags marked [bold green]📖[/bold green] have a detailed help page — run [cyan]--explain <flag>[/cyan]
or pass [cyan]help[/cyan] as the value (e.g. [cyan]--cloud-sync help[/cyan], [cyan]--export help[/cyan]).

[bold]Data dir[/bold] [yellow]~/.system_update/[/yellow]  ·  [bold]Docs[/bold] [blue]https://github.com/kelevramad/system_update[/blue]
"""


app = typer.Typer(
	name='system-update',
	help=APP_HELP,
	no_args_is_help=False,
	add_completion=False,
	rich_markup_mode='rich',
	context_settings={'help_option_names': ['-h', '--help']},
)


def _intercept_subhelp_argv() -> bool:
	"""Pre-Typer scan: ``--<flag> help`` (any flag, including booleans).

	Typer rejects ``--interactive help`` because ``--interactive`` is a bool
	option that takes no value. We catch the pattern here, render the page,
	and exit cleanly before Typer parses argv.

	Returns True if a help page was rendered (caller should ``sys.exit(0)``).
	"""
	from system_update import subhelp

	argv = sys.argv[1:]
	for i in range(len(argv) - 1):
		flag, value = argv[i], argv[i + 1]
		if not flag.startswith('--'):
			continue
		if value.lower() != 'help':
			continue
		topic = flag.lstrip('-').replace('_', '-').lower()
		if subhelp.show(topic):
			return True
	return False


@app.command(epilog=EPILOG)
def main(
	# 🔎 Scanning & Sources
	source: Optional[str] = typer.Option(
		None,
		'--source',
		'-s',
		help='🎯 Limit scan to one or more sources (comma-separated, e.g. [cyan]winget,npm[/cyan]). [bold green]📖[/bold green]',
		rich_help_panel=PANEL_SCAN,
	),
	no_cache: bool = typer.Option(
		False,
		'--no-cache',
		help='🚫 Bypass scan cache and force a fresh scan.',
		rich_help_panel=PANEL_SCAN,
	),
	clear_cache: bool = typer.Option(
		False,
		'--clear-cache',
		help='🧹 Delete cache file before scanning.',
		rich_help_panel=PANEL_SCAN,
	),
	show_all: bool = typer.Option(
		False,
		'--show-all',
		help='👀 Include up-to-date packages in output (default hides them).',
		rich_help_panel=PANEL_SCAN,
	),
	exclude: Optional[str] = typer.Option(
		None,
		'--exclude',
		help='🚫 Skip packages matching the given names. Comma-separated; supports [cyan]source:name[/cyan] for per-source filtering (e.g. [cyan]--exclude Git.Git,pip:requests[/cyan]).',
		rich_help_panel=PANEL_SCAN,
	),
	# ⚙️ Updates & Actions
	update_all: bool = typer.Option(
		False,
		'--update-all',
		'-U',
		help='🚀 Apply every available update.',
		rich_help_panel=PANEL_UPDATE,
	),
	update_source: Optional[str] = typer.Option(
		None,
		'--update-source',
		help='📦 Update all packages from a specific source (e.g. [cyan]npm[/cyan]). [bold green]📖[/bold green]',
		rich_help_panel=PANEL_UPDATE,
	),
	update_package: Optional[str] = typer.Option(
		None,
		'--update-package',
		help='🎯 Update a specific package by name.',
		rich_help_panel=PANEL_UPDATE,
	),
	version: Optional[str] = typer.Option(
		None,
		'--version',
		help='🔖 Target a specific version (used with [cyan]--update-package[/cyan]).',
		rich_help_panel=PANEL_UPDATE,
	),
	dry_run: bool = typer.Option(
		False,
		'--dry-run',
		help='🧪 Preview updates without executing them.',
		rich_help_panel=PANEL_UPDATE,
	),
	yes: bool = typer.Option(
		False,
		'--yes',
		'-y',
		help='✅ Auto-confirm every prompt.',
		rich_help_panel=PANEL_UPDATE,
	),
	interactive: bool = typer.Option(
		False,
		'--interactive',
		help='🖱️  Interactive TUI to select packages to update. [bold green]📖[/bold green]',
		rich_help_panel=PANEL_UPDATE,
	),
	notify: bool = typer.Option(
		False,
		'--notify',
		help='🔔 Send a system notification when updates are available. [bold green]📖[/bold green]',
		rich_help_panel=PANEL_UPDATE,
	),
	# 📤 Export & Reports
	export_format: Optional[str] = typer.Option(
		None,
		'--export',
		help='📄 Export format: [cyan]json, csv, html, xml, markdown, md, diff[/cyan]. [bold green]📖[/bold green]',
		rich_help_panel=PANEL_EXPORT,
	),
	export_file: Optional[str] = typer.Option(
		None,
		'--output',
		'-o',
		help='💾 Destination file for the export.',
		rich_help_panel=PANEL_EXPORT,
	),
	html_template: Optional[str] = typer.Option(
		None,
		'--html-template',
		help='🧩 Custom HTML template path (overrides built-in).',
		rich_help_panel=PANEL_EXPORT,
	),
	html_logo: Optional[str] = typer.Option(
		None,
		'--html-logo',
		help='🖼️  Logo image (PNG/JPG/SVG) embedded as base64 in HTML.',
		rich_help_panel=PANEL_EXPORT,
	),
	html_title: Optional[str] = typer.Option(
		None,
		'--html-title',
		help='📝 Override report title on HTML export.',
		rich_help_panel=PANEL_EXPORT,
	),
	html_company: Optional[str] = typer.Option(
		None,
		'--html-company',
		help='🏢 Company name shown in HTML header.',
		rich_help_panel=PANEL_EXPORT,
	),
	# 🎨 UI & Display
	format_mode: Optional[str] = typer.Option(
		None,
		'--format',
		help='🎛️  Display mode: [cyan]auto, compact, verbose, json[/cyan]. [bold green]📖[/bold green]',
		rich_help_panel=PANEL_UI,
	),
	theme: Optional[str] = typer.Option(
		None,
		'--theme',
		help='🌈 UI theme: [cyan]default, vibrant, minimal, dark, neon[/cyan]. [bold green]📖[/bold green]',
		rich_help_panel=PANEL_UI,
	),
	# 🧭 Profiles & Config
	profile: Optional[str] = typer.Option(
		None,
		'--profile',
		help='👤 Activate a named config profile. [bold green]📖[/bold green]',
		rich_help_panel=PANEL_PROFILE,
	),
	profile_export: Optional[str] = typer.Option(
		None,
		'--profile-export',
		help='📤 Export active profile to a JSON file. [bold green]📖[/bold green]',
		rich_help_panel=PANEL_PROFILE,
	),
	profile_import: Optional[str] = typer.Option(
		None,
		'--profile-import',
		help='📥 Import profile from a JSON file. [bold green]📖[/bold green]',
		rich_help_panel=PANEL_PROFILE,
	),
	save_config: bool = typer.Option(
		False,
		'--save-config',
		help="💾 Persist this run's flag overrides ([cyan]--source[/cyan], [cyan]--theme[/cyan], [cyan]--format[/cyan]) into the active profile's config.json.",
		rich_help_panel=PANEL_PROFILE,
	),
	# 📜 History & Trends
	history: bool = typer.Option(
		False,
		'--history',
		help='📚 Show scan history from the SQLite database.',
		rich_help_panel=PANEL_HISTORY,
	),
	history_package: Optional[str] = typer.Option(
		None,
		'--history-package',
		help='🔍 Show version history for a specific package.',
		rich_help_panel=PANEL_HISTORY,
	),
	history_trends: bool = typer.Option(
		False,
		'--history-trends',
		help='📈 Show update trends over time. [bold green]📖[/bold green]',
		rich_help_panel=PANEL_HISTORY,
	),
	history_stale: int = typer.Option(
		0,
		'--history-stale',
		help='🕰️  Show packages not updated in N days. [bold green]📖[/bold green]',
		rich_help_panel=PANEL_HISTORY,
	),
	report: Optional[str] = typer.Option(
		None,
		'--report',
		help='🧾 Generate a history report: [cyan]text, html, json[/cyan]. [bold green]📖[/bold green]',
		rich_help_panel=PANEL_HISTORY,
	),
	report_output: Optional[str] = typer.Option(
		None,
		'--report-output',
		help='💾 Output file for the history report.',
		rich_help_panel=PANEL_HISTORY,
	),
	# 🕸️ Dependency Graph (6.3)
	dependency_graph: Optional[str] = typer.Option(
		None,
		'--dependency-graph',
		help='🕸️  Dependency graph action: [cyan]dot, conflicts, minimal, help[/cyan]. [bold green]📖[/bold green]',
		rich_help_panel=PANEL_EXPORT,
	),
	graph_output: Optional[str] = typer.Option(
		None,
		'--graph-output',
		help='💾 Output path for [cyan]--dependency-graph dot[/cyan].',
		rich_help_panel=PANEL_EXPORT,
	),
	# 🔄 Data Sharing (5.4)
	import_files: Optional[List[str]] = typer.Option(
		None,
		'--import',
		help='📥 Import scan data from JSON/CSV file(s). Repeatable; multiple files are merged. [bold green]📖[/bold green]',
		rich_help_panel=PANEL_DATA,
	),
	merge_with_cache: bool = typer.Option(
		False,
		'--merge',
		help='🧬 Merge imported scan(s) with the existing cache instead of replacing it.',
		rich_help_panel=PANEL_DATA,
	),
	list_plugins: bool = typer.Option(
		False,
		'--list-plugins',
		help='🧩 Show loaded plugins (one row per plugin file with capability chips).',
		rich_help_panel=PANEL_DATA,
	),
	list_plugins_detail: bool = typer.Option(
		False,
		'--list-plugins-detail',
		help='🧬 Show every registered extension point per plugin (per-type table).',
		rich_help_panel=PANEL_DATA,
	),
	no_plugins: bool = typer.Option(
		False,
		'--no-plugins',
		help='🛡️  Bypass the plugin loader entirely (security kill switch).',
		rich_help_panel=PANEL_DATA,
	),
	cloud_sync: Optional[str] = typer.Option(
		None,
		'--cloud-sync',
		help='☁️  Cloud-sync action: [cyan]push, pull, status[/cyan]. [bold green]📖[/bold green]',
		rich_help_panel=PANEL_DATA,
	),
	explain: Optional[str] = typer.Option(
		None,
		'--explain',
		help='📖 Show detailed help for any flag (e.g. [cyan]--explain interactive[/cyan]). Use [cyan]--explain list[/cyan] to see all topics.',
	),
	# 🗓️  Scheduled Tasks (6.1)
	schedule: Optional[str] = typer.Option(
		None,
		'--schedule',
		help='🗓️  Scheduled-task action: [cyan]create, delete, list, status, run, eval, help[/cyan]. [bold green]📖[/bold green]',
		rich_help_panel=PANEL_SCHEDULE,
	),
	schedule_name: Optional[str] = typer.Option(
		'SystemUpdate_Scan',
		'--schedule-name',
		help='🏷️  Task name (default [yellow]SystemUpdate_Scan[/yellow]).',
		rich_help_panel=PANEL_SCHEDULE,
	),
	schedule_when: Optional[str] = typer.Option(
		'daily',
		'--schedule-when',
		help='🔁 Recurrence: [cyan]daily, weekly, hourly, monthly, onstart, onlogon[/cyan].',
		rich_help_panel=PANEL_SCHEDULE,
	),
	schedule_time: Optional[str] = typer.Option(
		'09:00',
		'--schedule-time',
		help='⏰ Time of day for daily/weekly/monthly schedules (HH:MM).',
		rich_help_panel=PANEL_SCHEDULE,
	),
	schedule_days: Optional[str] = typer.Option(
		'',
		'--schedule-days',
		help='📅 Days for weekly schedule (e.g. [cyan]MON,WED,FRI[/cyan]).',
		rich_help_panel=PANEL_SCHEDULE,
	),
	schedule_args: Optional[str] = typer.Option(
		'--no-cache --notify',
		'--schedule-args',
		help='🧰 Arguments the scheduled task will pass to system-update.',
		rich_help_panel=PANEL_SCHEDULE,
	),
	# ⏪ Snapshots & Rollback (6.2)
	snapshot: Optional[str] = typer.Option(
		None,
		'--snapshot',
		help='📸 Snapshot action: [cyan]list, show, delete, help[/cyan]. [bold green]📖[/bold green]',
		rich_help_panel=PANEL_ROLLBACK,
	),
	snapshot_id: Optional[str] = typer.Option(
		None,
		'--snapshot-id',
		help='🆔 Target a specific snapshot id (used with [cyan]show[/cyan] / [cyan]delete[/cyan]).',
		rich_help_panel=PANEL_ROLLBACK,
	),
	rollback: Optional[str] = typer.Option(
		None,
		'--rollback',
		help='⏪ Rollback to a snapshot: pass the snapshot id, [cyan]last[/cyan], or [cyan]help[/cyan]. [bold green]📖[/bold green]',
		rich_help_panel=PANEL_ROLLBACK,
	),
	# 🌐 Remote Management (6.4)
	remote: Optional[str] = typer.Option(
		None,
		'--remote',
		help='🌐 Remote action: [cyan]list, add, remove, scan, update, report, help[/cyan]. [bold green]📖[/bold green]',
		rich_help_panel=PANEL_REMOTE,
	),
	remote_host: Optional[str] = typer.Option(
		None,
		'--remote-host',
		help='🖥️  Target a single inventory host by name.',
		rich_help_panel=PANEL_REMOTE,
	),
	remote_group: Optional[str] = typer.Option(
		None,
		'--remote-group',
		help='👥 Target every host in a named group.',
		rich_help_panel=PANEL_REMOTE,
	),
	remote_address: Optional[str] = typer.Option(
		None,
		'--remote-address',
		help='📡 Hostname / IP for [cyan]--remote add[/cyan] (defaults to the host name).',
		rich_help_panel=PANEL_REMOTE,
	),
	remote_user: Optional[str] = typer.Option(
		None,
		'--remote-user',
		help='👤 Username used by [cyan]winrs[/cyan] for [cyan]--remote add[/cyan].',
		rich_help_panel=PANEL_REMOTE,
	),
	remote_groups: Optional[str] = typer.Option(
		None,
		'--remote-groups',
		help='🏷️  Comma-separated groups for [cyan]--remote add[/cyan].',
		rich_help_panel=PANEL_REMOTE,
	),
	remote_args: Optional[str] = typer.Option(
		None,
		'--remote-args',
		help='🧰 Extra args to append to the remote [cyan]system-update[/cyan] command.',
		rich_help_panel=PANEL_REMOTE,
	),
	remote_output: Optional[str] = typer.Option(
		None,
		'--remote-output',
		help='💾 Write the consolidated remote report to this file.',
		rich_help_panel=PANEL_REMOTE,
	),
	remote_timeout: int = typer.Option(
		600,
		'--remote-timeout',
		help='⏱️  Per-host timeout in seconds.',
		rich_help_panel=PANEL_REMOTE,
	),
	remote_verbose: bool = typer.Option(
		False,
		'--remote-verbose',
		help="🔊 Show the remote command and stream each host's stdout/stderr as it completes.",
		rich_help_panel=PANEL_REMOTE,
	),
	remote_debug: bool = typer.Option(
		False,
		'--remote-debug',
		help='🐛 Show redacted winrs argv, timeout, target metadata, and completion output.',
		rich_help_panel=PANEL_REMOTE,
	),
	# 🪵 Logging & Debug
	debug: bool = typer.Option(
		False,
		'--debug',
		help='🐛 Verbose debug logging to stderr.',
		rich_help_panel=PANEL_LOG,
	),
	log: bool = typer.Option(
		False,
		'--log',
		help='🗒️  Write INFO logs to [yellow]~/.system_update/system.log[/yellow].',
		rich_help_panel=PANEL_LOG,
	),
) -> None:
	"""Scan the system, display available updates, and optionally apply them."""
	from system_update.app import SystemUpdateApp
	from system_update import subhelp
	from system_update.cli_options import CLIOptions

	# ── --explain FLAG / <choice-flag> help → detailed sub-help pages ──────
	# Handled before validation so '--export help' and '--cloud-sync help'
	# don't trip the choice-validator.
	def _maybe_show_subhelp(name: str) -> bool:
		if subhelp.show(name):
			raise typer.Exit(code=0)
		return False

	if explain:
		if explain.lower() in ('list', 'topics', 'help'):
			from rich.console import Console as _Console

			c = _Console()
			c.print('[bold]Available --explain topics:[/bold]')
			for t in subhelp.list_topics():
				c.print(f'  • [cyan]{t}[/cyan]')
			c.print('\n[dim]Usage: system-update --explain <topic>[/dim]')
			raise typer.Exit(code=0)
		if not subhelp.show(explain):
			raise typer.BadParameter(
				f'No detailed help for {explain!r}. Available: {", ".join(subhelp.list_topics())}',
				param_hint='--explain',
			)
		raise typer.Exit(code=0)

	# Choice flags that opt-in to "<flag> help" syntax — show page and exit.
	for _flag, _val in (
		('cloud-sync', cloud_sync),
		('dependency-graph', dependency_graph),
		('export', export_format),
		('report', report),
		('source', source),
		('format', format_mode),
		('theme', theme),
		('schedule', schedule),
		('snapshot', snapshot),
		('remote', remote),
		('rollback', rollback),
		('update-source', update_source),
		('profile', profile),
		('profile-export', profile_export),
		('profile-import', profile_import),
		('history-package', history_package),
		('import', import_files[0] if import_files else None),
	):
		if isinstance(_val, str) and _val.lower() == 'help':
			_maybe_show_subhelp(_flag)

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
			f'{value!r} is not one of {valid}.{suggestion}',
			param_hint=flag,
		)

	_VALID_EXPORTS = ['json', 'csv', 'html', 'xml', 'markdown', 'md', 'diff']
	_VALID_REPORTS = ['text', 'html', 'json']
	_VALID_FORMATS = ['auto', 'compact', 'verbose', 'json']
	_VALID_THEMES = ['default', 'vibrant', 'minimal', 'dark', 'neon']
	_VALID_CLOUD = ['push', 'pull', 'status', 'help']
	_VALID_SCHEDULE = ['create', 'delete', 'list', 'status', 'run', 'eval', 'help']
	_VALID_SNAPSHOT = ['list', 'show', 'delete', 'help']
	_VALID_REMOTE = ['list', 'add', 'remove', 'scan', 'update', 'report', 'help']
	_VALID_DEP_GRAPH = ['dot', 'conflicts', 'minimal', 'help']

	if export_format and export_format not in _VALID_EXPORTS:
		_bail('--export', export_format, _VALID_EXPORTS)
	if report and report not in _VALID_REPORTS:
		_bail('--report', report, _VALID_REPORTS)
	if format_mode and format_mode not in _VALID_FORMATS:
		_bail('--format', format_mode, _VALID_FORMATS)
	if theme and theme not in _VALID_THEMES:
		_bail('--theme', theme, _VALID_THEMES)
	if cloud_sync and cloud_sync not in _VALID_CLOUD:
		_bail('--cloud-sync', cloud_sync, _VALID_CLOUD)
	if dependency_graph and dependency_graph not in _VALID_DEP_GRAPH:
		_bail('--dependency-graph', dependency_graph, _VALID_DEP_GRAPH)
	if schedule and schedule not in _VALID_SCHEDULE:
		_bail('--schedule', schedule, _VALID_SCHEDULE)
	if snapshot and snapshot not in _VALID_SNAPSHOT:
		_bail('--snapshot', snapshot, _VALID_SNAPSHOT)
	if remote and remote not in _VALID_REMOTE:
		_bail('--remote', remote, _VALID_REMOTE)

	args = CLIOptions(
		source=source,
		exclude=exclude,
		update_source=update_source,
		update_all=update_all,
		dry_run=dry_run,
		yes=yes,
		no_cache=no_cache,
		clear_cache=clear_cache,
		profile=profile,
		profile_export=profile_export,
		profile_import=profile_import,
		save_config=save_config,
		format=format_mode,
		theme=theme,
		interactive=interactive,
		show_all=show_all,
		notify=notify,
		export=export_format,
		output=export_file,
		html_template=html_template,
		html_logo=html_logo,
		html_title=html_title,
		html_company=html_company,
		package=update_package,
		version=version,
		history=history,
		history_package=history_package,
		history_trends=history_trends,
		history_stale=history_stale,
		report=report,
		report_output=report_output,
		dependency_graph=dependency_graph,
		graph_output=graph_output,
		import_files=import_files,
		merge_with_cache=merge_with_cache,
		list_plugins=list_plugins,
		list_plugins_detail=list_plugins_detail,
		no_plugins=no_plugins,
		cloud_sync=cloud_sync,
		schedule=schedule,
		schedule_name=schedule_name,
		schedule_when=schedule_when,
		schedule_time=schedule_time,
		schedule_days=schedule_days,
		schedule_args=schedule_args,
		snapshot=snapshot,
		snapshot_id=snapshot_id,
		rollback=rollback,
		remote=remote,
		remote_host=remote_host,
		remote_group=remote_group,
		remote_address=remote_address,
		remote_user=remote_user,
		remote_groups=remote_groups,
		remote_args=remote_args,
		remote_output=remote_output,
		remote_timeout=remote_timeout,
		remote_verbose=remote_verbose,
		remote_debug=remote_debug,
		debug=debug,
		log=log,
	)
	try:
		args.validate()
	except ValueError as e:
		raise typer.BadParameter(str(e)) from e

	if no_plugins:
		from system_update.plugins import disable_plugin_loading

		disable_plugin_loading()
	SystemUpdateApp().run(args)


def _main_entry() -> None:
	"""Console-script entry point (``system-update`` and ``python -m system_update``).

	Runs the pre-Typer sub-help intercept first so ``--<bool-flag> help`` works.
	"""
	if _intercept_subhelp_argv():
		sys.exit(0)
	if any(arg in ('--help', '-h') for arg in sys.argv[1:]):
		print_banner()
	app()


if __name__ == '__main__':
	_main_entry()
