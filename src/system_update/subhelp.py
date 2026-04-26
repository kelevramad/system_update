"""Detailed sub-help pages for flags whose top-level ``--help`` line is too
short to be useful on its own.

Two ways to trigger a page:

* ``--<flag> help`` — works for choice-style flags (e.g. ``--cloud-sync help``,
  ``--export help``).
* ``--explain <flag>`` — works for any flag, including booleans
  (e.g. ``--explain interactive``).

Pages live here so ``cli.py`` stays focused on argument plumbing.
"""

from __future__ import annotations

from typing import Callable, Dict

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from system_update.utils import console as _default_console


# ─── Helpers ───────────────────────────────────────────────────────────────


def _header(console: Console, title: str, subtitle: str, color: str = 'cyan') -> None:
	console.print(
		Panel.fit(subtitle, title=title, border_style=color)
	)


def _action_table(console: Console, rows: list, *, title: str = 'Actions') -> None:
	t = Table(title=title, show_header=True, header_style='bold')
	t.add_column('Value', style='cyan', no_wrap=True)
	t.add_column('Effect')
	for v, eff in rows:
		t.add_row(v, eff)
	console.print(t)
	console.print()


def _examples(console: Console, rows: list) -> None:
	t = Table(title='Examples', show_header=False, box=None)
	t.add_column(style='cyan', no_wrap=True)
	t.add_column(style='dim')
	for cmd, comment in rows:
		t.add_row(cmd, comment)
	console.print(t)
	console.print()


def _json_block(console: Console, label: str, body: str) -> None:
	console.print(f'[bold]{label}[/bold]')
	console.print(Syntax(body, 'json', theme='ansi_dark', line_numbers=False))
	console.print()


# ─── Pages ─────────────────────────────────────────────────────────────────


def _page_cloud_sync(console: Console) -> None:
	_header(
		console,
		'☁️  --cloud-sync — Detailed Help',
		'Sync the scan cache across devices. Pick a backend, write the config '
		'block once, then push/pull anywhere.',
	)
	_action_table(console, [
		('push', 'Upload local cache to the configured target.'),
		('pull', 'Download the remote cache and overwrite the local copy.'),
		('status', 'Show backend type, target, and local/remote sizes + mtimes.'),
		('help', 'Print this page.'),
	])
	t = Table(title='Backends', show_header=True, header_style='bold')
	t.add_column('Type', style='cyan', no_wrap=True)
	t.add_column('Target')
	t.add_column('How it works')
	t.add_row('file', 'Folder path',
		'Writes/reads [yellow]<target>/<filename>[/yellow]. Point this at OneDrive, '
		'Dropbox, Google Drive, iCloud, or a network share for free cross-device sync.')
	t.add_row('http', 'URL',
		'PUT on push, GET on pull. Add [yellow]auth_header[/yellow] '
		'(e.g. [italic]"Bearer xxx"[/italic]) for protected endpoints.')
	console.print(t)
	console.print()
	_json_block(console, 'Config block  (~/.system_update/config.json)', '''{
  "cloud_sync": {
    "enabled": true,
    "type": "file",
    "target": "C:/Users/me/OneDrive/system_update",
    "filename": "cache.json"
  }
}''')
	_json_block(console, 'HTTP variant', '''{
  "cloud_sync": {
    "enabled": true,
    "type": "http",
    "target": "https://my-server.example.com/api/system-update/cache",
    "auth_header": "Bearer ey..."
  }
}''')
	_examples(console, [
		('system-update --cloud-sync push', '# upload local cache'),
		('system-update --cloud-sync pull', '# fetch remote'),
		('system-update --cloud-sync status', '# show sync state'),
	])


def _page_report(console: Console) -> None:
	_header(
		console,
		'🧾 --report — Detailed Help',
		'Generate a [bold]history report[/bold] (different from [bold]--export[/bold] '
		'which exports the current scan). Aggregates scans, trends, stale packages, '
		'and vulnerability stats.',
	)
	_action_table(console, [
		('text', 'Plain-text dump (stdout or [yellow]--report-output[/yellow] file).'),
		('json', 'Machine-readable JSON. All sections in one object.'),
		('html', 'Self-contained branded HTML (KPIs + scan/trend/stale/vuln tables).'),
	], title='Formats')
	console.print('[bold]Sections included in every format[/bold]')
	console.print(
		'  • Recent scans (timestamp, source, pkgs, updates, vulns)\n'
		'  • Trends — last 30 days per source + unique packages tracked\n'
		'  • Stale packages — last seen >90 days ago\n'
		'  • Vulnerability stats — open / resolved / by severity / persistent\n'
	)
	console.print(
		'[dim]HTML branding is shared with [bold]--export html[/bold]: '
		'[bold]--html-title[/bold], [bold]--html-company[/bold], '
		'[bold]--html-logo[/bold] all apply.[/dim]\n'
	)
	_examples(console, [
		('system-update --report text', '# print to stdout'),
		('system-update --report json --report-output history.json', '# CI-friendly'),
		('system-update --report html --report-output history.html', '# branded HTML'),
		('system-update --report html --html-title "Q2 Audit" --html-logo logo.png --report-output q2.html', '# branded'),
	])


def _page_interactive(console: Console) -> None:
	_header(
		console,
		'🖱️  --interactive — Detailed Help',
		'Numbered TUI picker for selecting which packages to update. Vulnerable '
		'packages appear first, tagged [red]\\[VULN][/red].',
	)
	_action_table(console, [
		('all', 'Select every listed package.'),
		('none', 'Select nothing — exits cleanly.'),
		('1,3,5', 'Pick individual indices.'),
		('5-7', 'Pick a contiguous range.'),
		('1,3,5-7', 'Mix of indices and ranges.'),
	], title='Selection syntax')
	console.print('[bold]Flag interactions[/bold]')
	console.print(
		'  • [cyan]--dry-run[/cyan] → preview only, no real updates\n'
		'  • [cyan]--yes[/cyan]     → skip the final confirmation prompt\n'
		'  • [cyan]--source X[/cyan] → restrict picker to one or more sources\n'
		'  • [cyan]Ctrl-C[/cyan] / EOF → cancel safely at any prompt\n'
	)
	_examples(console, [
		('system-update --interactive', '# pick from all updates'),
		('system-update --interactive --source chocolatey', '# only choco'),
		('system-update --interactive --dry-run', '# preview'),
		('system-update --interactive --yes', '# no confirmation step'),
	])


def _page_export(console: Console) -> None:
	_header(
		console,
		'📤 --export — Detailed Help',
		'Export the current scan results to a file. Pair with [bold]--output[/bold] / [bold]-o[/bold].',
	)
	t = Table(title='Formats', show_header=True, header_style='bold')
	t.add_column('Format', style='cyan', no_wrap=True)
	t.add_column('Best for')
	t.add_column('Notes')
	t.add_row('json', 'Machines / CI', 'Full schema, includes security findings.')
	t.add_row('csv', 'Spreadsheets', 'One row per package.')
	t.add_row('html', 'Humans / reports', 'Branded report. Custom template + logo supported.')
	t.add_row('xml', 'Legacy systems', 'Hierarchical XML.')
	t.add_row('markdown / md', 'Wikis / docs', 'GitHub-flavored markdown table.')
	t.add_row('diff', 'Changelogs', 'Shows what changed since the previous scan.')
	console.print(t)
	console.print()
	console.print('[bold]HTML-only flags[/bold]')
	console.print(
		'  • [cyan]--html-template PATH[/cyan] — custom template (placeholder-based)\n'
		'  • [cyan]--html-logo PATH[/cyan]     — embed PNG/JPG/SVG as base64\n'
		'  • [cyan]--html-title STR[/cyan]     — override report title\n'
		'  • [cyan]--html-company STR[/cyan]   — company name in header\n'
	)
	_examples(console, [
		('system-update --export json -o scan.json', '# CI artifact'),
		('system-update --export html -o report.html', '# default branding'),
		('system-update --export html -o branded.html --html-title "Audit" --html-logo logo.png', '# branded'),
		('system-update --export diff -o changes.txt', '# changes since last scan'),
		('system-update --export csv -o pkgs.csv --show-all', '# every package'),
	])


def _page_source(console: Console) -> None:
	_header(
		console,
		'🎯 --source — Detailed Help',
		'Limit the scan (and any updates) to one or more sources. Comma-separated, '
		'order-independent, case-insensitive.',
	)
	t = Table(title='Valid sources', show_header=True, header_style='bold')
	t.add_column('Source', style='cyan', no_wrap=True)
	t.add_column('What it covers')
	for src, desc in [
		('winget', 'Windows Package Manager'),
		('chocolatey', 'Chocolatey (alias: [italic]choco[/italic])'),
		('scoop', 'Scoop'),
		('npm', 'Global npm packages'),
		('pnpm', 'Global pnpm packages'),
		('yarn', 'Global yarn packages'),
		('bun', 'Bun runtime + global packages'),
		('pip', 'Active interpreter + known global Python installs'),
		('rust', 'Cargo / Rust toolchain'),
		('dotnet', 'dotnet global tools'),
		('path', 'Executables on PATH'),
		('registry', 'Windows Uninstall registry'),
		('appx', 'Appx packages (Windows Store)'),
		('msix', 'MSIX packages'),
	]:
		t.add_row(src, desc)
	console.print(t)
	console.print()
	console.print('[bold]Cache behavior[/bold]')
	console.print(
		'  • If requested source is cached → cache hit, no rescan.\n'
		'  • If [italic]some[/italic] requested sources are cached → only the missing ones are\n'
		'    scanned, then merged into the cache (partial-scan + merge).\n'
		'  • Unknown tokens print a warning; mixed valid+invalid proceeds with valid only.\n'
	)
	_examples(console, [
		('system-update --source winget', '# single source'),
		('system-update -s npm,pip', '# multiple'),
		('system-update --source choco', '# alias for chocolatey'),
		('system-update -s winget --no-cache', '# force fresh scan'),
	])


def _page_import(console: Console) -> None:
	_header(
		console,
		'📥 --import — Detailed Help',
		'Load scan data from a JSON or CSV file instead of running a live scan. '
		'Repeatable; multiple files are merged.',
	)
	console.print('[bold]Auto-detection[/bold]')
	console.print(
		'  • [cyan].json[/cyan] suffix → JSON loader\n'
		'  • [cyan].csv[/cyan]  suffix → CSV loader\n'
		'  • Other suffixes try JSON first, fall back to CSV.\n'
	)
	console.print('[bold]JSON shapes accepted[/bold]')
	console.print(
		'  • A bare list:                [yellow][{...}, {...}][/yellow]\n'
		'  • An object with a key:       [yellow]{"packages": [{...}]}[/yellow]\n'
		'    (also recognised: [italic]apps, items, data[/italic])\n'
	)
	_json_block(console, 'Minimal JSON entry', '''{
  "name": "git",
  "source": "winget",
  "version": "2.40.0",
  "latestVersion": "2.41.0",
  "status": "update_available",
  "scanTime": "2026-04-25T12:00:00.000Z"
}''')
	console.print('[bold]CSV header expected[/bold]')
	console.print(
		'  [yellow]Name,Source,Version,Latest,Status[/yellow] '
		'(snake_case variants also accepted)\n'
	)
	console.print('[bold]Combine with[/bold]')
	console.print(
		'  • [cyan]--merge[/cyan] → fold into the existing cache (latest [italic]scanTime[/italic] wins)\n'
		'  • [cyan]--export html[/cyan] → render imported data as a report\n'
	)
	_examples(console, [
		('system-update --import scan.json', '# replace cache with imported'),
		('system-update --import a.json --import b.csv', '# merge two files'),
		('system-update --import remote.json --merge', '# fold into local cache'),
		('system-update --import scan.json --export html -o report.html', '# render imported data'),
	])


def _page_profile(console: Console) -> None:
	_header(
		console,
		'👤 --profile — Detailed Help',
		'Switch between named configuration profiles. Each profile has isolated '
		'config, cache, history, and vulnerability log.',
	)
	console.print('[bold]Storage layout[/bold]')
	console.print(
		'  [yellow]~/.system_update/profiles/<name>/config.json[/yellow]\n'
		'  [yellow]~/.system_update/profiles/<name>/cache.json[/yellow]\n'
		'  [yellow]~/.system_update/profiles/<name>/history.db[/yellow]\n'
	)
	_action_table(console, [
		('--profile NAME', 'Activate profile NAME for this run.'),
		('--profile-export PATH', 'Export active profile config to a JSON file.'),
		('--profile-import PATH', 'Import profile config from a JSON file.'),
	], title='Related flags')
	_examples(console, [
		('system-update --profile work', '# use the "work" profile'),
		('system-update --profile-export work.json', '# back up current config'),
		('system-update --profile-import work.json', '# restore from JSON'),
	])


def _page_theme(console: Console) -> None:
	_header(
		console,
		'🌈 --theme — Detailed Help',
		'Switch the terminal UI palette. Affects spinners, tables, banners, and chips.',
	)
	_action_table(console, [
		('default', 'Balanced palette — cyan/yellow/red. Default.'),
		('vibrant', 'Saturated colors, high contrast.'),
		('minimal', 'Monochrome — best for CI logs / piping.'),
		('dark', 'Tuned for dark terminals.'),
		('neon', 'Neon accents — fun, high-energy.'),
	], title='Themes')
	_examples(console, [
		('system-update --theme vibrant', ''),
		('system-update --theme minimal --no-cache', '# CI run'),
	])


def _page_format(console: Console) -> None:
	_header(
		console,
		'🎛️  --format — Detailed Help',
		'Control how the result table is rendered.',
	)
	_action_table(console, [
		('auto', 'Default — picks best layout for terminal width.'),
		('compact', 'Dense rows — fits more on small screens.'),
		('verbose', 'All columns — name, source, current, latest, status, app id.'),
		('json', 'Machine-readable JSON to stdout. Skips Rich rendering.'),
	], title='Formats')
	_examples(console, [
		('system-update --format compact', ''),
		('system-update --format json | jq .', '# pipe through jq'),
	])


def _page_notify(console: Console) -> None:
	_header(
		console,
		'🔔 --notify — Detailed Help',
		'Send a notification when updates are available. Backends are pluggable '
		'and configured under [yellow]notifications[/yellow] in config.json.',
	)
	t = Table(title='Backends', show_header=True, header_style='bold')
	t.add_column('Type', style='cyan', no_wrap=True)
	t.add_column('Notes')
	t.add_row('toast', 'Windows native toast (no config needed).')
	t.add_row('email', 'SMTP — set [yellow]smtp_host/port/user/password/from/to[/yellow].')
	t.add_row('email_api', 'REST — set [yellow]url/auth_header/from/to[/yellow] (curl-driven).')
	t.add_row('webhook', 'POST JSON to a URL (Slack, Discord, Teams, etc.).')
	t.add_row('script', 'Run an arbitrary script with the alert as JSON via stdin.')
	console.print(t)
	console.print()
	_json_block(console, 'Config block', '''{
  "notifications": {
    "enabled": true,
    "channels": ["toast", "webhook"],
    "webhook_url": "https://hooks.slack.com/services/...",
    "min_severity": "high"
  }
}''')
	_examples(console, [
		('system-update --notify', '# fire all configured channels'),
		('system-update --notify --update-all -y', '# notify + apply'),
	])


def _page_history_trends(console: Console) -> None:
	_header(
		console,
		'📈 --history-trends — Detailed Help',
		'Aggregate update activity across the last 30 days, grouped by source.',
	)
	console.print('[bold]Output columns[/bold]')
	console.print(
		'  • [cyan]Source[/cyan]        — package source identifier\n'
		'  • [cyan]Scans[/cyan]         — number of scan sessions in window\n'
		'  • [cyan]Total pkgs[/cyan]    — sum of packages observed\n'
		'  • [cyan]Total updates[/cyan] — sum of update_count across scans\n'
	)
	console.print(
		'[dim]Data source: SQLite [italic]scans[/italic] table at '
		'~/.system_update/history.db.[/dim]\n'
	)


def _page_history_stale(console: Console) -> None:
	_header(
		console,
		'🕰️  --history-stale — Detailed Help',
		'List packages whose [italic]most recent[/italic] entry in the version-history '
		'table is older than N days.',
	)
	console.print('[bold]Definition of "stale"[/bold]')
	console.print(
		'  Stale = MAX([yellow]version_history.timestamp[/yellow]) for (package, source) is\n'
		'  older than N days.\n'
	)
	_examples(console, [
		('system-update --history-stale 30', '# >30 days'),
		('system-update --history-stale 90', '# >3 months'),
		('system-update --history-stale 180', '# half-year unmaintained'),
	])


def _page_update_source(console: Console) -> None:
	_header(
		console,
		'📦 --update-source — Detailed Help',
		'Shorthand for [bold]--source X --update-all --yes[/bold]. Updates every '
		'package from a single source without further prompts.',
	)
	console.print(
		'[yellow]⚠ Equivalent to --yes[/yellow]: confirmation prompts are skipped. '
		'Use [bold]--dry-run[/bold] to preview.\n'
	)
	_examples(console, [
		('system-update --update-source npm', '# update every npm package'),
		('system-update --update-source pip --dry-run', '# preview only'),
	])


# ─── Registry ──────────────────────────────────────────────────────────────


_REGISTRY: Dict[str, Callable[[Console], None]] = {
	'cloud-sync': _page_cloud_sync,
	'report': _page_report,
	'interactive': _page_interactive,
	'export': _page_export,
	'source': _page_source,
	'import': _page_import,
	'profile': _page_profile,
	'profile-export': _page_profile,
	'profile-import': _page_profile,
	'theme': _page_theme,
	'format': _page_format,
	'notify': _page_notify,
	'history-trends': _page_history_trends,
	'history-stale': _page_history_stale,
	'update-source': _page_update_source,
}


def show(flag: str, console: Console = None) -> bool:
	"""Print the detailed help page for ``flag``. Returns ``True`` if printed.

	``flag`` is matched both with and without leading dashes, and with both
	hyphens and underscores.
	"""
	key = flag.lstrip('-').replace('_', '-').lower()
	handler = _REGISTRY.get(key)
	if handler is None:
		return False
	handler(console or _default_console)
	return True


def has_subhelp(flag: str) -> bool:
	key = flag.lstrip('-').replace('_', '-').lower()
	return key in _REGISTRY


def list_topics() -> list:
	"""Return the sorted list of registered help topics (deduped)."""
	# De-dupe profile-* aliases.
	seen = set()
	topics = []
	for k, v in _REGISTRY.items():
		if v in seen:
			continue
		seen.add(v)
		topics.append(k)
	return sorted(topics)


__all__ = ['show', 'has_subhelp', 'list_topics']
