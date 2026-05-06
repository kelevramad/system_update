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
		('drivers', 'Windows driver packages via pnputil'),
		('services', 'Windows services and executable versions'),
		('psmodules', 'Installed PowerShell modules'),
		('vsextensions', 'Visual Studio Code extensions'),
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


def _page_schedule(console: Console) -> None:
	_header(
		console,
		'🗓️  --schedule — Detailed Help',
		'Manage Windows Task Scheduler entries that run [bold]system-update[/bold] '
		'on a recurring schedule. Linux/macOS users should configure cron / '
		'systemd / launchd manually.',
	)
	_action_table(console, [
		('create', 'Create or replace a scheduled task.'),
		('delete', 'Remove a scheduled task by name.'),
		('list', 'List every SystemUpdate task registered with the OS.'),
		('status', 'Show last run, next run, exit code, and command line.'),
		('run', 'Trigger the task immediately (out-of-band).'),
		('eval', 'Run a scan and evaluate conditional_actions rules. Used by tasks.'),
		('help', 'Print this page.'),
	])
	t = Table(title='Companion flags', show_header=True, header_style='bold')
	t.add_column('Flag', style='cyan', no_wrap=True)
	t.add_column('Default')
	t.add_column('Notes')
	t.add_row('--schedule-name', 'SystemUpdate_Scan', 'Task identifier in Task Scheduler.')
	t.add_row('--schedule-when', 'daily',
		'One of: [yellow]daily, weekly, hourly, monthly, onstart, onlogon[/yellow].')
	t.add_row('--schedule-time', '09:00', 'HH:MM. Required for daily/weekly/monthly.')
	t.add_row('--schedule-days', '(empty)',
		'Weekly only — e.g. [yellow]MON,WED,FRI[/yellow].')
	t.add_row('--schedule-args', '--no-cache --notify',
		'Arguments the scheduled run will pass to system-update.')
	console.print(t)
	console.print()
	console.print('[bold]Conditional actions ([yellow]conditional_actions[/yellow] in config.json)[/bold]')
	console.print(
		'  • Predicates: [cyan]any_updates, any_vulnerabilities, any_critical_cves, '
		'security_updates_only, n_updates_gte:N, n_vulns_gte:N[/cyan]\n'
		'  • Actions:    [cyan]notify, log, auto_update[/cyan]\n'
	)
	_json_block(console, 'Sample config block', '''{
  "conditional_actions": [
    {"when": "any_critical_cves",      "do": "notify"},
    {"when": "n_updates_gte:20",       "do": "notify"},
    {"when": "security_updates_only",  "do": "auto_update"},
    {"when": "any_vulnerabilities",    "do": "log"}
  ]
}''')
	_examples(console, [
		('system-update --schedule create --schedule-when daily --schedule-time 03:00', '# nightly 3 AM scan'),
		('system-update --schedule create --schedule-when weekly --schedule-days MON,FRI --schedule-time 09:00', '# Mon+Fri 9 AM'),
		('system-update --schedule create --schedule-when onlogon --schedule-args "--source winget --notify"', '# at logon'),
		('system-update --schedule list', ''),
		('system-update --schedule status --schedule-name SystemUpdate_Scan', ''),
		('system-update --schedule run --schedule-name SystemUpdate_Scan', '# fire immediately'),
		('system-update --schedule eval', '# evaluate conditional_actions'),
		('system-update --schedule delete --schedule-name SystemUpdate_Scan', ''),
	])


def _page_remote(console: Console) -> None:
	_header(
		console,
		'🌐 --remote — Detailed Help',
		'Manage and run [bold]system-update[/bold] across multiple Windows '
		'machines via [cyan]winrs[/cyan] (built into Windows). Inventory lives '
		'at [yellow]~/.system_update/inventory.json[/yellow].',
	)
	_action_table(console, [
		('list',   'Show all hosts in the inventory.'),
		('add',    'Add or replace a host (use [cyan]--remote-host NAME[/cyan]).'),
		('remove', 'Remove a host by name.'),
		('scan',   'Run a JSON scan on the target host(s) and print per-host summary.'),
		('update', 'Run [cyan]--update-all --yes[/cyan] on the target host(s).'),
		('report', 'Scan + emit consolidated JSON across hosts ([cyan]--remote-output[/cyan]).'),
		('help',   'Print this page.'),
	])
	t = Table(title='Companion flags', show_header=True, header_style='bold')
	t.add_column('Flag', style='cyan', no_wrap=True)
	t.add_column('Notes')
	t.add_row('--remote-host NAME', 'Single target. Required for add / remove.')
	t.add_row('--remote-group NAME', 'Run against every host whose ``groups`` includes NAME.')
	t.add_row('--remote-address ADDR', 'Hostname/IP for [cyan]add[/cyan] (defaults to NAME).')
	t.add_row('--remote-user USER', 'Username for winrs (e.g. [yellow]DOMAIN\\\\admin[/yellow]).')
	t.add_row('--remote-groups CSV', 'Comma-list of groups for [cyan]add[/cyan].')
	t.add_row('--remote-args "..."', 'Extra args appended to the remote system-update call.')
	t.add_row('--remote-output PATH', 'Where [cyan]report[/cyan] writes its JSON.')
	t.add_row('--remote-timeout SECS', 'Per-host timeout (default 600).')
	t.add_row(
		'--remote-verbose',
		'Stream each host\'s stdout/stderr tail as it completes (great for '
		'debugging WinRM auth or trust failures).',
	)
	t.add_row(
		'--remote-debug',
		'Print redacted winrs argv, target metadata, timeout, and completion output. '
		'Use when a host appears stuck.',
	)
	console.print(t)
	console.print()
	console.print('[bold]Credentials[/bold]')
	console.print(
		'  • Set [yellow]SYSTEM_UPDATE_REMOTE_PASS[/yellow] in env to avoid '
		'embedding passwords on the command line.\n'
		'  • [cyan]winrs[/cyan] requires WinRM to be enabled on the target '
		'([cyan]winrm quickconfig[/cyan]) and a trusted-hosts entry on the '
		'caller ([cyan]winrm set winrm/config/client \'@{TrustedHosts="*"}\'[/cyan]).\n'
	)
	_examples(console, [
		('system-update --remote add --remote-host build01 --remote-user "DOMAIN\\\\admin" --remote-groups builders,windows', '# register'),
		('system-update --remote list', ''),
		('system-update --remote scan --remote-group builders', '# fan-out scan'),
		('system-update --remote scan --remote-host build01 --remote-debug', '# show winrs argv'),
		('system-update --remote update --remote-host build01 --remote-args "--source winget"', ''),
		('system-update --remote report --remote-group builders --remote-output fleet.json', ''),
		('system-update --remote remove --remote-host build01', ''),
	])


def _page_snapshot(console: Console) -> None:
	_header(
		console,
		'📸 --snapshot — Detailed Help',
		'Inspect the version snapshots that [bold]system-update[/bold] records '
		'automatically before every batch update. Pair with [cyan]--rollback[/cyan] '
		'to restore a prior state.',
	)
	_action_table(console, [
		('list', 'List recent snapshots (id, timestamp, package count, success).'),
		('show', 'Show every package recorded in a snapshot. Use [cyan]--snapshot-id[/cyan] or pass [cyan]last[/cyan] (default).'),
		('delete', 'Drop a snapshot. Use [cyan]--snapshot-id ID[/cyan].'),
		('help', 'Print this page.'),
	])
	console.print('[bold]How they get created[/bold]')
	console.print(
		'  Every successful [cyan]--update-all[/cyan], [cyan]--update-source[/cyan], '
		'or [cyan]--interactive[/cyan] batch records a snapshot under '
		'[yellow]~/.system_update/history.db[/yellow]\n'
		'  in the [cyan]snapshots[/cyan] / [cyan]snapshot_packages[/cyan] tables.\n'
	)
	_examples(console, [
		('system-update --snapshot list', '# all snapshots'),
		('system-update --snapshot show', '# most recent'),
		('system-update --snapshot show --snapshot-id 20260426-150000', '# specific'),
		('system-update --snapshot delete --snapshot-id 20260426-150000', ''),
	])
	console.print('[dim]→ Tied to[/dim] [cyan]--rollback[/cyan]')


def _page_rollback(console: Console) -> None:
	_header(
		console,
		'⏪ --rollback — Detailed Help',
		'Restore packages to the versions captured in a snapshot. Useful when an '
		'update breaks something — re-installs the prior version per source.',
		color='yellow',
	)
	_action_table(console, [
		('<snapshot-id>', 'Roll back the specific snapshot.'),
		('last',          'Roll back the most recent snapshot.'),
		('help',          'Print this page.'),
	])
	console.print('[bold]Supported sources[/bold]')
	console.print(
		'  [green]✓[/green] winget, chocolatey, npm, pnpm, bun, yarn, pip\n'
		'  [yellow]✗[/yellow] PATH, registry, scoop, dotnet, rust, appx, msix, '
		'drivers, services, psmodules, vsextensions '
		'[dim](no version-pinning install command)[/dim]\n'
	)
	console.print('[bold]Flags it honours[/bold]')
	console.print(
		'  • [cyan]--dry-run[/cyan] — print rollback commands without executing\n'
		'  • [cyan]--yes[/cyan] — skip the confirmation prompt\n'
	)
	_examples(console, [
		('system-update --rollback last', '# undo the most recent batch'),
		('system-update --rollback 20260426-150000', '# specific snapshot'),
		('system-update --rollback last --dry-run', '# preview only'),
		('system-update --rollback last --yes', '# no confirmation'),
	])


def _page_update_source(console: Console) -> None:
	_header(
		console,
		'📦 --update-source — Detailed Help',
		'Shorthand for [bold]--source X --update-all[/bold]. Lists every '
		'available update from one source and prompts for confirmation before '
		'applying them. Add [bold]--yes[/bold] to skip the prompt or '
		'[bold]--dry-run[/bold] to preview without executing.',
	)
	_examples(console, [
		('system-update --update-source npm', '# review + confirm before applying'),
		('system-update --update-source npm --yes', '# skip the prompt'),
		('system-update --update-source pip --dry-run', '# preview only'),
	])


def _page_dependency_graph(console: Console) -> None:
	_header(
		console,
		'🕸️ --dependency-graph — Detailed Help',
		'Build a best-effort dependency graph from the current scan/cache/import data. '
		'The graph can be exported as Graphviz DOT, inspected for version conflicts, '
		'or reduced to a minimal direct update set.',
	)
	t = Table(title='Actions', show_header=True, header_style='bold')
	t.add_column('Action', style='cyan', no_wrap=True)
	t.add_column('What it does')
	t.add_row('dot', 'Write a Graphviz DOT file. Use --graph-output to choose the path.')
	t.add_row('conflicts', 'Show packages observed with multiple installed versions.')
	t.add_row('minimal', 'Suggest direct updates, omitting dependency updates covered by parent updates.')
	console.print(t)
	console.print()
	console.print('[bold]Dependency metadata[/bold]')
	console.print(
		'  • [cyan]npm[/cyan] / [cyan]pnpm[/cyan]: reads global list output at depth 1.\n'
		'  • [cyan]pip[/cyan]: reads [cyan]pip show[/cyan] metadata from the scanned interpreter.\n'
		'  • Other sources are included as nodes; dependency edges are added when metadata is available.\n'
		'  • Imported or cached scans work too, with graceful fallback to node-only graphs.\n'
	)
	_examples(console, [
		('system-update --dependency-graph dot --graph-output deps.dot', '# Graphviz file'),
		('system-update --dependency-graph conflicts --show-all', '# version conflicts'),
		('system-update --dependency-graph minimal', '# direct update plan'),
	])


# ─── Registry ──────────────────────────────────────────────────────────────


_REGISTRY: Dict[str, Callable[[Console], None]] = {
	'cloud-sync': _page_cloud_sync,
	'dependency-graph': _page_dependency_graph,
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
	'schedule': _page_schedule,
	'snapshot': _page_snapshot,
	'rollback': _page_rollback,
	'remote': _page_remote,
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
