"""Top-level UI: banner, summary, apps table, and security views."""

from __future__ import annotations

from typing import Dict, List, Optional

from rich import box
from rich.table import Table
from rich.text import Text

from system_update.config import SystemConfig
from system_update.models import AppInfo, UpdateStatus
from system_update.ui.theme import ThemeManager
from system_update.utils import console, source_badge

_VERSION = '5.2.0'
_SEVERITY_PRIORITY = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}
_SEVERITY_COLORS = {
	'CRITICAL': 'bold red',
	'HIGH': 'red',
	'MEDIUM': 'yellow',
	'LOW': 'green',
}
_TABLE_SEVERITY_COLORS = {**_SEVERITY_COLORS, 'CRITICAL': 'bold red blink'}


def display_banner(config: SystemConfig) -> None:
	"""Render the ``System Update Python`` header and data-directory paths."""
	rule = '─' * 70
	title = f'🚀 System Update Python v{_VERSION}'
	sub = f'⚙️ Data dir: {config.config_dir}'

	console.print(f'[cyan]┌{rule}┐[/cyan]')
	console.print(f'[cyan]│[/cyan] [bold cyan]{title.ljust(69)}[/bold cyan][cyan]│[/cyan]')
	console.print(f'[cyan]│[/cyan] [dim cyan]{sub.ljust(69)}[/dim cyan][cyan]│[/cyan]')
	console.print(f'[cyan]└{rule}┘[/cyan]')

	console.print(f'[dim white]Files in {config.config_dir}:[/dim white]')
	for label, path in (
		('cache.json', config.cache_file),
		('config.json', config.config_file),
		('errors.log', config.config_dir / 'errors.log'),
		('system.log', config.log_file),
		('vulnerability_history.json', config.config_dir / 'vulnerability_history.json'),
	):
		console.print(f'  [dim white]{label} → {path}[/dim white]')
	console.print()


def display_summary(
	total_apps: int,
	updates: int,
	scan_time: float,
	sources_count: Dict[str, int],
	show_all: bool = False,  # noqa: ARG001 — reserved for future "all apps" variant
) -> None:
	"""Print the 4-line scan summary with per-source counts."""
	console.print('[bold magenta]📊 Summary[/bold magenta]')
	console.print(f'📦 total apps     [bold white]{total_apps}[/bold white]')
	console.print(f'🔄 updates        [bold yellow]{updates}[/bold yellow]')
	console.print(f'⏱️ scan duration  [bold white]{scan_time:.2f}s[/bold white]')

	parts = [
		f'{source_badge(s)}:[bold white]{c}[/bold white]'
		for s, c in sorted(sources_count.items())
		if c > 0
	]
	console.print(f'⚙️ sources        {", ".join(parts)}')
	console.print()


def _latest_cell(app: AppInfo) -> object:
	"""Build the ``Latest`` column value for one app row."""
	if app.latest_version and app.update_status in (
		UpdateStatus.UPDATE_AVAILABLE, UpdateStatus.VULNERABLE,
	):
		return Text(app.latest_version, style='bold yellow')
	if app.update_status == UpdateStatus.UP_TO_DATE:
		return '-'
	return app.latest_version or '-'


def create_apps_table(
	apps: List[AppInfo],
	title: str = 'Installed Applications',  # noqa: ARG001 — kept for API compat
	show_all: bool = False,
	theme: str = 'default',
	use_icons: bool = False,
) -> Table:
	"""Build the main packages table.

	By default only ``UPDATE_AVAILABLE`` / ``VULNERABLE`` rows are shown; pass
	``show_all=True`` to include everything.
	"""
	display_apps = (
		apps if show_all
		else [
			app for app in apps
			if app.update_status in (UpdateStatus.UPDATE_AVAILABLE, UpdateStatus.VULNERABLE)
		]
	)

	theme_data = ThemeManager.get_theme(theme)
	table = Table(
		box=theme_data.get('box', box.SIMPLE),
		show_header=True,
		show_lines=theme_data.get('show_lines', False),
		header_style=theme_data['header_style'],
		border_style=theme_data['border_style'],
		pad_edge=False,
	)
	table.add_column('Package', style='bold white', width=30, justify='left')
	table.add_column('Source', width=16, justify='left')
	table.add_column('Current', width=20, style='white', justify='left')
	table.add_column('Latest', width=20, justify='left')
	table.add_column('Status', width=17, justify='left')

	for app in sorted(display_apps, key=lambda x: (x.source, x.name)):
		src_color = ThemeManager.get_source_color(app.source, theme)
		src_icon = ThemeManager.get_source_icon(app.source) + ' ' if use_icons else ''
		status_color = ThemeManager.get_status_color(app.update_status.name.lower(), theme)

		table.add_row(
			app.name[:30],
			f'[{src_color}]{src_icon}{app.source}[/{src_color}]',
			app.version,
			_latest_cell(app),
			f'[{status_color}]{app.status_display}[/{status_color}]',
		)
	return table


def compute_security_stats(vulns: List[Dict]) -> Dict:
	"""Aggregate a list of vulnerability dicts into summary counts."""
	severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
	if not vulns:
		return {
			'total_vulnerabilities': 0,
			'open_vulnerabilities': 0,
			'severity_breakdown': severity_counts,
			'critical_count': 0,
			'high_count': 0,
			'medium_count': 0,
			'low_count': 0,
			'packages_affected': 0,
			'persistent_vulnerabilities': 0,
		}

	packages: set[str] = set()
	for v in vulns:
		sev = v.get('severity', '').upper()
		key = sev if sev in severity_counts else 'MEDIUM'
		severity_counts[key] += 1
		packages.add(v.get('package', ''))

	total = sum(severity_counts.values())
	return {
		'total_vulnerabilities': total,
		'open_vulnerabilities': total,
		'severity_breakdown': severity_counts,
		'critical_count': severity_counts['CRITICAL'],
		'high_count': severity_counts['HIGH'],
		'medium_count': severity_counts['MEDIUM'],
		'low_count': severity_counts['LOW'],
		'packages_affected': len(packages),
		'persistent_vulnerabilities': 0,
	}


def display_security_summary(stats: Dict) -> None:
	"""Print the coloured severity breakdown from :func:`compute_security_stats`."""
	if not stats or stats.get('total_vulnerabilities', 0) == 0:
		return

	console.print()
	console.print('[bold magenta]📈 Security Summary[/bold magenta]')

	breakdown = stats.get('severity_breakdown', {})
	parts = [
		f'[{_SEVERITY_COLORS[sev]}]{sev}[/{_SEVERITY_COLORS[sev]}]: {breakdown.get(sev, 0)}'
		for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
		if breakdown.get(sev, 0) > 0
	]
	if parts:
		console.print('  ' + ' | '.join(parts))

	console.print(
		f'  📦 Packages affected: [bold white]{stats.get("packages_affected", 0)}[/bold white]'
	)
	console.print(
		f'  🔁 Persistent (3+ scans): [bold yellow]{stats.get("persistent_vulnerabilities", 0)}[/bold yellow]'
	)
	console.print()


def _security_title(critical_count: int) -> str:
	if critical_count > 0:
		return (
			f'[bold red]🚨 CRITICAL ALERT: {critical_count} '
			'Critical Vulnerability(ies) Found![/bold red]'
		)
	return '[bold red]🔥 Security Vulnerabilities Detected[/bold red]'


def _cvss_display(vuln: Optional[object]) -> str:
	if vuln is None:
		return '-'
	score = vuln.get('cvss_score') if hasattr(vuln, 'get') else getattr(vuln, 'cvss_score', None)
	return f'{score:.1f}' if isinstance(score, (int, float)) else '-'


def create_security_table(security_results: List) -> Table:
	"""Build the red/heavy-edge table of scanned security findings."""
	sorted_results = sorted(
		security_results,
		key=lambda r: _SEVERITY_PRIORITY.get(r.highest_severity, 99),
	)
	critical_count = sum(1 for r in sorted_results if r.highest_severity == 'CRITICAL')

	table = Table(
		title=_security_title(critical_count),
		box=box.HEAVY_EDGE,
		border_style='red',
		show_lines=True,
	)
	table.add_column('Package', style='cyan')
	table.add_column('Severity', justify='center')
	table.add_column('CVSS', justify='center')
	table.add_column('CVE', justify='center')
	table.add_column('Description', style='dim', width=50)

	for result in sorted_results:
		severity = result.highest_severity
		color = _TABLE_SEVERITY_COLORS.get(severity, 'white')
		alert = '🚨 ' if severity == 'CRITICAL' else ''
		first_vuln = result.vulnerabilities[0] if result.vulnerabilities else None
		desc = first_vuln.description if first_vuln else 'Unknown'

		table.add_row(
			result.app_info.name,
			f'[{color}]{alert}{severity}[/{color}]',
			_cvss_display(first_vuln),
			str(result.total_vulnerabilities),
			desc,
		)

	return table


class UISystem:
	"""Static-method facade preserving the legacy ``UISystem`` API."""

	display_banner = staticmethod(display_banner)
	display_summary = staticmethod(display_summary)
	create_apps_table = staticmethod(create_apps_table)
	compute_security_stats = staticmethod(compute_security_stats)
	display_security_summary = staticmethod(display_security_summary)
	create_security_table = staticmethod(create_security_table)


__all__ = [
	'UISystem',
	'compute_security_stats',
	'create_apps_table',
	'create_security_table',
	'display_banner',
	'display_security_summary',
	'display_summary',
]
