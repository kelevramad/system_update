"""Top-level UI: banner, summary, apps table, and security views."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

from rich import box
from rich.table import Table
from rich.text import Text

from system_update.config import SystemConfig
from system_update.models import AppInfo, UpdateStatus
from system_update.ui.theme import ThemeManager
from system_update.utils import console, display_source, source_chip, source_icon

_VERSION = '8.1.3'
_SEVERITY_PRIORITY = {'CRITICAL': 0, 'HIGH': 1,
                      'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}
_SEVERITY_COLORS = {
    'CRITICAL': 'bold red',
    'HIGH': 'red',
    'MEDIUM': 'yellow',
    'LOW': 'green',
}
_TABLE_SEVERITY_COLORS = {**_SEVERITY_COLORS, 'CRITICAL': 'bold red blink'}


def _format_size(size: int) -> str:
    """Compact human-readable byte count (e.g. 1.2 KB, 4.7 MB)."""
    for unit in ('B', 'KB', 'MB', 'GB'):
        if size < 1024:
            return f'{size:.1f} {unit}' if unit != 'B' else f'{size} {unit}'
        size /= 1024
    return f'{size:.1f} TB'


def _file_row(label: str, path: Path, show_path: bool = True) -> str:
    """Render one file row: ✅/⬜ icon, label, size, mtime, full path."""
    from datetime import datetime

    if path.is_file():
        try:
            stat = path.stat()
            size = _format_size(stat.st_size)
            mtime = datetime.fromtimestamp(
                stat.st_mtime).strftime('%Y-%m-%d %H:%M')
            meta = f'[dim]({size}, {mtime})[/dim]'
        except OSError:
            meta = ''
        marker = '[green]✅[/green]'
        path_style = 'dim cyan'
    else:
        marker = '❌'
        meta = '[dim red](missing)[/dim red]'
        path_style = 'dim white'

    pieces = [marker, f'[white]{label}[/white]', meta]
    if show_path:
        pieces.append(f'[{path_style}]→ {path}[/{path_style}]')
    return '  ' + ' '.join(p for p in pieces if p)


def _python_runtime_info() -> tuple:
    """Return (label, is_venv, raw_path) describing the running interpreter.

    Detects venvs via PEP 405 (``sys.prefix != sys.base_prefix``) and via the
    ``VIRTUAL_ENV`` environment variable. The label includes the venv folder
    name so the user can see WHICH venv is active.
    """
    import os
    import sys

    pyver = f'Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}'
    venv_env = os.environ.get('VIRTUAL_ENV') or os.environ.get('CONDA_PREFIX')
    in_venv = (
        hasattr(sys, 'real_prefix')
        or (getattr(sys, 'base_prefix', sys.prefix) != sys.prefix)
        or bool(venv_env)
    )
    if in_venv:
        venv_path = venv_env or sys.prefix
        venv_name = Path(venv_path).name or venv_path
        # Common venv folder names → derive parent project name for clarity.
        if venv_name.lower() in ('.venv', 'venv', 'env', '.env'):
            parent = Path(venv_path).parent.name
            if parent:
                venv_name = f'{parent}/{venv_name}'
        return (f'{pyver} (venv: {venv_name})', True, sys.executable)
    return (f'{pyver} (system / no venv)', False, sys.executable)


def _file_inventory_table(rows: list) -> Table:
    """Compact 3-column file inventory: status · name · size · mtime.

    The full path is intentionally omitted — the directory header line above
    the table already shows it, and including it forced ugly mid-path
    wrapping inside the banner panel.
    """
    from datetime import datetime

    t = Table(box=None, show_header=False, pad_edge=False, padding=(0, 2))
    t.add_column('', width=2, no_wrap=True)
    t.add_column('Name', style='white', no_wrap=True, min_width=28)
    t.add_column('Size', style='dim', no_wrap=True,
                 justify='right', min_width=10)
    t.add_column('Modified', style='dim', no_wrap=True)
    for label, path in rows:
        if path.is_file():
            try:
                stat = path.stat()
                size = _format_size(stat.st_size)
                mtime = datetime.fromtimestamp(
                    stat.st_mtime).strftime('%Y-%m-%d %H:%M')
            except OSError:
                size, mtime = '-', '-'
            t.add_row('[green]✅[/green]', label, size, mtime)
        else:
            t.add_row('❌', label, '[red]missing[/red]', '')
    return t


def _profile_chip_row(profile: str | None, available: list) -> Text:
    """Build the ``Profiles available:`` chip line as a single Text object."""
    out = Text()
    out.append('Profiles ', style='dim')
    if not available:
        out.append('none — create one via ', style='dim italic')
        out.append('--profile <name>', style='cyan')
        return out
    for p in available:
        if p == profile:
            out.append(f' ★ {p} ', style='bold bright_white on green')
        else:
            out.append(f' {p} ', style='bold bright_white on grey23')
        out.append(' ')
    return out


def display_banner(config: SystemConfig) -> None:
    """Render a single grouped panel: header · runtime · profile · files · profiles.

    Replaces the previous loose-output banner that printed five separate
    blocks. Everything now lives inside one bordered Panel so the user sees
    the whole startup context at a glance, and the file inventory uses a
    right-aligned table so sizes / mtimes line up regardless of name length.
    """
    from rich.console import Group
    from rich.panel import Panel

    profile = getattr(config, 'current_profile', None)
    py_label, in_venv, py_path = _python_runtime_info()

    # ── Top metadata row: title · version · runtime · profile ─────────────
    header = Table(box=None, show_header=False, pad_edge=False, padding=(0, 2))
    header.add_column(style='bold cyan', no_wrap=True)
    header.add_column(no_wrap=True, overflow='fold')

    header.add_row(
        '🚀 System Update', f'[bold cyan]v{_VERSION}[/bold cyan]'
    )
    venv_style = 'bold bright_white on green' if in_venv else 'bold bright_white on yellow'
    header.add_row(
        '🐍 Runtime',
        f'[{venv_style}] {py_label} [/{venv_style}]\n[dim]→ {py_path}[/dim]',
    )
    if profile:
        profile_pill = (
            f'[bold bright_white on cyan] 👤 {profile} [/bold bright_white on cyan]'
        )
    else:
        profile_pill = '[bright_white]👤 default[/bright_white]'
    header.add_row('📂 Profile', profile_pill)

    # ── File inventory ────────────────────────────────────────────────────
    if profile:
        profile_dir = Path(config.profiles_dir) / profile
        profile_rows = [
            ('config.json', Path(config.config_file)),
            ('cache.json', Path(config.cache_file)),
            ('system.log', Path(config.log_file)),
        ]
        shared_rows = [
            ('history.db', Path(config.config_dir) / 'history.db'),
            ('vulnerability_history.json',
             Path(config.config_dir) / 'vulnerability_history.json'),
            ('errors.log', Path(config.config_dir) / 'errors.log'),
        ]
        files_block = Group(
            Text(f'📁 Profile data → {profile_dir}', style='dim white'),
            _file_inventory_table(profile_rows),
            Text(f'🌐 Shared data  → {config.config_dir}', style='dim white'),
            _file_inventory_table(shared_rows),
        )
    else:
        shared_rows = [
            ('config.json', Path(config.config_file)),
            ('cache.json', Path(config.cache_file)),
            ('history.db', Path(config.config_dir) / 'history.db'),
            ('vulnerability_history.json',
             Path(config.config_dir) / 'vulnerability_history.json'),
            ('system.log', Path(config.log_file)),
            ('errors.log', Path(config.config_dir) / 'errors.log'),
        ]
        files_block = Group(
            Text(f'📁 {config.config_dir}', style='dim white'),
            _file_inventory_table(shared_rows),
        )

    # ── Profiles row ──────────────────────────────────────────────────────
    profiles_dir = Path(config.profiles_dir)
    if profiles_dir.is_dir():
        available = sorted(
            p.name for p in profiles_dir.iterdir() if p.is_dir())
    else:
        available = []

    body = Group(
        header,
        Text(),  # blank line
        files_block,
        Text(),
        _profile_chip_row(profile, available),
    )

    console.print(Panel(
        body,
        title='[bold cyan]System Update[/bold cyan]',
        title_align='left',
        border_style='cyan',
        padding=(0, 1),
        expand=True,
    ))


def display_summary(
        total_apps: int,
        updates: int,
        scan_time: float,
        sources_count: Dict[str, int],
        show_all: bool = False,  # noqa: ARG001 — reserved for future "all apps" variant
        security_stats: Optional[Dict] = None,
) -> None:
    """Render the scan summary as a single grouped panel.

    Top KPI strip: total / updates / vulns / scan time. Source distribution
    is rendered as colored chips in a single line. Security breakdown
    (if any) gets its own row.
    """
    from rich.console import Group
    from rich.panel import Panel

    # ── KPI strip ─────────────────────────────────────────────────────────
    vulns = (security_stats or {}).get('total_vulnerabilities', 0)
    pkgs_affected = (security_stats or {}).get('packages_affected', 0)
    persistent = (security_stats or {}).get('persistent_vulnerabilities', 0)

    # Use bare emojis (no U+FE0F variation selector). Rich miscounts
    # cell-width for VS-augmented emoji vs. how the terminal actually
    # renders them, which previously pushed content past the right border.
    kpis = Text.from_markup(
        f'📦 [bold white]{total_apps}[/bold white] [dim]total[/dim]   '
        f'🔄 [bold yellow]{updates}[/bold yellow] [dim]updates[/dim]   '
        f'🔥 [bold red]{vulns}[/bold red] [dim]vulns[/dim]   '
        f'⏱  [bold white]{scan_time:.2f}s[/bold white]'
    )
    kpis.overflow = 'fold'
    kpis.no_wrap = False

    # ── Source distribution chips ────────────────────────────────────────
    # Use Rich's own renderable measurement (Padding + Text) so emoji-with-
    # variation-selector chars don't desync the manual width math from the
    # terminal's actual cell widths. Letting the Panel/Group own wrapping
    # keeps every line strictly inside the panel borders regardless of the
    # window size.
    chip_parts = [
        f'{source_chip(s)}[bold white]:{c}[/bold white]'
        for s, c in sorted(sources_count.items(), key=lambda kv: -kv[1])
        if c > 0
    ]
    if chip_parts:
        sources_text = Text.from_markup(
            '✨ [dim]Sources:[/dim] ' + '   '.join(chip_parts)
        )
    else:
        sources_text = Text.from_markup('[dim]No sources scanned.[/dim]')
    sources_text.overflow = 'fold'
    sources_text.no_wrap = False

    # Blank ``Text('')`` rows insert a clear visual gap between the KPI
    # strip, source distribution, and severity breakdown — keeps the panel
    # readable on wide terminals where everything would otherwise stack.
    rows = [kpis, Text(''), sources_text]

    # ── Security severity row ────────────────────────────────────────────
    if security_stats and vulns > 0:
        breakdown = security_stats.get('severity_breakdown', {})
        sev_parts = [
            f'[{_SEVERITY_COLORS[sev]}]{sev}[/{_SEVERITY_COLORS[sev]}]: '
            f'[bold]{breakdown.get(sev, 0)}[/bold]'
            for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
            if breakdown.get(sev, 0) > 0
        ]
        sec_line = Text.from_markup(
            f'🛡  [dim]Severity:[/dim] {"  ".join(sev_parts)}   '
            f'[dim]·[/dim]   📦 [bold white]{pkgs_affected}[/bold white] '
            f'[dim]packages affected[/dim]   '
            f'[dim]·[/dim]   🔁 [bold yellow]{persistent}[/bold yellow] '
            f'[dim]persistent[/dim]'
        )
        sec_line.overflow = 'fold'
        sec_line.no_wrap = False
        rows.extend([Text(''), sec_line])

    # Plain-text title — Rich measures emoji-with-variation-selector
    # inconsistently in panel titles, which can shift the top border by
    # one cell and visually disagree with the bottom border. Keep the
    # 📊 emoji in the *content* (the KPI strip), not the chrome.
    console.print(Panel(
        Group(*rows),
        title='[bold magenta]Summary[/bold magenta]',
        title_align='left',
        border_style='magenta',
        padding=(0, 2),
        expand=True,
    ))


def _wrap_markup_chips(prefix: str, chips: List[str], max_width: int) -> List[Text]:
    """Deprecated. Kept as a thin wrapper so any external import doesn't break.

    The previous implementation pre-wrapped Rich markup chips by computing
    ``Text.cell_len`` manually — but that under-counts emoji with variation
    selectors (⚙️, 🛡️, 🐍 …) so the wrapped lines occasionally exceeded the
    terminal's true cell width and shoved through the surrounding Panel
    border. The new code in :func:`display_summary` lets Rich do the wrapping
    inside the Panel context, which uses the same measurement engine for
    text-fitting and border-drawing — so they always agree.
    """
    if not chips:
        return [Text.from_markup(prefix)]
    return [Text.from_markup(prefix + '   '.join(chips))]


def _latest_cell(app: AppInfo) -> object:
    """Build the ``Latest`` column value for one app row."""
    if app.latest_version and app.update_status in (
            UpdateStatus.UPDATE_AVAILABLE, UpdateStatus.VULNERABLE,
    ):
        return Text(app.latest_version, style='bold yellow')
    if app.update_status == UpdateStatus.UP_TO_DATE:
        return '-'
    return app.latest_version or '-'


def _source_icon(source: str) -> str:
    """Return a package-source icon, using a plugin glyph for custom sources."""
    return source_icon(source)


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
        src_icon = f'{_source_icon(app.source)} '
        status_color = ThemeManager.get_status_color(
            app.update_status.name.lower(), theme)

        table.add_row(
            app.name[:30],
            f'[{src_color}]{src_icon}{display_source(app.source)}[/{src_color}]',
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
    score = vuln.get('cvss_score') if hasattr(
        vuln, 'get') else getattr(vuln, 'cvss_score', None)
    return f'{score:.1f}' if isinstance(score, (int, float)) else '-'


def create_security_table(security_results: List) -> Table:
    """Build the red/heavy-edge table of scanned security findings."""
    sorted_results = sorted(
        security_results,
        key=lambda r: _SEVERITY_PRIORITY.get(r.highest_severity, 99),
    )
    critical_count = sum(
        1 for r in sorted_results if r.highest_severity == 'CRITICAL')

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
