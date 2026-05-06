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
import threading
import time
from argparse import Namespace
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

from rich.prompt import Prompt

from system_update.cache import CacheManager
from system_update.checkers import UpdateChecker
from system_update.config import SystemConfig, setup_logging
from system_update.executors import UpdateExecutor
from system_update.history import HistoryDatabase, VulnerabilityHistory
from system_update.models import AppInfo, UpdateStatus
from system_update.network import configure_network, fetch_json
from system_update.notifications import NotificationManager
from system_update.plugins import PluginRegistry, load_plugins, scanner_map
from system_update.scanners import PackageScanner
from system_update.security import SecurityChecker
from system_update.ui import DisplayFormatter, UISystem
from system_update.utils import console, dedupe_apps, display_source, source_chip

logger = logging.getLogger(__name__)


_SOURCE_ALIASES = {'choco': 'chocolatey'}

_SCAN_ORDER = (
    'winget',
    'chocolatey',
    'npm',
    'pnpm',
    'bun',
    'yarn',
    'pip',
    'path',
    'registry',
    'rust',
    'scoop',
    'dotnet',
    'appx',
    'msix',
    'drivers',
    'services',
    'psmodules',
    'vsextensions',
)

_KNOWN_SOURCES: Set[str] = set(_SCAN_ORDER) | set(_SOURCE_ALIASES.keys())


def _confirm_default_no(message: str) -> bool:
    """Prompt for y/n with Enter defaulting to no."""
    answer = Prompt.ask(
        f'{message} [dim]\\[y/N][/dim]',
        choices=['y', 'n', 'Y', 'N'],
        default='n',
        show_choices=False,
        show_default=False,
    )
    return answer.lower() == 'y'


def _phase_time_label(label: str, start_time: float) -> str:
    """Return a consistent elapsed-time message for a completed CLI phase."""
    return f'[dim]⏱  {label} completed in {time.time() - start_time:.2f}s[/dim]\n'


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
        'drivers': PackageScanner.scan_drivers,
        'services': PackageScanner.scan_services,
        'psmodules': PackageScanner.scan_psmodules,
        'vsextensions': PackageScanner.scan_vsextensions,
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


def _partition_sources(
        raw: Optional[str], extra_sources: Optional[Set[str]] = None
) -> Tuple[Set[str], Set[str]]:
    """Split ``--source a,b,xpto`` into (valid_canonical, invalid_raw_tokens)."""
    if not raw:
        return set(), set()
    known = _KNOWN_SOURCES | (extra_sources or set())
    valid: Set[str] = set()
    invalid: Set[str] = set()
    for item in raw.split(','):
        token = item.strip()
        if not token:
            continue
        lowered = token.lower()
        canonical = _SOURCE_ALIASES.get(lowered, lowered)
        if canonical in known or lowered in known:
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
            data = fetch_json(url)
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


def _exclude_matches(
        app: AppInfo,
        tokens: List[str],
        extra_sources: Optional[Set[str]] = None,
) -> bool:
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
    known = _KNOWN_SOURCES | (extra_sources or set())
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
            if t in known:
                if t == source:
                    return True
            elif t == name or t == app_id:
                return True
    return False


def _apply_excludes(
        apps: List[AppInfo],
        tokens: List[str],
        extra_sources: Optional[Set[str]] = None,
) -> List[AppInfo]:
    """Drop apps matching any exclude token. No-op if ``tokens`` is empty."""
    if not tokens:
        return apps
    return [a for a in apps if not _exclude_matches(a, tokens, extra_sources)]


def _count_updates(apps: List[AppInfo]) -> int:
    """Total = regular updates + vulnerable packages that also have a newer version available."""
    regular = sum(1 for a in apps if a.update_status ==
                  UpdateStatus.UPDATE_AVAILABLE)
    security = sum(1 for a in apps if a.update_status ==
                   UpdateStatus.VULNERABLE and a.has_update)
    return regular + security


class SystemUpdateApp:
    """Main orchestrator — compose subsystems in :meth:`__init__`, drive them in :meth:`run`."""

    def __init__(self) -> None:
        self.config = SystemConfig()
        self.settings = self.config.settings
        configure_network(self.settings.get(
            'network', {}), self.config.config_dir)
        self.ui = UISystem()
        self.scanner = PackageScanner()
        self.checker = UpdateChecker()
        self.executor = UpdateExecutor()
        self.security = SecurityChecker()
        self.cache_mgr = CacheManager(
            self.config.cache_file,
            self.settings.get('cache', {}).get('duration_hours', 2),
        )
        self._configure_cache_manager()
        self.notifier = NotificationManager(self.config)
        self.plugins: PluginRegistry = load_plugins(self.config)
        self.notifier.plugin_registry = self.plugins
        self.history_db = HistoryDatabase(
            Path(self.config.config_dir) / 'history.db')
        self.vuln_history = VulnerabilityHistory(
            Path(self.config.config_dir) / 'vulnerability_history.json'
        )
        self._include_sources: Set[str] = set()

    @property
    def plugin_sources(self) -> Set[str]:
        """Enabled custom source names registered by plugins."""
        return {name for name, scanner in self.plugins.scanners.items() if scanner.enabled}

    def _scanner_order(self) -> Tuple[str, ...]:
        """Built-in scanner order followed by plugin scanners sorted by source."""
        return _SCAN_ORDER + tuple(sorted(self.plugin_sources))

    def __del__(self) -> None:
        try:
            if getattr(self, 'history_db', None):
                self.history_db.close()
        except Exception:
            pass

    def _configure_cache_manager(self) -> None:
        cache_settings = self.settings.get('cache', {})
        self.cache_mgr.hot_cache_max_items = cache_settings.get(
            'lru_max_items', 512)
        self.cache_mgr.delta_enabled = cache_settings.get(
            'delta_enabled', True)
        self.cache_mgr.prune_after_days = cache_settings.get(
            'prune_after_days', 14)
        self.cache_mgr.storage_fields = cache_settings.get(
            'storage_fields') or []
        self.cache_mgr.omit_empty_fields = cache_settings.get(
            'omit_empty_fields', True)

    # ── scanning ────────────────────────────────────────────────────────────

    def scan_system(self, source_filter: Optional[str] = None) -> List[AppInfo]:
        """Run every enabled source scanner in parallel with a per-source progress bar."""
        scanners = _build_scanner_map()
        scanners.update(scanner_map(self.plugins))

        include = set(self._include_sources)
        include.update(_parse_source_filter(source_filter))
        if include:
            scanners = {name: func for name,
                        func in scanners.items() if name in include}

        enabled = self.settings.get('sources', {})
        # An explicit ``--source X`` request overrides ``sources.X: false`` in
        # the active profile — the user asking for X by name wins. Surface a
        # clear notice so it's obvious what happened.
        overridden = sorted(
            name for name in include if name in scanners and not enabled.get(name, True)
        )
        if overridden:
            console.print(
                f'[yellow]ℹ  Source(s) disabled in config but requested via '
                f'--source:[/yellow] [bold]{", ".join(overridden)}[/bold] '
                f'[dim](scanning anyway — pass [cyan]--save-config[/cyan] '
                f'to make this permanent)[/dim]'
            )

        selected = [
            (name, scanners[name])
            for name in self._scanner_order()
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

        max_workers = self.settings.get(
            'performance', {}).get('max_workers', 4)
        all_apps: List[AppInfo] = []
        from system_update.ui.progress import make_progress

        with make_progress() as progress:
            tasks = {
                name: progress.add_task(f'🔎 {source_chip(name)}', total=1) for name, _ in selected
            }

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_source = {executor.submit(
                    func): name for name, func in selected}
                for future in as_completed(future_to_source):
                    name = future_to_source[future]
                    try:
                        apps = future.result()
                        unique = dedupe_apps(apps)
                        all_apps.extend(unique)
                        icon = '✓' if len(unique) == 0 else '✅'
                        progress.update(
                            tasks[name],
                            completed=1,
                            description=f'{icon} {source_chip(name)} [{len(unique)}]',
                        )
                    except Exception as e:
                        progress.update(
                            tasks[name],
                            completed=1,
                            description=f'❌ {source_chip(name)} error',
                        )
                        console.print(f'  [red]✗[/red] {name}: {e}')

        return sorted(all_apps, key=lambda x: f'{x.source}{x.name}')

    # ── partial scan + cache merge ─────────────────────────────────────────

    def _scan_missing_and_merge(self, cached: List[AppInfo], missing: Set[str]) -> List[AppInfo]:
        """Scan only ``missing`` sources, merge into ``cached``, save, return filtered view."""
        cached_sources = sorted(
            {display_source(app.source) for app in cached if display_source(
                app.source) not in missing}
        )
        hit_label = ', '.join(source_chip(s)
                              for s in cached_sources) if cached_sources else 'none'
        missing_label = ', '.join(source_chip(s) for s in sorted(missing))
        console.print(
            f'[bold cyan]⚡ Partial Cache Hit![/bold cyan] '
            f'[dim]cached source(s):[/dim] [bold green]{hit_label}[/bold green]\n'
            f'[bold cyan]🧐 Scanning missing[/bold cyan] [dim]source(s):[/dim] '
            f'[bold]{missing_label}[/bold]\n'
        )
        prev_include = self._include_sources
        self._include_sources = set(missing)
        try:
            console.print('[bold cyan]🔎 Scanning sources...[/bold cyan]')
            phase_start = time.time()
            new_apps = self.scan_system(','.join(sorted(missing)))
            console.print(
                f'\n📦 [bold]Discovered {len(new_apps)} unique apps.[/bold]')
            console.print(_phase_time_label('Scanning sources', phase_start))

            console.print('[bold cyan]🔄 Checking for updates...[/bold cyan]')
            phase_start = time.time()
            self.checker.check_all_updates(
                new_apps,
                max_workers=self.settings.get(
                    'performance', {}).get('max_workers', 4),
            )

            regular_updates = sum(
                1 for a in new_apps if a.update_status == UpdateStatus.UPDATE_AVAILABLE
            )
            security_updates = sum(
                1 for a in new_apps if a.update_status == UpdateStatus.VULNERABLE and a.has_update
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
            console.print(_phase_time_label(
                'Checking for updates', phase_start))

            console.print(
                '[bold magenta]🔒 Checking security vulnerabilities...[/bold magenta]')
            phase_start = time.time()
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
                    '[bold green]🛡️ No security vulnerabilities found.[/bold green]\n')
            console.print(_phase_time_label(
                'Checking security vulnerabilities', phase_start))
            _pypi_fallback_latest(new_apps)
        finally:
            self._include_sources = prev_include

        # Merge: drop any cached entries for newly-scanned sources, append fresh.
        merged = [a for a in cached if a.source.lower() not in missing] + \
            new_apps
        merged = sorted(merged, key=lambda x: f'{x.source}{x.name}')
        self._save_cache_with_context(merged, missing)
        console.print(
            f'[dim]💾 Cache updated ({len(merged)} items across '
            f'{len({a.source.lower() for a in merged})} sources) '
            f'{self._cache_expiry_hint()}[/dim]\n'
        )
        # Bare run with no source filter → return EVERYTHING; only filter when
        # the caller explicitly scoped the run to specific sources.
        if not self._include_sources:
            return merged
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
            configure_network(self.settings.get(
                'network', {}), self.config.config_dir)
            # Re-bind any sub-system that captured an old path.
            from system_update.cache import CacheManager
            from system_update.history import HistoryDatabase, VulnerabilityHistory

            self.cache_mgr = CacheManager(
                self.config.cache_file,
                self.settings.get('cache', {}).get('duration_hours', 2),
            )
            self._configure_cache_manager()
            self.notifier = NotificationManager(self.config)
            self.plugins = load_plugins(self.config)
            self.notifier.plugin_registry = self.plugins
            try:
                if self.history_db:
                    self.history_db.close()
            except Exception:
                pass
            self.history_db = HistoryDatabase(
                Path(self.config.config_dir) / 'history.db')
            self.vuln_history = VulnerabilityHistory(
                Path(self.config.config_dir) / 'vulnerability_history.json'
            )
            console.print(
                f'[bold cyan]👤 Profile activated:[/bold cyan] [bold]{profile}[/bold]')

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
            # Don't auto-confirm — let the user see the queued packages and
            # approve. Add ``--yes`` explicitly to skip prompts.

        if getattr(args, 'source', None):
            valid, invalid = _partition_sources(
                args.source, self.plugin_sources)
            if invalid:
                available = ', '.join(self._scanner_order())
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
                    f'[dim]   Proceeding with: {", ".join(sorted(valid))}[/dim]\n')
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

        # ── cache check ────────────────────────────────────────────────────
        no_cache = getattr(args, 'no_cache', False)
        cache_enabled = self.settings.get('cache', {}).get('enabled', True)

        if no_cache:
            console.print(
                '[cyan]🚀 Bypassing cache (--no-cache). Scanning live sources...[/cyan]\n'
            )
        elif not cache_enabled:
            console.print(
                '[dim]ℹ Cache disabled in config. Scanning live sources...[/dim]\n')

        if apps is None and not no_cache and cache_enabled:
            cached = self.cache_mgr.load()
            if cached:
                # Pip is interpreter-sensitive; if the user activated a venv
                # (or deactivated one) since the cache was written, the
                # cached pip entries are stale even though the timestamp is
                # fresh. Drop them so the partial-scan-merge path rescans.
                pip_stale = self._pip_context_changed()
                if pip_stale:
                    before = len(cached)
                    cached = [a for a in cached if a.source.lower() != 'pip']
                    recorded = self.cache_mgr.load_pip_context()
                    console.print(
                        f'[yellow]🐍 Python context changed[/yellow] '
                        f'(was: interpreter={recorded.get("interpreter", "?")}, '
                        f'venv={recorded.get("in_venv")}). '
                        f'[dim]Invalidated {before - len(cached)} cached '
                        f'pip entry(ies); will rescan pip.[/dim]\n'
                    )

                if self._include_sources:
                    missing = self._cache_missing_sources(
                        self._include_sources)
                    if pip_stale and 'pip' in self._include_sources:
                        missing.add('pip')
                    if missing:
                        apps = self._scan_missing_and_merge(cached, missing)
                    else:
                        apps = [a for a in cached if a.source.lower()
                                in self._include_sources]
                        self._maybe_prefetch_cache(
                            cached, self._include_sources)
                        console.print(
                            f'[bold cyan]⚡ Cache Hit![/bold cyan] '
                            f'[dim]Loaded {len(apps)} items from cache '
                            f'(filter: {",".join(sorted(self._include_sources))}) '
                            f'{self._cache_expiry_hint()}[/dim]\n'
                        )
                elif pip_stale:
                    # Bare run + pip context changed → treat pip as missing
                    # so the merge path rescans only pip.
                    apps = self._scan_missing_and_merge(cached, {'pip'})
                else:
                    enabled_sources = self._enabled_sources()
                    missing = self._cache_missing_sources(enabled_sources)
                    if missing and self.settings.get('cache', {}).get('incremental_enabled', True):
                        apps = self._scan_missing_and_merge(cached, missing)
                    else:
                        apps = cached
                        self._maybe_prefetch_cache(cached, enabled_sources)
                        console.print(
                            f'[bold cyan]⚡ Cache Hit![/bold cyan] '
                            f'[dim]Loaded {len(apps)} items from cache '
                            f'{self._cache_expiry_hint()}[/dim]\n'
                        )
            elif cached is not None and self._include_sources:
                # Valid but empty cache + --source X: scan X silently via merge
                # path so the full-scan banners don't fire.
                apps = self._scan_missing_and_merge(
                    [], set(self._include_sources))
            else:
                # Cache missing or expired (load() returned None)
                if self.cache_mgr.cache_file.exists():
                    console.print(
                        '[yellow]⏳ Cache expired or invalid. Refreshing data from sources...[/yellow]\n'
                    )
                else:
                    console.print(
                        '[dim]🆕 No cache found. Starting fresh scan...[/dim]\n')

        security_vulns: List[Dict] = []
        total_updates = 0

        if apps is None:
            start_time = time.time()

            # Phase 1 — scan.
            console.print('[bold cyan]🔎 Scanning sources...[/bold cyan]')
            phase_start = time.time()
            apps = self.scan_system(getattr(args, 'source', None))
            console.print(
                f'\n📦 [bold]Discovered {len(apps)} unique apps.[/bold]')
            console.print(_phase_time_label('Scanning sources', phase_start))

            # Phase 2 — update checking.
            console.print('[bold cyan]🔄 Checking for updates...[/bold cyan]')
            phase_start = time.time()
            self.checker.check_all_updates(
                apps,
                max_workers=self.settings.get(
                    'performance', {}).get('max_workers', 4),
            )

            regular_updates = sum(
                1 for a in apps if a.update_status == UpdateStatus.UPDATE_AVAILABLE
            )
            security_updates = sum(
                1 for a in apps if a.update_status == UpdateStatus.VULNERABLE and a.has_update
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
            console.print(_phase_time_label(
                'Checking for updates', phase_start))

            # Phase 3 — security vulnerability check.
            console.print(
                '[bold magenta]🔒 Checking security vulnerabilities...[/bold magenta]')
            phase_start = time.time()
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
                    '[bold green]🛡️ No security vulnerabilities found.[/bold green]\n')
            console.print(_phase_time_label(
                'Checking security vulnerabilities', phase_start))

            _pypi_fallback_latest(apps)

            # Persist findings + full scan to history stores.
            scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
            for app in apps:
                for finding in app.security_findings:
                    self.vuln_history.record_vulnerability(
                        app, finding, scan_id)

            scanned_sources = self._scanned_sources_label(args)
            scan_time = time.time() - start_time
            self.history_db.record_scan(
                apps, scan_id, scanned_sources, scan_time)

            total_updates = _count_updates(apps)
            if getattr(args, 'no_cache', False):
                console.print(
                    '[dim]💾 --no-cache: skipping cache write (scan results not persisted).[/dim]\n'
                )
            else:
                self._save_cache_with_context(
                    apps, self._fresh_scan_sources(args, apps))
                console.print(
                    f'[dim]💾 Cache updated ({len(apps)} items across '
                    f'{len({a.source.lower() for a in apps})} sources) '
                    f'{self._cache_expiry_hint()}[/dim]\n'
                )
        else:
            total_updates = _count_updates(apps)
            scan_time = 0.0

        # ── apply exclude list (CLI > env > config) ────────────────────────
        exclude_tokens = _parse_exclude_list(getattr(args, 'exclude', None))
        if not exclude_tokens:
            exclude_tokens = _parse_exclude_list(self.settings.get('exclude'))
        if exclude_tokens:
            before = len(apps)
            apps = _apply_excludes(apps, exclude_tokens, self.plugin_sources)
            dropped = before - len(apps)
            if dropped:
                console.print(
                    f'[dim]🚫 Excluded {dropped} package(s) matching: '
                    f'{", ".join(exclude_tokens)}[/dim]\n'
                )
            total_updates = _count_updates(apps)

        if getattr(args, 'dependency_graph', None):
            self._handle_dependency_graph(apps, args)
            return

        # ── shared rendering path (cache hit OR fresh scan) ────────────────
        sources_count: Dict[str, int] = {}
        for app in apps:
            source = display_source(app.source)
            sources_count[source] = sources_count.get(source, 0) + 1

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
            len(apps),
            total_updates,
            scan_time,
            sources_count,
            show_all=getattr(args, 'show_all', False),
            security_stats=security_stats,
        )

        if getattr(args, 'package', None):
            self._handle_single_update(apps, args)
            return

        updates = [a for a in apps if a.update_status ==
                   UpdateStatus.UPDATE_AVAILABLE]
        vulnerable = [a for a in apps if a.update_status ==
                      UpdateStatus.VULNERABLE]

        console.print()
        ui_settings = self.settings.get('ui', {})
        apps_table = DisplayFormatter.format_table(
            apps,
            ui_settings.get('display_format', 'auto'),
            ui_settings.get('theme', 'default'),
            True,
            show_all=getattr(args, 'show_all', False),
        )
        console.print(apps_table)

        if getattr(args, 'show_all', False):
            console.print('\n[dim]💾 Showing: all packages[/dim]')
        else:
            console.print('\n[dim]💾 Showing: updates only[/dim]')

        if vulnerable:
            self._display_security_table(vulnerable)

        if updates or vulnerable:
            security_updates = [a for a in vulnerable if a.has_update]
            total_count = self._print_available_updates_summary(
                updates, security_updates)

            if getattr(args, 'notify', False):
                self.notifier.notify_updates_available(
                    total_count, len(security_updates), force=True
                )

            if getattr(args, 'interactive', False):
                self._interactive_update(updates, vulnerable, args)
            elif getattr(args, 'update_all', False):
                self._update_all_workflow(updates, vulnerable, args)
        else:
            console.print('\n[green]✨ System is up to date![/green]')

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
                    self.settings.get('report', {}).get(
                        'template_path') or None
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
        return ','.join(name for name in self._scanner_order() if enabled.get(name, True))

    def _print_available_updates_summary(
            self, regular_updates: List[AppInfo], security_updates: List[AppInfo]
    ) -> int:
        """Print the regular/security split for available updates and return total."""
        total_count = len(regular_updates) + len(security_updates)
        console.print(
            f'\n[bold yellow]🎯 Found {total_count} available updates '
            f'({len(regular_updates)} regular, {len(security_updates)} security/vulnerable)'
            f'[/bold yellow]'
        )
        return total_count

    def _update_all_workflow(
            self, updates: List[AppInfo], vulnerable: List[AppInfo], args: Namespace
    ) -> None:
        """Security-first update flow: vulnerable packages get their own confirmation + pass."""
        security_updates = [a for a in vulnerable if a.has_update]
        regular_updates = [
            a for a in updates if a.update_status != UpdateStatus.VULNERABLE]
        dry_run = getattr(args, 'dry_run', False)
        yes = getattr(args, 'yes', False)

        store = None if dry_run else self._snapshot_store()
        import sys as _sys

        cmd_label = ' '.join(_sys.argv)

        try:
            if security_updates:
                console.print(
                    f'\n[bold red]🔒 Priority: Updating {len(security_updates)} '
                    f'vulnerable package(s) first...[/bold red]'
                )
                # Show the CVE detail for the batch about to run so the user
                # can see exactly what's being patched before they confirm.
                self._display_security_table(security_updates)
                if yes or _confirm_default_no('🚀 Proceed with security updates?'):
                    self.executor.execute_updates(
                        security_updates,
                        dry_run,
                        snapshot_store=store,
                        snapshot_label='security batch',
                        snapshot_command=cmd_label,
                    )
                else:
                    console.print(
                        '[yellow]Skipped security/vulnerable package updates.[/yellow]')

            if regular_updates:
                console.print(
                    f'\n[bold yellow]⚡ Now updating {len(regular_updates)} '
                    f'regular package(s)...[/bold yellow]'
                )
                if yes or _confirm_default_no('🚀 Proceed with remaining updates?'):
                    self.executor.execute_updates(
                        regular_updates,
                        dry_run,
                        snapshot_store=store,
                        snapshot_label='regular batch',
                        snapshot_command=cmd_label,
                    )
                else:
                    console.print(
                        '[yellow]Skipped regular package updates.[/yellow]')
        finally:
            if store is not None:
                store.close()

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
                findings = [
                    {
                        'severity': 'HIGH',
                        'cvss_score': None,
                        'cve': 'N/A',
                        'description': 'Update recommended',
                    }
                ]

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
                cvss_display = f'{cvss_val:.1f}' if isinstance(
                    cvss_val, (int, float)) else '-'
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
        """Update one package by name, optionally constrained by source/version."""
        target_name = (getattr(args, 'package', '') or '').lower()
        source_arg = getattr(args, 'source', None)
        target_sources = (
            {item.strip().lower()
             for item in source_arg.split(',') if item.strip()}
            if isinstance(source_arg, str) and source_arg
            else set()
        )

        candidates = [
            app
            for app in apps
            if (app.name.lower() == target_name or (app.app_id or '').lower() == target_name)
            and (not target_sources or app.source.lower() in target_sources)
        ]

        if not candidates:
            console.print(f"[red]❌ Package '{args.package}' not found[/red]")
            if target_sources:
                console.print(
                    f'[dim]🔍 Filter: source={",".join(sorted(target_sources))}[/dim]')
            return

        if len(candidates) > 1 and not target_sources:
            console.print('[yellow]⚠️  Multiple packages found:[/yellow]')
            for i, candidate in enumerate(candidates, start=1):
                console.print(
                    f'  {i}. {candidate.name} ({display_source(candidate.source)}) - {candidate.version}'
                )
            console.print(
                '[yellow]💡 Please specify --source to target one[/yellow]')
            return

        target_app = candidates[0]
        version = getattr(args, 'version', None)
        if version:
            target_app.latest_version = version
            console.print(f'[cyan]🎯 Targeting version: {version}[/cyan]')
        elif not target_app.has_update:
            console.print(
                f'[green]✅ {target_app.name} is up to date ({target_app.version})[/green]'
            )
            if not (getattr(args, 'yes', False) or _confirm_default_no('🔄 Force reinstall?')):
                return
            target_app.latest_version = ''

        dry_run = getattr(args, 'dry_run', False)
        yes = getattr(args, 'yes', False)
        from rich.table import Table

        t = Table(title='Package queued for update', expand=True)
        t.add_column('Package', style='bold')
        t.add_column('Source', style='magenta')
        t.add_column('Current', style='yellow')
        t.add_column('Target', style='green')
        t.add_column('Vulns', justify='center')
        vuln_count = len(target_app.security_findings or [])
        vuln_cell = f'[bold red]🔥 {vuln_count}[/bold red]' if vuln_count else '[dim]—[/dim]'
        t.add_row(
            target_app.name,
            display_source(target_app.source),
            target_app.version or '-',
            target_app.latest_version or 'latest',
            vuln_cell,
        )
        console.print(t)

        # Surface CVE detail BEFORE the confirm prompt when the package is
        # vulnerable — same table that runs at end-of-scan, scoped to this
        # package only so the user sees what's being patched.
        if target_app.is_vulnerable:
            self._display_security_table([target_app])

        if not yes and not dry_run:
            if not _confirm_default_no(
                    'Proceed with update? This will run the package manager command.',
            ):
                console.print('[yellow]Cancelled.[/yellow]')
                return

        import sys as _sys

        store = None if dry_run else self._snapshot_store()
        try:
            self.executor.execute_updates(
                [target_app],
                dry_run=dry_run,
                snapshot_store=store,
                snapshot_label=f'package:{target_app.name}',
                snapshot_command=' '.join(_sys.argv),
            )
            if not dry_run:
                self._save_cache_with_context(apps)
                console.print(
                    '[bold green]✓[/bold green] '
                    f'[dim]Cache updated with package result {self._cache_expiry_hint()}[/dim]'
                )
        finally:
            if store is not None:
                store.close()

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

    def _handle_dependency_graph(self, apps: List[AppInfo], args: Namespace) -> None:
        """Handle ``--dependency-graph`` actions after scan/cache/import resolution."""
        from rich.table import Table

        from system_update import dependency_graph
        from system_update import subhelp

        action = (getattr(args, 'dependency_graph', '') or '').lower()
        if action == 'help':
            subhelp.show('dependency-graph')
            return

        graph = dependency_graph.build_graph(apps)
        if action == 'dot':
            output = getattr(args, 'graph_output',
                             None) or 'dependency-graph.dot'
            path = dependency_graph.export_dot(graph, output)
            console.print(
                f'[green]✓[/green] Dependency graph exported to [cyan]{path}[/cyan] '
                f'[dim]({len(graph.nodes)} nodes, {len(graph.edges)} edges)[/dim]'
            )
            return

        if action == 'conflicts':
            conflicts = dependency_graph.detect_conflicts(graph)
            table = Table(title='Dependency Version Conflicts', expand=True)
            table.add_column('Package', style='bold')
            table.add_column('Versions')
            table.add_column('Locations')
            for conflict in conflicts:
                versions = ', '.join(sorted(conflict.versions))
                locations = []
                for version, nodes in sorted(conflict.versions.items()):
                    where = ', '.join(f'{n.source}:{n.name}' for n in nodes)
                    locations.append(f'{version} → {where}')
                table.add_row(conflict.name, versions, '\n'.join(locations))
            console.print(table)
            if not conflicts:
                console.print(
                    '[green]✓[/green] No dependency version conflicts detected.')
            return

        if action == 'minimal':
            selected = dependency_graph.minimal_update_set(graph)
            table = Table(title='Minimal Update Set', expand=True)
            table.add_column('Package', style='bold')
            table.add_column('Source', style='magenta')
            table.add_column('Current', style='yellow')
            table.add_column('Target', style='green')
            table.add_column('Reason')
            for node in selected:
                reason = 'vulnerable' if node.vulnerable else 'update available'
                table.add_row(
                    node.name,
                    display_source(node.source),
                    node.version or '-',
                    node.latest_version or 'latest',
                    reason,
                )
            console.print(table)
            if not selected:
                console.print('[green]✓[/green] No direct updates needed.')
            return

        console.print(
            f'[red]✗ Unknown dependency graph action:[/red] {action}')

    # ── Meta commands (history / report / interactive) ─────────────────────

    def _handle_meta_commands(self, args: Namespace) -> bool:
        """Route history/report/interactive flags; return True if the command was consumed."""
        if getattr(args, 'list_plugins', False):
            self._show_plugins()
            return True
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
            self._generate_history_report(
                args.report, getattr(args, 'report_output', None))
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
        if getattr(args, 'snapshot', None):
            self._handle_snapshot(args)
            return True
        if getattr(args, 'rollback', None):
            self._handle_rollback(args)
            return True
        if getattr(args, 'remote', None):
            self._handle_remote(args)
            return True
        return False

    def _show_plugins(self) -> None:
        """Display loaded plugin scanners/notifiers and load errors."""
        from rich.table import Table

        table = Table(title='Plugins', expand=True)
        table.add_column('Type', style='cyan')
        table.add_column('Name', style='bold')
        table.add_column('Plugin')
        table.add_column('Description', style='dim')

        for scanner in sorted(self.plugins.scanners.values(), key=lambda s: s.source):
            table.add_row(
                'scanner',
                scanner.source,
                scanner.plugin or '-',
                scanner.description or '-',
            )
        for notifier in sorted(self.plugins.notifiers.values(), key=lambda n: n.name):
            table.add_row(
                'notifier',
                notifier.name,
                notifier.plugin or '-',
                notifier.description or '-',
            )

        if not self.plugins.scanners and not self.plugins.notifiers:
            console.print(
                '[yellow]No plugins loaded.[/yellow] '
                f'[dim]Add .py plugins under {Path(self.config.config_dir) / "plugins"} '
                'or configure plugins.paths.[/dim]'
            )
        else:
            console.print(table)

        for error in self.plugins.errors:
            console.print(f'[red]✗[/red] {error.path}: {error.error}')

    # ── Remote management (6.4) ───────────────────────────────────────────

    def _handle_remote(self, args: Namespace) -> None:
        """Dispatch ``--remote list|add|remove|scan|update|report|help``."""
        from system_update import remote as remote_mod
        from system_update import subhelp

        action = (args.remote or '').lower()
        if action == 'help':
            subhelp.show('remote')
            return

        inv = remote_mod.Inventory()

        if action == 'list':
            if not inv.hosts:
                console.print(
                    '[yellow]No remote hosts in inventory.[/yellow] '
                    '[dim]Add one with [cyan]--remote add --remote-host NAME[/cyan].[/dim]'
                )
                return
            from rich.table import Table

            t = Table(title='🌐 Remote inventory', expand=True)
            t.add_column('Name', style='bold')
            t.add_column('Address', style='cyan')
            t.add_column('User', style='magenta')
            t.add_column('Transport')
            t.add_column('Groups', style='dim')
            t.add_column('Description', style='dim')
            for h in inv.hosts:
                t.add_row(
                    h.name, h.address, h.user or '-',
                    h.transport, ', '.join(h.groups) or '-',
                    h.description or '-',
                )
            console.print(t)
            return

        if action == 'add':
            name = getattr(args, 'remote_host', None)
            if not isinstance(name, str) or not name:
                console.print(
                    '[red]✗ --remote add requires --remote-host NAME[/red]'
                )
                return
            groups = []
            raw_groups = getattr(args, 'remote_groups', None)
            if isinstance(raw_groups, str) and raw_groups:
                groups = [g.strip()
                          for g in raw_groups.split(',') if g.strip()]
            host = remote_mod.RemoteHost(
                name=name,
                address=getattr(args, 'remote_address', None) or name,
                user=getattr(args, 'remote_user', None) or '',
                transport='winrs',
                groups=groups,
            )
            inv.add(host)
            console.print(
                f'[green]✓ Added[/green] [bold]{host.name}[/bold] → '
                f'[cyan]{host.address}[/cyan] '
                f'(groups: {", ".join(host.groups) or "none"})'
            )
            return

        if action == 'remove':
            name = getattr(args, 'remote_host', None)
            if not isinstance(name, str) or not name:
                console.print(
                    '[red]✗ --remote remove requires --remote-host NAME[/red]'
                )
                return
            ok = inv.remove(name)
            if ok:
                console.print(f'[green]✓ Removed[/green] [bold]{name}[/bold]')
            else:
                console.print(
                    f'[yellow]No host named[/yellow] [bold]{name}[/bold]')
            return

        # scan / update / report all need a target list.
        hosts = inv.resolve(
            host=getattr(args, 'remote_host', None),
            group=getattr(args, 'remote_group', None),
        )
        if not hosts:
            console.print(
                '[yellow]No matching hosts.[/yellow] '
                '[dim]Pass --remote-host NAME or --remote-group GROUP, '
                'or use --remote list to see what is available.[/dim]'
            )
            return

        extra = getattr(args, 'remote_args', None) or ''
        timeout = int(getattr(args, 'remote_timeout', 600) or 600)

        if action in ('scan', 'report'):
            cmd = remote_mod.build_remote_scan_command(extra)
        elif action == 'update':
            cmd = remote_mod.build_remote_update_command(extra)
        else:
            console.print(f'[red]Unknown remote action: {action}[/red]')
            return

        console.print(
            f'[bold cyan]🌐 Running on {len(hosts)} host(s):[/bold cyan] '
            f'[dim]{cmd}[/dim]'
        )

        debug = bool(getattr(args, 'remote_debug', False))
        verbose = bool(getattr(args, 'remote_verbose', False)) or debug
        results = self._run_remote_with_progress(
            hosts, cmd, timeout, verbose, debug)
        self._render_remote_results(results, action, args)

    def _run_remote_with_progress(
            self,
            hosts: List,
            cmd: str,
            timeout: int,
            verbose: bool,
            debug: bool = False,
    ) -> List:
        """Fan-out to ``hosts`` with a per-host progress bar and optional streaming.

        Without progress, the user sees nothing while ``winrs`` connects (which
        can take 30+ seconds per host). The progress bar shows ``⏳`` for each
        running host and locks in the actual duration on completion. With
        ``verbose=True`` we also dump the remote stdout / stderr tail to the
        console as each host finishes — invaluable for diagnosing auth or
        WinRM-config failures. ``debug=True`` additionally prints the exact
        redacted ``winrs`` argv before each host starts so a long-running host
        doesn't look like a silent freeze.
        """
        from system_update import remote as remote_mod
        from system_update.ui.progress import make_progress

        verbose = verbose or debug
        if debug:
            console.print('[bold cyan]🐛 Remote debug enabled[/bold cyan]')
            console.print(f'[dim]remote command:[/dim] {cmd}')
            console.print(f'[dim]timeout:[/dim] {timeout}s')
            for h in hosts:
                debug_argv = remote_mod.build_debug_argv(h, cmd)
                console.print(
                    f'[dim]host:[/dim] [bold]{h.name}[/bold] '
                    f'[dim]address:[/dim] {h.address or h.name} '
                    f'[dim]transport:[/dim] {h.transport} '
                    f'[dim]user:[/dim] {h.user or "-"}'
                )
                console.print(
                    f'[dim]local command:[/dim] {remote_mod.argv_to_display(debug_argv)}'
                )

        with make_progress() as progress:
            tasks = {
                h.name: progress.add_task(f'🌐 {h.name}', total=1) for h in hosts
            }

            def _on_start(host) -> None:
                if debug:
                    progress.console.print(
                        f'[dim]▶ started {host.name}; waiting for winrs response...[/dim]'
                    )

            def _on_tick(host, elapsed: float) -> None:
                if debug:
                    progress.console.print(
                        f'[dim]⏳ {host.name} still running '
                        f'({elapsed:.0f}s elapsed / timeout {timeout}s)[/dim]'
                    )

            def _on_done(host, result) -> None:
                progress.update(tasks[host.name], completed=1)
                icon = '✅' if result.ok else '❌'
                progress.update(
                    tasks[host.name],
                    description=f'{icon} {host.name}',
                )
                if verbose:
                    # Print outside the progress bar so it stays readable.
                    progress.console.print(
                        f'\n[bold]── {icon} {host.name} '
                        f'(exit {result.exit_code}, '
                        f'{result.duration:.1f}s) ──[/bold]'
                    )
                    if result.stdout:
                        tail = result.stdout.strip().splitlines()[-20:]
                        progress.console.print(
                            '[dim]stdout:[/dim] '
                            + ('\n  ' + '\n  '.join(tail)
                               if tail else '(empty)')
                        )
                    if result.stderr:
                        err_tail = result.stderr.strip().splitlines()[-10:]
                        progress.console.print(
                            '[red]stderr:[/red] '
                            + ('\n  ' + '\n  '.join(err_tail)
                               if err_tail else '(empty)')
                        )

            results = remote_mod.execute_many(
                hosts,
                cmd,
                timeout=timeout,
                tick_interval=30.0,
                on_start=_on_start if debug else None,
                on_tick=_on_tick if debug else None,
                on_complete=_on_done,
            )
        return results

    def _render_remote_results(
            self, results: List, action: str, args: Namespace
    ) -> None:
        """Print a summary table + optional consolidated JSON report."""
        from rich.table import Table

        t = Table(title=f'🌐 Remote {action} results', expand=True)
        t.add_column('Host', style='bold')
        t.add_column('Status', no_wrap=True)
        t.add_column('Exit', justify='right')
        t.add_column('Duration', justify='right', style='cyan')
        t.add_column('Notes', style='dim', overflow='fold')
        for r in results:
            status = '[green]✓[/green]' if r.ok else '[red]✗[/red]'
            notes = ''
            if r.parsed is not None:
                pkgs = (
                    r.parsed if isinstance(r.parsed, list)
                    else r.parsed.get('packages') or []
                )
                updates = sum(1 for p in pkgs if p.get(
                    'status') == 'update_available')
                vulns = sum(1 for p in pkgs if p.get('status') == 'vulnerable')
                notes = (
                    f'{len(pkgs)} pkgs · {updates} updates · {vulns} vulns'
                )
            elif r.stderr:
                notes = r.stderr.strip().splitlines()[-1][:120]
            t.add_row(
                r.host, status, str(r.exit_code),
                f'{r.duration:.1f}s', notes,
            )
        console.print(t)

        if action == 'report':
            from system_update import remote as remote_mod

            report = remote_mod.aggregate_scans(results)
            out_path = getattr(args, 'remote_output', None)
            payload = json.dumps(report, indent=2, default=str)
            if isinstance(out_path, str) and out_path:
                from pathlib import Path as _Path

                _Path(out_path).parent.mkdir(parents=True, exist_ok=True)
                _Path(out_path).write_text(payload, encoding='utf-8')
                console.print(
                    f'[green]✓ Wrote consolidated report[/green] '
                    f'→ [cyan]{out_path}[/cyan] '
                    f'({report["host_count"]} hosts, '
                    f'{len(report["package_index"])} unique packages)'
                )
            else:
                console.print()
                console.print(
                    f'[bold]🧾 Consolidated:[/bold] {report["host_count"]} hosts, '
                    f'{len(report["package_index"])} unique packages, '
                    f'{report["error_count"]} errors. '
                    f'Pass [cyan]--remote-output PATH[/cyan] to save full JSON.'
                )

    # ── Snapshots & rollback (6.2) ─────────────────────────────────────────

    def _snapshot_store(self):
        """Lazy-construct a :class:`SnapshotStore` against the active history.db."""
        from system_update.snapshots import SnapshotStore

        return SnapshotStore(Path(self.config.config_dir) / 'history.db')

    def _handle_snapshot(self, args: Namespace) -> None:
        """Dispatch ``--snapshot list|show|delete|help``."""
        from system_update import subhelp

        action = (args.snapshot or '').lower()
        if action == 'help':
            subhelp.show('snapshot')
            return

        with self._snapshot_store() as store:
            if action == 'list':
                rows = store.list_snapshots()
                if not rows:
                    console.print(
                        '[yellow]No snapshots recorded yet.[/yellow]')
                    return
                from rich.table import Table

                t = Table(title='📸 Snapshots', expand=True)
                t.add_column('ID', style='cyan')
                t.add_column('Timestamp', style='magenta')
                t.add_column('Pkgs', justify='right')
                t.add_column('OK', justify='right', style='green')
                t.add_column('Label')
                for s in rows:
                    t.add_row(
                        s.id,
                        s.timestamp,
                        str(s.package_count),
                        str(s.success_count),
                        s.label or '-',
                    )
                console.print(t)
                return

            target_id = getattr(args, 'snapshot_id', None) or 'last'

            if action == 'show':
                snap = store.get(target_id)
                if not snap:
                    console.print(
                        f'[yellow]No snapshot found:[/yellow] {target_id}')
                    return
                from rich.table import Table

                console.print(
                    f'[bold]📸 Snapshot[/bold] [cyan]{snap.id}[/cyan]  '
                    f'· {snap.timestamp}  · {snap.label or "(no label)"}'
                )
                if snap.command:
                    console.print(f'[dim]command:[/dim] {snap.command}')
                t = Table(expand=True)
                t.add_column('Package', style='bold')
                t.add_column('Source', style='magenta')
                t.add_column('Before', style='yellow')
                t.add_column('After', style='green')
                t.add_column('OK', justify='center')
                for p in snap.packages:
                    t.add_row(
                        p.name,
                        display_source(p.source),
                        p.version_before or '-',
                        p.version_after or '-',
                        '[green]✓[/green]' if p.success else '[red]✗[/red]',
                    )
                console.print(t)
                return

            if action == 'delete':
                ok = store.delete(target_id)
                if ok:
                    console.print(
                        f'[green]✓ Deleted[/green] snapshot [bold]{target_id}[/bold]')
                else:
                    console.print(
                        f'[yellow]No snapshot found:[/yellow] {target_id}')
                return

    def _handle_rollback(self, args: Namespace) -> None:
        """Restore packages captured in a snapshot to their previous versions."""
        from system_update import subhelp

        token = (args.rollback or '').strip()
        if token.lower() == 'help':
            subhelp.show('rollback')
            return

        with self._snapshot_store() as store:
            snap = store.get(token)
            if not snap:
                console.print(
                    f'[red]✗ Snapshot not found:[/red] {token!r}. '
                    f'[dim]Try [cyan]--snapshot list[/cyan] to see available ids.[/dim]'
                )
                return

        console.print(
            f'[bold]⏪ Rolling back snapshot[/bold] [cyan]{snap.id}[/cyan] '
            f'({snap.timestamp}) — {len(snap.packages)} package(s)'
        )
        if snap.label:
            console.print(f'[dim]label:[/dim] {snap.label}')
        if snap.command:
            console.print(f'[dim]snapshot command:[/dim] {snap.command}')
        from rich.table import Table

        t = Table(title='Packages queued for rollback', expand=True)
        t.add_column('Package', style='bold')
        t.add_column('Source', style='magenta')
        t.add_column('Current / Snapshot After', style='green')
        t.add_column('Rollback Target', style='yellow')
        t.add_column('Snapshot OK', justify='center')
        for pkg in snap.packages:
            t.add_row(
                pkg.name,
                display_source(pkg.source),
                pkg.version_after or '-',
                pkg.version_before or '[red]missing[/red]',
                '[green]✓[/green]' if pkg.success else '[red]✗[/red]',
            )
        console.print(t)

        dry_run = getattr(args, 'dry_run', False)
        yes = getattr(args, 'yes', False)
        if not yes and not dry_run:
            if not _confirm_default_no(
                    'Proceed with rollback? This will run install commands for each recorded package.',
            ):
                console.print('[yellow]Cancelled.[/yellow]')
                return
        from system_update.executors import execute_rollback

        execute_rollback(snap.packages, dry_run=dry_run)

    # ── Cache helpers ──────────────────────────────────────────────────────

    def _current_pip_context(self) -> Tuple[str, bool]:
        """Return ``(interpreter, in_venv)`` for the current process."""
        import sys

        from system_update.scanners import pip as _pip_scanner

        return (
            sys.executable,
            _pip_scanner._is_in_venv(),
        )

    def _save_cache_with_context(
            self, apps: List[AppInfo], refreshed_sources: Optional[Set[str]] = None
    ) -> None:
        """Wrap ``cache_mgr.save`` so we always record the pip context."""
        interpreter, in_venv = self._current_pip_context()
        self.cache_mgr.save(
            apps,
            pip_interpreter=interpreter,
            pip_in_venv=in_venv,
            refreshed_sources=refreshed_sources,
        )

    def _cache_missing_sources(self, sources: Set[str]) -> Set[str]:
        """Return sources that are missing or stale under smart caching."""
        if not self.settings.get('cache', {}).get('incremental_enabled', True):
            cached_sources = {s.lower() for s in self.cache_mgr.load_sources()}
            return {s for s in sources if s not in cached_sources}
        return self.cache_mgr.stale_sources(sources)

    def _enabled_sources(self) -> Set[str]:
        """Enabled built-in/plugin source names for cache freshness checks."""
        enabled = self.settings.get('sources', {})
        return {name for name in self._scanner_order() if enabled.get(name, True)}

    def _fresh_scan_sources(self, args: Namespace, apps: List[AppInfo]) -> Set[str]:
        """Sources refreshed by a full live scan."""
        if getattr(args, 'source', None):
            return _parse_source_filter(args.source)
        return {a.source.lower() for a in apps}

    def _maybe_prefetch_cache(self, cached: List[AppInfo], candidate_sources: Set[str]) -> None:
        """Best-effort background refresh for caches close to expiry."""
        cache_settings = self.settings.get('cache', {})
        if not cache_settings.get('prefetch_enabled', False):
            return
        remaining = self.cache_mgr.expires_at()
        if remaining is None:
            return
        threshold = cache_settings.get('prefetch_threshold_minutes', 15)
        if (remaining - datetime.now()).total_seconds() > threshold * 60:
            return
        sources = set(candidate_sources)
        if not sources:
            return

        def _prefetch() -> None:
            try:
                self._scan_missing_and_merge(cached, sources)
            except Exception as exc:
                logger.debug(f'Cache prefetch failed: {exc}')

        thread = threading.Thread(
            target=_prefetch, name='system-update-prefetch', daemon=True)
        thread.start()

    def _pip_context_changed(self) -> bool:
        """True if the cached pip scan was made under a different Python context."""
        recorded = self.cache_mgr.load_pip_context()
        if not recorded.get('interpreter'):
            return False  # no metadata → nothing to compare against
        current_interp, current_venv = self._current_pip_context()
        # Different interpreter (e.g. switched venv) invalidates. ``in_venv``
        # also catches transitions where the interpreter hint stayed empty.
        if recorded.get('interpreter') and recorded['interpreter'] != current_interp:
            return True
        if recorded.get('in_venv') != current_venv:
            return True
        return False

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
        """Write current CLI overrides (sources, theme, format) into config.json.

        Only ``--source`` rewrites the ``sources`` block — every named source
        gets ``true`` and every other one gets ``false``. UI flags merge into
        ``ui``. Called when the user passes ``--save-config``.
        """
        changed: List[str] = []

        def _str_arg(name: str):
            """Pull ``args.<name>`` only if it's a real non-empty string."""
            v = getattr(args, name, None)
            return v if isinstance(v, str) and v else None

        raw_source = _str_arg('source')
        if raw_source:
            valid, _ = _partition_sources(raw_source, self.plugin_sources)
            if valid:
                new_sources = {name: (name in valid)
                               for name in self.settings.get('sources', {})}
                # Add any canonical names that weren't already in config.
                for name in valid:
                    new_sources.setdefault(name, True)
                self.settings['sources'] = new_sources
                changed.append(f'sources → {", ".join(sorted(valid))}')

        raw_exclude = _str_arg('exclude')
        if raw_exclude:
            tokens = _parse_exclude_list(raw_exclude)
            self.settings['exclude'] = tokens
            changed.append(f'exclude → {", ".join(tokens)}')

        ui = self.settings.setdefault('ui', {})
        theme = _str_arg('theme')
        if theme:
            ui['theme'] = theme
            changed.append(f'ui.theme → {theme}')
        fmt = _str_arg('format')
        if fmt:
            ui['display_format'] = fmt
            changed.append(f'ui.display_format → {fmt}')

        if not changed:
            console.print(
                '[yellow]⚠ --save-config: nothing to persist[/yellow] '
                '[dim](no --source/--theme/--format supplied)[/dim]'
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

    def _import_profile(self, input_path: str, target_name: Optional[str] = None) -> None:
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
            configure_network(self.settings.get(
                'network', {}), self.config.config_dir)
            from system_update.cache import CacheManager
            from system_update.history import HistoryDatabase, VulnerabilityHistory

            self.cache_mgr = CacheManager(
                self.config.cache_file,
                self.settings.get('cache', {}).get('duration_hours', 2),
            )
            self._configure_cache_manager()
            try:
                if self.history_db:
                    self.history_db.close()
            except Exception:
                pass
            self.history_db = HistoryDatabase(
                Path(self.config.config_dir) / 'history.db')
            self.vuln_history = VulnerabilityHistory(
                Path(self.config.config_dir) / 'vulnerability_history.json'
            )
            console.print(
                f'[green]✓ Imported[/green] profile [bold]{profile_label}[/bold] '
                f'← [cyan]{src}[/cyan]'
            )
        else:
            console.print(
                f'[red]✗ Import failed:[/red] {src} (invalid JSON or missing "settings" key)'
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
                    frequency=getattr(args, 'schedule_when',
                                      'daily') or 'daily',
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
                console.print(
                    f'[green]✓ Removed[/green] scheduled task [bold]{name}[/bold]')

            elif action == 'list':
                tasks = scheduler.list_tasks()
                if not tasks:
                    console.print(
                        '[yellow]No SystemUpdate scheduled tasks found.[/yellow]')
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
                        'status',
                        'schedule_type',
                        'next_run_time',
                        'last_run_time',
                        'last_result',
                        'task_to_run',
                        'run_as_user',
                ):
                    console.print(f'  [cyan]{key}[/cyan]: {info.get(key, "")}')

            elif action == 'run':
                scheduler.run_task_now(name)
                console.print(
                    f'[green]✓ Triggered[/green] task [bold]{name}[/bold]')

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

        console.print(
            '[bold cyan]🤖 Evaluating conditional actions...[/bold cyan]')
        apps = self.scan_system(getattr(args, 'source', None))
        try:
            from system_update.checkers import check_all_updates

            check_all_updates(
                apps,
                max_workers=self.settings.get(
                    'performance', {}).get('max_workers', 4),
            )
        except Exception as e:
            logger.warning(f'check_all_updates failed during eval: {e}')

        matched = conditions.evaluate(apps, self.settings)
        if not matched:
            console.print('[green]✓ No conditional rules matched.[/green]')
            return

        console.print(f'[bold]Matched {len(matched)} rule(s).[/bold]')
        conditions.apply(
            matched,
            apps,
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
                target, size = data_sharing.cloud_push(
                    cache_path, self.settings)
                console.print(
                    f'[green]✓ Pushed[/green] {size:,} bytes → [cyan]{target}[/cyan]')
            elif action == 'pull':
                target, size = data_sharing.cloud_pull(
                    cache_path, self.settings)
                console.print(
                    f'[green]✓ Pulled[/green] {size:,} bytes ← [cyan]{target}[/cyan]')
            elif action == 'status':
                stat = data_sharing.cloud_status(cache_path, self.settings)
                console.print('[bold]☁️  Cloud sync status[/bold]')
                for k, v in stat.items():
                    console.print(f'  [cyan]{k}[/cyan]: {v}')
            else:
                console.print(
                    f'[red]Unknown cloud-sync action: {action}[/red]')
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
                    f'[green]✓ Imported[/green] {len(batch)} package(s) from [cyan]{path}[/cyan]'
                )
                batches.append(batch)
            except (FileNotFoundError, ValueError) as e:
                console.print(f'[red]✗ Import failed for {path}:[/red] {e}')
            except Exception as e:
                console.print(
                    f'[red]✗ Unexpected import error for {path}:[/red] {e}')

        if merge_with_cache:
            cached = self.cache_mgr.load() or []
            if cached:
                console.print(
                    f'[bold cyan]⚡ Cache Hit![/bold cyan] '
                    f'[dim]Merging with {len(cached)} cached package(s) '
                    f'{self._cache_expiry_hint()}...[/dim]'
                )
                batches.append(cached)

        if not batches:
            return []

        merged = data_sharing.merge_apps(*batches, prefer='latest')
        console.print(
            f'[bold]🧬 Merge complete:[/bold] {len(merged)} unique package(s)')
        # Persist merged result so subsequent runs use it.
        try:
            self._save_cache_with_context(merged)
            console.print(
                '[bold green]✓[/bold green] '
                f'[dim]Cache updated with merged data {self._cache_expiry_hint()}[/dim]')
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
                display_source(app.source),
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
            vuln_tag = ' [red]🔥[/red]' if app.is_vulnerable else ''
            console.print(
                f'  • {app.name} [{display_source(app.source)}] '
                f'{app.version} → {app.latest_version}{vuln_tag}'
            )

        # Render the CVE detail when any selected package is vulnerable.
        vuln_chosen = [a for a in chosen if a.is_vulnerable]
        if vuln_chosen:
            self._display_security_table(vuln_chosen)

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
        import sys as _sys

        store = None if dry_run else self._snapshot_store()
        try:
            UpdateExecutor.execute_updates(
                chosen,
                dry_run=dry_run,
                snapshot_store=store,
                snapshot_label='interactive',
                snapshot_command=' '.join(_sys.argv),
            )
        finally:
            if store is not None:
                store.close()

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
                display_source(str(s.get('source', '') or '-'))[:60],
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
            console.print(
                f'[yellow]No history found for[/yellow] [bold]{package}[/bold].')
            return
        table = Table(title=f'🔍 Version history — {package}', expand=True)
        table.add_column('Timestamp', style='cyan')
        table.add_column('Source', style='magenta')
        table.add_column('Version', style='white')
        table.add_column('Change', style='yellow')
        for r in rows:
            table.add_row(
                str(r.get('timestamp', '')),
                display_source(str(r.get('source', '') or '-')),
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
        console.print(
            f'Unique packages tracked: [cyan]{data.get("unique_packages", 0)}[/cyan]')
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
                display_source(str(row.get('source', '') or '-'))[:40],
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
            console.print(
                f'[green]✓ No packages stale beyond {days} day(s).[/green]')
            return
        table = Table(
            title=f'🕰️  Packages not updated in {days}+ day(s)', expand=True)
        table.add_column('Package', style='bold')
        table.add_column('Source', style='magenta')
        table.add_column('Last seen', style='cyan')
        for r in stale:
            table.add_row(
                str(r.get('package_name', '')),
                display_source(str(r.get('source', '') or '-')),
                str(r.get('last_seen', '')),
            )
        console.print(table)
        console.print(f'[yellow]Total stale:[/yellow] {len(stale)}')

    def _generate_history_report(self, fmt: str, output: Optional[str] = None) -> None:
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
                    f'  [{s.get("timestamp", "")}] '
                    f'{display_source(str(s.get("source", "-"))):<25} '
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
                    f'  - {display_source(str(r.get("source", "-"))):<20} '
                    f'scans={r.get("total_scans", 0):>3}  '
                    f'updates={r.get("total_updates", 0) or 0:>4}'
                )
            lines += ['', f'Stale packages (>90d): {len(stale)}']
            for r in stale[:20]:
                lines.append(
                    f'  - {r.get("package_name", ""):<30} '
                    f'{display_source(str(r.get("source", "-"))):<15} '
                    f'last_seen={r.get("last_seen", "")}'
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
            console.print(
                f'[green]✓[/green] History report written to [cyan]{out}[/cyan]')
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
            f'<td>{_esc(display_source(str(s.get("source", "-"))))}</td>'
            f'<td>{s.get("package_count", 0)}</td>'
            f'<td>{s.get("update_count", 0)}</td>'
            f'<td>{s.get("vulnerability_count", 0)}</td></tr>'
            for s in scans[:50]
        )
        trend_rows = '\n'.join(
            f'<tr><td>{_esc(display_source(str(r.get("source", "-"))))}</td>'
            f'<td>{r.get("total_scans", 0)}</td>'
            f'<td>{r.get("total_packages", 0) or 0}</td>'
            f'<td>{r.get("total_updates", 0) or 0}</td></tr>'
            for r in (trends.get('source_stats') or [])
        )
        stale_rows = '\n'.join(
            f'<tr><td>{_esc(r.get("package_name", ""))}</td>'
            f'<td>{_esc(display_source(str(r.get("source", "-"))))}</td>'
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
