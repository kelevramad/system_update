"""Top-level orchestrator — scan → check → security → display → export → update.

:class:`SystemUpdateApp` composes every subsystem (config, cache, history,
scanners, update-checkers, executors, security, UI) and drives the full
workflow exactly like the legacy flat ``system_update.py`` did, so this
module is the one the typer CLI targets.
"""

from __future__ import annotations

import logging
import os
import threading  # noqa: F401 - legacy tests patch system_update.app.threading.Thread
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from rich.prompt import Prompt

from system_update.cache import CacheManager
from system_update.checkers import UpdateChecker
from system_update.cli_options import CLIOptions
from system_update.config import SystemConfig, setup_logging
from system_update.executors import UpdateExecutor
from system_update.history import HistoryDatabase, VulnerabilityHistory
from system_update.models import AppInfo, UpdateStatus
from system_update.network import configure_network, fetch_json
from system_update.notifications import NotificationManager
from system_update.plugins import (
    PluginRegistry,
    checker_map,
    load_plugins,
    scanner_map,
    security_checker_map,
)
from system_update.scanners import PackageScanner, get_scanner_map
from system_update.security import SecurityChecker
from system_update.security.common import is_security_issue
from system_update.ui import DisplayFormatter, UISystem
from system_update.utils import console, dedupe_apps, display_source, source_chip

logger = logging.getLogger(__name__)


def _split_security_results(results: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
    """Return ``(vulnerabilities, scanner_issues)`` for security check output."""
    issues = [item for item in results if is_security_issue(item)]
    vulns = [item for item in results if not is_security_issue(item)]
    return vulns, issues


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


from system_update.app_actions import AppActionsMixin  # noqa: E402


class SystemUpdateApp(AppActionsMixin):
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
        scanners = get_scanner_map()
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
                extra_checkers=checker_map(self.plugins),
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
            security_results = self.security.check_all(
                new_apps, advisory_file,
                extra_checkers=security_checker_map(self.plugins),
            )
            security_vulns, security_issues = _split_security_results(security_results)
            if security_vulns:
                console.print(
                    f'[bold red]🔥 Found {len(security_vulns)} '
                    f'security vulnerabilities.[/bold red]\n'
                )
            else:
                console.print(
                    '[bold green]🛡️ No security vulnerabilities found.[/bold green]\n')
            for issue in security_issues:
                console.print(f'[yellow]! {issue.get("message", "Security check skipped")}[/yellow]')
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

    def run(self, args: Any) -> None:
        """Full flow: scan → check → security → cache → history → display → export → update."""
        args = CLIOptions.from_namespace(args)
        # Activate the named profile BEFORE setup_logging so log/cache/history
        # all land in the right directory. SystemConfig.__init__ runs with the
        # default profile (we don't see args yet), so we re-init here.
        # Strict ``isinstance(str)`` so MagicMock attrs in unit tests don't
        # accidentally get treated as profile names.
        profile = args.profile
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
            debug=args.debug,
            enable_log=args.log,
        )

        # Apply UI overrides from CLI flags.
        if args.theme:
            self.settings.setdefault('ui', {})['theme'] = args.theme
        if args.format:
            self.settings.setdefault('ui', {})['display_format'] = args.format

        # --save-config: fold this run's CLI overrides into config.json so the
        # next run uses them as defaults. Specifically: --source X,Y,Z sets
        # sources.* to True only for those sources (everything else False).
        if args.save_config:
            self._persist_cli_overrides(args)

        # Step 11 features (history/report/interactive) are routed here.
        if self._handle_meta_commands(args):
            return

        if args.clear_cache:
            self.cache_mgr.clear()
            console.print('[green]🗑️  Cache cleared successfully![/green]')
            return

        self.ui.display_banner(self.config)
        self._include_sources = set()

        # --update-source <s> is shorthand for --source <s> --update-all --yes.
        if args.update_source:
            args = replace(args, source=args.update_source, update_all=True)
            # Don't auto-confirm — let the user see the queued packages and
            # approve. Add ``--yes`` explicitly to skip prompts.

        if args.source:
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
            args = replace(args, source=','.join(sorted(valid)))

        apps: Optional[List[AppInfo]] = None

        # ── --import (5.4.1) / --merge (5.4.2) ─────────────────────────────
        import_files = args.import_files or []
        if import_files:
            merge_flag = bool(args.merge_with_cache)
            imported = self._import_apps_from_files(import_files, merge_flag)
            if imported:
                apps = imported
                # Imported data short-circuits live scan; security checks
                # can still run on the imported set below.
                security_vulns = []
                total_updates = _count_updates(apps)

        # ── cache check ────────────────────────────────────────────────────
        no_cache = args.no_cache
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
            apps = self.scan_system(args.source)
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
                extra_checkers=checker_map(self.plugins),
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
            security_results = self.security.check_all(
                apps, advisory_file,
                extra_checkers=security_checker_map(self.plugins),
            )
            security_vulns, security_issues = _split_security_results(security_results)

            if security_vulns:
                console.print(
                    f'[bold red]🔥 Found {len(security_vulns)} '
                    f'security vulnerabilities.[/bold red]\n'
                )
            else:
                console.print(
                    '[bold green]🛡️ No security vulnerabilities found.[/bold green]\n')
            for issue in security_issues:
                console.print(f'[yellow]! {issue.get("message", "Security check skipped")}[/yellow]')
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
            if args.no_cache:
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
        exclude_tokens = _parse_exclude_list(args.exclude)
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

        if args.dependency_graph:
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
                if is_security_issue(f):
                    continue
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
            show_all=args.show_all,
            security_stats=security_stats,
        )

        if args.package:
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
            show_all=args.show_all,
        )
        console.print(apps_table)

        if args.show_all:
            console.print('\n[dim]💾 Showing: all packages[/dim]')
        else:
            console.print('\n[dim]💾 Showing: updates only[/dim]')

        if vulnerable:
            self._display_security_table(vulnerable)

        if updates or vulnerable:
            security_updates = [a for a in vulnerable if a.has_update]
            total_count = self._print_available_updates_summary(
                updates, security_updates)
            before_update_state = self._update_cache_state(apps)

            if args.notify:
                self.notifier.notify_updates_available(
                    total_count, len(security_updates), force=True
                )

            if args.interactive:
                self._interactive_update(updates, vulnerable, args)
                self._save_cache_after_updates(apps, args, before_update_state)
            elif args.update_all:
                self._update_all_workflow(updates, vulnerable, args)
                self._save_cache_after_updates(apps, args, before_update_state)
        else:
            console.print('\n[green]✨ System is up to date![/green]')

        export_format = args.export
        output_path = args.output
        if isinstance(export_format, str) and export_format:
            from system_update import export as export_module

            branding = None
            template_path = None
            if export_format == 'html':
                from system_update.report_templates import resolve_branding

                cli_overrides = {
                    'title': args.html_title,
                    'company_name': args.html_company,
                    'logo_path': args.html_logo,
                }
                branding = resolve_branding(self.settings, cli_overrides)
                template_path = args.html_template or (
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
