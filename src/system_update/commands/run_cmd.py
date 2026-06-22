"""Default run command entry point.

Hardening 3.1.5 — the full scan/check/security/display/export/update
workflow was extracted from :meth:`SystemUpdateApp.run` so the command
module owns the orchestration.
"""

from __future__ import annotations

import os
import time
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, TYPE_CHECKING

from system_update.app import (
	_apply_excludes,
	_count_updates,
	_parse_exclude_list,
	_partition_sources,
	_phase_time_label,
	_pypi_fallback_latest,
	_split_security_results,
)
from system_update.cli_options import CLIOptions
from system_update.config import setup_logging
from system_update.models import AppInfo, UpdateStatus
from system_update.network import configure_network
from system_update.notifications import NotificationManager
from system_update.plugins import (
	checker_map,
	load_plugins,
	security_checker_map,
)
from system_update.security.common import is_security_issue
from system_update.ui import DisplayFormatter
from system_update.utils import console, data_dir, display_source

if TYPE_CHECKING:
	from system_update.app import SystemUpdateApp


class RunCommand:
    """Dispatch the default scan/render/update flow."""

    def execute(self, args: Any, app_ctx: 'SystemUpdateApp') -> None:
        """Full flow: scan → check → security → cache → history → display → export → update."""
        args = CLIOptions.from_namespace(args)
        # Activate the named profile BEFORE setup_logging so log/cache/history
        # all land in the right directory. SystemConfig.__init__ runs with the
        # default profile (we don't see args yet), so we re-init here.
        # Strict ``isinstance(str)`` so MagicMock attrs in unit tests don't
        # accidentally get treated as profile names.
        profile = args.profile
        if isinstance(profile, str) and profile:
            app_ctx.config.reinit(profile)
            app_ctx.settings = app_ctx.config.settings
            configure_network(app_ctx.settings.get(
                'network', {}), app_ctx.config.config_dir)
            # Re-bind any sub-system that captured an old path.
            from system_update.cache import CacheManager
            from system_update.history import HistoryDatabase, VulnerabilityHistory

            app_ctx.cache_mgr = CacheManager(
                app_ctx.config.cache_file,
                app_ctx.settings.get('cache', {}).get('duration_hours', 2),
            )
            app_ctx._configure_cache_manager()
            app_ctx.notifier = NotificationManager(app_ctx.config)
            app_ctx.plugins = load_plugins(app_ctx.config)
            app_ctx.notifier.plugin_registry = app_ctx.plugins
            try:
                if app_ctx.history_db:
                    app_ctx.history_db.close()
            except Exception:
                pass
            app_ctx.history_db = HistoryDatabase(
                Path(app_ctx.config.config_dir) / 'history.db')
            app_ctx.vuln_history = VulnerabilityHistory(
                Path(app_ctx.config.config_dir) / 'vulnerability_history.json'
            )
            console.print(
                f'[bold cyan]👤 Profile activated:[/bold cyan] [bold]{profile}[/bold]')

        setup_logging(
            app_ctx.config,
            debug=args.debug,
            enable_log=args.log,
        )

        # Apply UI overrides from CLI flags.
        if args.theme:
            app_ctx.settings.setdefault('ui', {})['theme'] = args.theme
        if args.format:
            app_ctx.settings.setdefault('ui', {})['display_format'] = args.format

        # --save-config: fold this run's CLI overrides into config.json so the
        # next run uses them as defaults. Specifically: --source X,Y,Z sets
        # sources.* to True only for those sources (everything else False).
        if args.save_config:
            app_ctx._persist_cli_overrides(args)

        # Step 11 features (history/report/interactive) are routed here.
        if app_ctx._handle_meta_commands(args):
            return

        if args.clear_cache:
            app_ctx.cache_mgr.clear()
            console.print('[green]🗑️  Cache cleared successfully![/green]')
            return

        app_ctx.ui.display_banner(app_ctx.config)
        app_ctx._include_sources = set()

        # --update-source <s> is shorthand for --source <s> --update-all --yes.
        if args.update_source:
            args = replace(args, source=args.update_source, update_all=True)
            # Don't auto-confirm — let the user see the queued packages and
            # approve. Add ``--yes`` explicitly to skip prompts.

        if args.source:
            valid, invalid = _partition_sources(
                args.source, app_ctx.plugin_sources)
            if invalid:
                available = ', '.join(app_ctx._scanner_order())
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
            app_ctx._include_sources = valid
            # Overwrite args.source with the sanitized CSV so downstream
            # helpers (scan_system, _scanned_sources_label, cache sources check)
            # see only valid tokens.
            args = replace(args, source=','.join(sorted(valid)))

        apps: Optional[List[AppInfo]] = None

        # ── --import (5.4.1) / --merge (5.4.2) ─────────────────────────────
        import_files = args.import_files or []
        if import_files:
            merge_flag = bool(args.merge_with_cache)
            imported = app_ctx._import_apps_from_files(import_files, merge_flag)
            if imported:
                apps = imported
                # Imported data short-circuits live scan; security checks
                # can still run on the imported set below.
                security_vulns = []
                total_updates = _count_updates(apps)

        # ── cache check ────────────────────────────────────────────────────
        no_cache = args.no_cache
        cache_enabled = app_ctx.settings.get('cache', {}).get('enabled', True)

        if no_cache:
            console.print(
                '[cyan]🚀 Bypassing cache (--no-cache). Scanning live sources...[/cyan]\n'
            )
        elif not cache_enabled:
            console.print(
                '[dim]ℹ Cache disabled in config. Scanning live sources...[/dim]\n')

        if apps is None and not no_cache and cache_enabled:
            cached = app_ctx.cache_mgr.load()
            if cached:
                # Pip is interpreter-sensitive; if the user activated a venv
                # (or deactivated one) since the cache was written, the
                # cached pip entries are stale even though the timestamp is
                # fresh. Drop them so the partial-scan-merge path rescans.
                pip_stale = app_ctx._pip_context_changed()
                if pip_stale:
                    before = len(cached)
                    cached = [a for a in cached if a.source.lower() != 'pip']
                    recorded = app_ctx.cache_mgr.load_pip_context()
                    console.print(
                        f'[yellow]🐍 Python context changed[/yellow] '
                        f'(was: interpreter={recorded.get("interpreter", "?")}, '
                        f'venv={recorded.get("in_venv")}). '
                        f'[dim]Invalidated {before - len(cached)} cached '
                        f'pip entry(ies); will rescan pip.[/dim]\n'
                    )

                if app_ctx._include_sources:
                    missing = app_ctx._cache_missing_sources(
                        app_ctx._include_sources)
                    if pip_stale and 'pip' in app_ctx._include_sources:
                        missing.add('pip')
                    if missing:
                        apps = app_ctx._scan_missing_and_merge(cached, missing)
                    else:
                        apps = [a for a in cached if a.source.lower()
                                in app_ctx._include_sources]
                        app_ctx._maybe_prefetch_cache(
                            cached, app_ctx._include_sources)
                        console.print(
                            f'[bold cyan]⚡ Cache Hit![/bold cyan] '
                            f'[dim]Loaded {len(apps)} items from cache '
                            f'(filter: {",".join(sorted(app_ctx._include_sources))}) '
                            f'{app_ctx._cache_expiry_hint()}[/dim]\n'
                        )
                elif pip_stale:
                    # Bare run + pip context changed → treat pip as missing
                    # so the merge path rescans only pip.
                    apps = app_ctx._scan_missing_and_merge(cached, {'pip'})
                else:
                    enabled_sources = app_ctx._enabled_sources()
                    missing = app_ctx._cache_missing_sources(enabled_sources)
                    if missing and app_ctx.settings.get('cache', {}).get('incremental_enabled', True):
                        apps = app_ctx._scan_missing_and_merge(cached, missing)
                    else:
                        apps = cached
                        app_ctx._maybe_prefetch_cache(cached, enabled_sources)
                        console.print(
                            f'[bold cyan]⚡ Cache Hit![/bold cyan] '
                            f'[dim]Loaded {len(apps)} items from cache '
                            f'{app_ctx._cache_expiry_hint()}[/dim]\n'
                        )
            elif cached is not None and app_ctx._include_sources:
                # Valid but empty cache + --source X: scan X silently via merge
                # path so the full-scan banners don't fire.
                apps = app_ctx._scan_missing_and_merge(
                    [], set(app_ctx._include_sources))
            else:
                # Cache missing or expired (load() returned None)
                if app_ctx.cache_mgr.cache_file.exists():
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
            apps = app_ctx.scan_system(args.source)
            console.print(
                f'\n📦 [bold]Discovered {len(apps)} unique apps.[/bold]')
            console.print(_phase_time_label('Scanning sources', phase_start))

            # Phase 2 — update checking.
            console.print('[bold cyan]🔄 Checking for updates...[/bold cyan]')
            phase_start = time.time()
            app_ctx.checker.check_all_updates(
                apps,
                max_workers=app_ctx.settings.get(
                    'performance', {}).get('max_workers', 4),
                extra_checkers=checker_map(app_ctx.plugins),
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
            advisory_file = os.path.join(data_dir(), 'advisories.json')
            security_results = app_ctx.security.check_all(
                apps, advisory_file,
                extra_checkers=security_checker_map(app_ctx.plugins),
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
                    app_ctx.vuln_history.record_vulnerability(
                        app, finding, scan_id)

            scanned_sources = app_ctx._scanned_sources_label(args)
            scan_time = time.time() - start_time
            app_ctx.history_db.record_scan(
                apps, scan_id, scanned_sources, scan_time)

            total_updates = _count_updates(apps)
            if args.no_cache:
                console.print(
                    '[dim]💾 --no-cache: skipping cache write (scan results not persisted).[/dim]\n'
                )
            else:
                app_ctx._save_cache_with_context(
                    apps, app_ctx._fresh_scan_sources(args, apps))
                console.print(
                    f'[dim]💾 Cache updated ({len(apps)} items across '
                    f'{len({a.source.lower() for a in apps})} sources) '
                    f'{app_ctx._cache_expiry_hint()}[/dim]\n'
                )
        else:
            total_updates = _count_updates(apps)
            scan_time = 0.0

        # ── apply exclude list (CLI > env > config) ────────────────────────
        exclude_tokens = _parse_exclude_list(args.exclude)
        if not exclude_tokens:
            exclude_tokens = _parse_exclude_list(app_ctx.settings.get('exclude'))
        if exclude_tokens:
            before = len(apps)
            apps = _apply_excludes(apps, exclude_tokens, app_ctx.plugin_sources)
            dropped = before - len(apps)
            if dropped:
                console.print(
                    f'[dim]🚫 Excluded {dropped} package(s) matching: '
                    f'{", ".join(exclude_tokens)}[/dim]\n'
                )
            total_updates = _count_updates(apps)

        if args.dependency_graph:
            app_ctx._handle_dependency_graph(apps, args)
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
        security_stats = app_ctx.ui.compute_security_stats(all_vulns)

        app_ctx.ui.display_summary(
            len(apps),
            total_updates,
            scan_time,
            sources_count,
            show_all=args.show_all,
            security_stats=security_stats,
        )

        if args.package:
            app_ctx._handle_single_update(apps, args)
            return

        updates = [a for a in apps if a.update_status ==
                   UpdateStatus.UPDATE_AVAILABLE]
        vulnerable = [a for a in apps if a.update_status ==
                      UpdateStatus.VULNERABLE]

        console.print()
        ui_settings = app_ctx.settings.get('ui', {})
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
            app_ctx._display_security_table(vulnerable)

        if updates or vulnerable:
            security_updates = [a for a in vulnerable if a.has_update]
            total_count = app_ctx._print_available_updates_summary(
                updates, security_updates)
            before_update_state = app_ctx._update_cache_state(apps)

            if args.notify:
                app_ctx.notifier.notify_updates_available(
                    total_count, len(security_updates), force=True
                )

            if args.interactive:
                app_ctx._interactive_update(updates, vulnerable, args)
                app_ctx._save_cache_after_updates(apps, args, before_update_state)
            elif args.update_all:
                app_ctx._update_all_workflow(updates, vulnerable, args)
                app_ctx._save_cache_after_updates(apps, args, before_update_state)
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
                branding = resolve_branding(app_ctx.settings, cli_overrides)
                template_path = args.html_template or (
                    app_ctx.settings.get('report', {}).get(
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
