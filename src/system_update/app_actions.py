"""Large command/action methods extracted from :mod:`system_update.app`."""

from __future__ import annotations

# pyright: reportAttributeAccessIssue=false, reportArgumentType=false, reportCallIssue=false

import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from rich.prompt import Prompt

from system_update.cli_options import CLIOptions
from system_update.models import AppInfo, UpdateStatus
from system_update.network import configure_network
from system_update.plugins import checker_map, updater_map
from system_update.security import SecurityChecker
from system_update.utils import console, display_source
from system_update.app import (
    _parse_exclude_list,
    _parse_source_filter,
    _partition_sources,
)

logger = logging.getLogger(__name__)


def _confirm_default_no(message: str) -> bool:
    """Proxy through ``system_update.app`` so existing monkeypatch tests still work."""
    from system_update import app as app_module

    return app_module._confirm_default_no(message)


class AppActionsMixin:
    """Compatibility mixin for command handlers and legacy app helpers."""

    def _scanned_sources_label(self, args: Any) -> str:
        """Return the comma-separated label to record in the history DB for this scan."""
        args = CLIOptions.from_namespace(args)
        if args.source:
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
            self, updates: List[AppInfo], vulnerable: List[AppInfo], args: Any
    ) -> None:
        """Security-first update flow: vulnerable packages get their own confirmation + pass."""
        args = CLIOptions.from_namespace(args)
        security_updates = [a for a in vulnerable if a.has_update]
        regular_updates = [
            a for a in updates if a.update_status != UpdateStatus.VULNERABLE]
        dry_run = args.dry_run
        yes = args.yes

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
                        extra_updaters=updater_map(self.plugins),
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
                        extra_updaters=updater_map(self.plugins),
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

    def _handle_single_update(self, apps: List[AppInfo], args: Any) -> None:
        """Update one package by name, optionally constrained by source/version."""
        args = CLIOptions.from_namespace(args)
        target_name = (args.package or '').lower()
        source_arg = args.source
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
        version = args.version
        if version:
            target_app.latest_version = version
            console.print(f'[cyan]🎯 Targeting version: {version}[/cyan]')
        elif not target_app.has_update:
            console.print(
                f'[green]✅ {target_app.name} is up to date ({target_app.version})[/green]'
            )
            if not (args.yes or _confirm_default_no('🔄 Force reinstall?')):
                return
            target_app.latest_version = ''

        dry_run = args.dry_run
        yes = args.yes
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
                extra_updaters=updater_map(self.plugins),
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

    def _handle_dependency_graph(self, apps: List[AppInfo], args: Any) -> None:
        """Handle ``--dependency-graph`` actions after scan/cache/import resolution."""
        args = CLIOptions.from_namespace(args)
        from rich.table import Table

        from system_update import dependency_graph
        from system_update import subhelp

        action = (args.dependency_graph or '').lower()
        if action == 'help':
            subhelp.show('dependency-graph')
            return

        graph = dependency_graph.build_graph(apps)
        if action == 'dot':
            output = args.graph_output or 'dependency-graph.dot'
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

    def _handle_meta_commands(self, args: Any) -> bool:
        """Route history/report/interactive flags; return True if the command was consumed."""
        args = CLIOptions.from_namespace(args)
        if args.list_plugins_detail:
            self._show_plugins(detail=True)
            return True
        if args.list_plugins:
            self._show_plugins(detail=False)
            return True
        if args.history:
            self._show_history()
            return True
        if args.history_package:
            self._show_package_history(args.history_package)
            return True
        if args.history_trends:
            self._show_trends()
            return True
        if args.history_stale and args.history_stale > 0:
            self._show_stale(args.history_stale)
            return True
        if args.report:
            self._generate_history_report(
                args.report, args.report_output)
            return True
        if args.cloud_sync:
            self._handle_cloud_sync(args.cloud_sync)
            return True
        if args.schedule:
            from system_update.commands.schedule_cmd import ScheduleCommand

            ScheduleCommand().execute(args, self)
            return True
        if args.profile_export:
            self._export_profile(args.profile_export)
            return True
        if args.profile_import:
            self._import_profile(
                args.profile_import,
                target_name=args.profile,
            )
            return True
        if args.snapshot:
            from system_update.commands.snapshot_cmd import SnapshotCommand

            SnapshotCommand().execute(args, self)
            return True
        if args.rollback:
            self._handle_rollback(args)
            return True
        if args.remote:
            from system_update.commands.remote_cmd import RemoteCommand

            RemoteCommand().execute(args, self)
            return True
        return False

    def _show_plugins(self, detail: bool = False) -> None:
        """Display loaded plugins.

        Default (``detail=False``) shows one row per plugin file with
        capability chips and the first line of its module docstring.
        ``detail=True`` (mapped from ``--list-plugins-detail``) keeps the
        old per-extension-type breakdown for debugging.
        """
        empty = (
            not self.plugins.scanners
            and not self.plugins.checkers
            and not self.plugins.updaters
            and not self.plugins.security_checkers
            and not self.plugins.notifiers
        )
        if empty:
            console.print(
                '[yellow]No plugins loaded.[/yellow] '
                f'[dim]Add .py plugins under {Path(self.config.config_dir) / "plugins"} '
                'or configure plugins.paths.[/dim]'
            )
            for error in self.plugins.errors:
                console.print(f'[red]✗[/red] {error.path}: {error.error}')
            return

        if detail:
            self._show_plugins_detail()
        else:
            self._show_plugins_summary()

        for error in self.plugins.errors:
            console.print(f'[red]✗[/red] {error.path}: {error.error}')

    def _show_plugins_summary(self) -> None:
        """One-line-per-plugin summary with compact capability icons."""
        from rich.table import Table

        # Compact icons keep the row narrow so the description column has
        # room. Run --list-plugins-detail when you need the labels.
        icon_for = {
            'scanner': '[bold cyan]🧩[/bold cyan]',
            'checker': '[bold yellow]🔄[/bold yellow]',
            'updater': '[bold green]⬆️[/bold green]',
            'security': '[bold red]🔒[/bold red]',
            'notifier': '[bold magenta]🔔[/bold magenta]',
        }

        table = Table(title='Plugins', expand=True)
        table.add_column('Plugin', style='bold cyan', no_wrap=True)
        table.add_column('Caps', no_wrap=True, justify='left')
        table.add_column('Description', style='dim')

        # Collect all plugin names from metadata + any registrations whose
        # plugin is not yet in metadata (e.g. registered via SCANNERS dict).
        names = set(self.plugins.metadata.keys())
        for bucket in (self.plugins.scanners, self.plugins.checkers,
                       self.plugins.updaters, self.plugins.security_checkers,
                       self.plugins.notifiers):
            for entry in bucket.values():
                if entry.plugin:
                    names.add(entry.plugin)

        for name in sorted(names):
            meta = self.plugins.metadata.get(name)
            if meta is None:
                # Synthesize from registrations only.
                caps = self._capabilities_for(name)
                description = '(no description)'
            else:
                caps = meta.capabilities or self._capabilities_for(name)
                description = meta.description
            icons = ' '.join(icon_for.get(c, c) for c in caps) or '[dim]-[/dim]'
            table.add_row(name or '<unnamed>', icons, description)

        console.print(table)
        console.print(
            '[dim]Use [cyan]--list-plugins-detail[/cyan] to see each '
            'extension point per plugin.[/dim]'
        )

    def _show_plugins_detail(self) -> None:
        """Per-extension-point table — useful when debugging registrations."""
        from rich.table import Table

        table = Table(title='Plugins (detailed)', expand=True)
        table.add_column('Type', style='cyan')
        table.add_column('Name', style='bold')
        table.add_column('Plugin')
        table.add_column('Description', style='dim')

        for scanner in sorted(self.plugins.scanners.values(), key=lambda s: s.source):
            table.add_row(
                'scanner', scanner.source, scanner.plugin or '-',
                scanner.description or '-',
            )
        for checker in sorted(self.plugins.checkers.values(), key=lambda c: c.source):
            table.add_row(
                'checker', checker.source, checker.plugin or '-',
                checker.description or '-',
            )
        for updater in sorted(self.plugins.updaters.values(), key=lambda u: u.source):
            table.add_row(
                'updater', updater.source, updater.plugin or '-',
                updater.description or '-',
            )
        for sec in sorted(self.plugins.security_checkers.values(), key=lambda s: s.source):
            table.add_row(
                'security', sec.source, sec.plugin or '-',
                sec.description or '-',
            )
        for notifier in sorted(self.plugins.notifiers.values(), key=lambda n: n.name):
            table.add_row(
                'notifier', notifier.name, notifier.plugin or '-',
                notifier.description or '-',
            )
        console.print(table)

    def _capabilities_for(self, plugin_name: str) -> list:
        caps: list = []
        if any(s.plugin == plugin_name for s in self.plugins.scanners.values()):
            caps.append('scanner')
        if any(c.plugin == plugin_name for c in self.plugins.checkers.values()):
            caps.append('checker')
        if any(u.plugin == plugin_name for u in self.plugins.updaters.values()):
            caps.append('updater')
        if any(s.plugin == plugin_name for s in self.plugins.security_checkers.values()):
            caps.append('security')
        if any(n.plugin == plugin_name for n in self.plugins.notifiers.values()):
            caps.append('notifier')
        return caps

    # ── Remote management (6.4) ───────────────────────────────────────────

    def _default_transport(self) -> str:
        """Return ``pywinrm`` if available, otherwise ``winrs``."""
        try:
            import winrm  # type: ignore[import-not-found]  # noqa: F401
            return 'pywinrm'
        except ImportError:
            return 'winrs'

    def _handle_remote(self, args: Any) -> None:
        """Dispatch ``--remote list|add|remove|scan|update|report|help``."""
        from system_update.commands.remote_cmd import RemoteCommand
        RemoteCommand().execute(args, self)

    def _run_remote_with_progress(
            self,
            hosts: List,
            cmd: str,
            timeout: int,
            verbose: bool,
            debug: bool = False,
    ) -> List:
        """Deprecated — logic moved to :class:`RemoteCommand`."""
        from system_update.commands.remote_cmd import RemoteCommand
        return RemoteCommand()._run_remote_with_progress(
            hosts, cmd, timeout, verbose, debug, self,
        )

    def _render_remote_results(
            self, results: List, action: str, args: Any
    ) -> None:
        """Deprecated — logic moved to :class:`RemoteCommand`."""
        from system_update.commands.remote_cmd import RemoteCommand
        RemoteCommand()._render_remote_results(results, action, args)

    # ── Snapshots & rollback (6.2) ─────────────────────────────────────────

    def _snapshot_store(self):
        """Lazy-construct a :class:`SnapshotStore` against the active history.db."""
        from system_update.snapshots import SnapshotStore

        return SnapshotStore(Path(self.config.config_dir) / 'history.db')

    def _handle_snapshot(self, args: Any) -> None:
        """Dispatch ``--snapshot list|show|delete|help``."""
        from system_update.commands.snapshot_cmd import SnapshotCommand
        SnapshotCommand().execute(args, self)

    def _handle_rollback(self, args: Any) -> None:
        """Restore packages captured in a snapshot to their previous versions."""
        args = CLIOptions.from_namespace(args)
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

        dry_run = args.dry_run
        yes = args.yes
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
            self, apps: List[AppInfo], refreshed_sources: Optional[Set[str]] = None,
            scan_time: float = 0.0,
    ) -> None:
        """Wrap ``cache_mgr.save`` so we always record the pip context."""
        interpreter, in_venv = self._current_pip_context()
        self.cache_mgr.save(
            apps,
            pip_interpreter=interpreter,
            pip_in_venv=in_venv,
            refreshed_sources=refreshed_sources,
            scan_time=scan_time,
        )

    def _update_cache_state(self, apps: List[AppInfo]) -> Tuple[Tuple[str, ...], ...]:
        """Return the fields that change when an update result should be cached."""
        return tuple(
            (
                (app.source or '').lower(),
                (app.app_id or '').lower(),
                (app.name or '').lower(),
                app.version or '',
                app.latest_version or '',
                str(
                    app.update_status.value
                    if hasattr(app.update_status, 'value')
                    else app.update_status
                ),
            )
            for app in apps
        )

    def _save_cache_after_updates(
            self,
            apps: List[AppInfo],
            args: Any,
            before_state: Tuple[Tuple[str, ...], ...],
    ) -> None:
        """Persist successful update mutations while preserving unrelated cached sources."""
        args = CLIOptions.from_namespace(args)
        if args.dry_run or not self.settings.get('cache', {}).get('enabled', True):
            return
        if self._update_cache_state(apps) == before_state:
            return

        refreshed_sources = self._fresh_scan_sources(args, apps)
        apps_to_save = list(apps)
        if args.source:
            cached = self.cache_mgr.load() or []
            apps_to_save = [
                app for app in cached if app.source.lower() not in refreshed_sources
            ] + apps_to_save
            apps_to_save = sorted(
                apps_to_save,
                key=lambda app: f'{app.source.lower()}{app.name.lower()}',
            )

        self._save_cache_with_context(apps_to_save, refreshed_sources)
        console.print(
            '[bold green]✓[/bold green] '
            f'[dim]Cache updated with update result {self._cache_expiry_hint()}[/dim]'
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

    def _fresh_scan_sources(self, args: Any, apps: List[AppInfo]) -> Set[str]:
        """Sources refreshed by a full live scan."""
        args = CLIOptions.from_namespace(args)
        if args.source:
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
        if (remaining - datetime.now(timezone.utc)).total_seconds() > threshold * 60:
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

    def _persist_cli_overrides(self, args: Any) -> None:
        """Write current CLI overrides (sources, theme, format) into config.json.

        Only ``--source`` rewrites the ``sources`` block — every named source
        gets ``true`` and every other one gets ``false``. UI flags merge into
        ``ui``. Called when the user passes ``--save-config``.
        """
        args = CLIOptions.from_namespace(args)
        changed: List[str] = []

        def _str_arg(name: str):
            """Pull ``args.<name>`` only if it's a real non-empty string."""
            v = vars(args).get(name)
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

    def _handle_schedule(self, args: Any) -> None:
        """Dispatch ``--schedule create|delete|list|status|run|eval|help``."""
        from system_update.commands.schedule_cmd import ScheduleCommand
        ScheduleCommand().execute(args, self)

    def _evaluate_conditional_actions(self, args: Any) -> None:
        """Run a scan, evaluate ``conditional_actions`` rules, fire matched actions.

        Used by scheduled tasks: configure ``--schedule-args "--schedule eval"``
        (or any combination) to have the task run a scan and act on the result
        without prompts.
        """
        args = CLIOptions.from_namespace(args)
        from system_update import conditions

        console.print(
            '[bold cyan]🤖 Evaluating conditional actions...[/bold cyan]')
        apps = self.scan_system(args.source)
        try:
            from system_update.checkers import check_all_updates

            check_all_updates(
                apps,
                max_workers=self.settings.get(
                    'performance', {}).get('max_workers', 4),
                extra_checkers=checker_map(self.plugins),
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
            dry_run=args.dry_run,
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
            args: Any,
    ) -> None:
        """Show numbered list of update candidates, let user pick which to apply.

        Input syntax: ``all`` / ``none`` / comma-and-range list (e.g. ``1,3,5-7``).
        Vulnerable packages are listed first and pre-marked with [VULN].
        """
        args = CLIOptions.from_namespace(args)
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

        if not args.yes:
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

        dry_run = args.dry_run
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
                extra_updaters=updater_map(self.plugins),
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
        from system_update.report_templates import render_history_html

        return render_history_html(scans, trends, stale, vuln_stats, generated, branding)


__all__ = ['AppActionsMixin']
