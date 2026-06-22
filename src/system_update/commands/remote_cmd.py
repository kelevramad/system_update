"""Remote management command entry point.

Hardening 3.1.1 — the remote logic was extracted from
:meth:`SystemUpdateApp._handle_remote` (and its helpers
:meth:`_run_remote_with_progress` and :meth:`_render_remote_results`)
so the command module owns its own workflow.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, List, TYPE_CHECKING

from rich.table import Table

from system_update.cli_options import CLIOptions
from system_update.utils import console

if TYPE_CHECKING:
	from system_update.app import SystemUpdateApp


class RemoteCommand:
	"""Dispatch remote-management actions."""

	def execute(self, args: Any, app_ctx: 'SystemUpdateApp') -> int:
		"""Dispatch ``--remote list|add|remove|scan|update|report|help``."""
		args = CLIOptions.from_namespace(args)
		from system_update import remote as remote_mod
		from system_update import subhelp

		action = (args.remote or '').lower()
		if action == 'help':
			subhelp.show('remote')
			return 0

		inv = remote_mod.Inventory()

		if action == 'list':
			if not inv.hosts:
				console.print(
					'[yellow]No remote hosts in inventory.[/yellow] '
					'[dim]Add one with [cyan]--remote add --remote-host NAME[/cyan].[/dim]'
				)
				return 0
			t = Table(title='🌐 Remote inventory', expand=True)
			t.add_column('Name', style='bold')
			t.add_column('Address', style='cyan')
			t.add_column('User', style='magenta')
			t.add_column('Transport')
			t.add_column('Groups', style='dim')
			t.add_column('Description', style='dim')
			for h in inv.hosts:
				t.add_row(
					h.name,
					h.address,
					h.user or '-',
					h.transport,
					', '.join(h.groups) or '-',
					h.description or '-',
				)
			console.print(t)
			return 0

		if action == 'add':
			name = args.remote_host
			if not isinstance(name, str) or not name:
				console.print(
					'[red]✗ --remote add requires --remote-host NAME[/red]'
				)
				return 0
			groups = []
			raw_groups = args.remote_groups
			if isinstance(raw_groups, str) and raw_groups:
				groups = [
					g.strip() for g in raw_groups.split(',') if g.strip()
				]
			host = remote_mod.RemoteHost(
				name=name,
				address=args.remote_address or name,
				user=args.remote_user or '',
				transport=app_ctx._default_transport(),
				groups=groups,
			)
			inv.add(host)
			console.print(
				f'[green]✓ Added[/green] [bold]{host.name}[/bold] → '
				f'[cyan]{host.address}[/cyan] '
				f'(groups: {", ".join(host.groups) or "none"})'
			)
			return 0

		if action == 'remove':
			name = args.remote_host
			if not isinstance(name, str) or not name:
				console.print(
					'[red]✗ --remote remove requires --remote-host NAME[/red]'
				)
				return 0
			ok = inv.remove(name)
			if ok:
				console.print(f'[green]✓ Removed[/green] [bold]{name}[/bold]')
			else:
				console.print(
					f'[yellow]No host named[/yellow] [bold]{name}[/bold]'
				)
			return 0

		# scan / update / report all need a target list.
		hosts = inv.resolve(
			host=args.remote_host,
			group=args.remote_group,
		)
		if not hosts:
			console.print(
				'[yellow]No matching hosts.[/yellow] '
				'[dim]Pass --remote-host NAME or --remote-group GROUP, '
				'or use --remote list to see what is available.[/dim]'
			)
			return 0

		extra = args.remote_args or ''
		timeout = int(args.remote_timeout or 600)

		if action in ('scan', 'report'):
			cmd = remote_mod.build_remote_scan_command(extra)
		elif action == 'update':
			cmd = remote_mod.build_remote_update_command(extra)
		else:
			console.print(f'[red]Unknown remote action: {action}[/red]')
			return 0

		console.print(
			f'[bold cyan]🌐 Running on {len(hosts)} host(s):[/bold cyan] '
			f'[dim]{cmd}[/dim]'
		)

		debug = bool(args.remote_debug)
		verbose = bool(args.remote_verbose) or debug
		results = self._run_remote_with_progress(
			hosts, cmd, timeout, verbose, debug, app_ctx,
		)
		self._render_remote_results(results, action, args)
		return 0

	def _run_remote_with_progress(
		self,
		hosts: List,
		cmd: str,
		timeout: int,
		verbose: bool,
		debug: bool,
		app_ctx: object,
	) -> List:
		"""Fan-out to ``hosts`` with a per-host progress bar and optional streaming."""
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
					f'[dim]local command:[/dim] '
					f'{remote_mod.argv_to_display(debug_argv)}'
				)

		with make_progress() as progress:
			tasks = {
				h.name: progress.add_task(f'🌐 {h.name}', total=1)
				for h in hosts
			}

			def _on_start(host) -> None:
				if debug:
					progress.console.print(
						f'[dim]▶ started {host.name}; '
						f'waiting for winrs response...[/dim]'
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
					progress.console.print(
						f'\n[bold]── {icon} {host.name} '
						f'(exit {result.exit_code}, '
						f'{result.duration:.1f}s) ──[/bold]'
					)
					if result.stdout:
						tail = result.stdout.strip().splitlines()[-20:]
						progress.console.print(
							'[dim]stdout:[/dim] '
							+ (
								'\n  ' + '\n  '.join(tail)
								if tail
								else '(empty)'
							)
						)
					if result.stderr:
						err_tail = result.stderr.strip().splitlines()[-10:]
						progress.console.print(
							'[red]stderr:[/red] '
							+ (
								'\n  ' + '\n  '.join(err_tail)
								if err_tail
								else '(empty)'
							)
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
		self, results: List, action: str, args: Any
	) -> None:
		"""Print a summary table + optional consolidated JSON report."""
		args = CLIOptions.from_namespace(args)
		from system_update import remote as remote_mod

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
					r.parsed
					if isinstance(r.parsed, list)
					else r.parsed.get('packages') or []
				)
				updates = sum(
					1 for p in pkgs if p.get('status') == 'update_available'
				)
				vulns = sum(
					1 for p in pkgs if p.get('status') == 'vulnerable'
				)
				notes = (
					f'{len(pkgs)} pkgs · {updates} updates · {vulns} vulns'
				)
			elif r.stderr:
				notes = r.stderr.strip().splitlines()[-1][:120]
			t.add_row(
				r.host,
				status,
				str(r.exit_code),
				f'{r.duration:.1f}s',
				notes,
			)
		console.print(t)

		if action == 'report':
			report = remote_mod.aggregate_scans(results)
			out_path = args.remote_output
			payload = json.dumps(report.to_dict(), indent=2, default=str)
			if isinstance(out_path, str) and out_path:
				Path(out_path).parent.mkdir(parents=True, exist_ok=True)
				Path(out_path).write_text(payload, encoding='utf-8')
				console.print(
					f'[green]✓ Wrote consolidated report[/green] '
					f'→ [cyan]{out_path}[/cyan] '
					f'({report.host_count} hosts, '
					f'{len(report.package_index)} unique packages)'
				)
			else:
				console.print()
				console.print(
					f'[bold]🧾 Consolidated:[/bold] {report.host_count} hosts, '
					f'{len(report.package_index)} unique packages, '
					f'{report.error_count} errors. '
					f'Pass [cyan]--remote-output PATH[/cyan] to save full JSON.'
				)


__all__ = ['RemoteCommand']
