"""Scheduled update command entry point.

Hardening 3.1.3 — the schedule logic was extracted from
:meth:`SystemUpdateApp._handle_schedule` so the command module owns
its own workflow.
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from rich.table import Table

from system_update.cli_options import CLIOptions
from system_update.utils import console

if TYPE_CHECKING:
	from system_update.app import SystemUpdateApp


class ScheduleCommand:
	"""Dispatch schedule actions."""

	def execute(self, args: Any, app_ctx: 'SystemUpdateApp') -> int:
		args = CLIOptions.from_namespace(args)
		from system_update import scheduler, subhelp

		action = (args.schedule or '').lower()
		name = args.schedule_name or 'SystemUpdate_Scan'

		if action == 'help':
			subhelp.show('schedule')
			return 0

		if action == 'eval':
			app_ctx._evaluate_conditional_actions(args)
			return 0

		try:
			if action == 'create':
				spec = scheduler.ScheduleSpec(
					name=name,
					frequency=args.schedule_when or 'daily',
					time=args.schedule_time or '09:00',
					days=args.schedule_days or '',
					command_args=args.schedule_args or '',
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
					f'[green]✓ Removed[/green] scheduled task [bold]{name}[/bold]'
				)

			elif action == 'list':
				tasks = scheduler.list_tasks()
				if not tasks:
					console.print(
						'[yellow]No SystemUpdate scheduled tasks found.[/yellow]'
					)
					return 0
				t = Table(title='🗓️  Scheduled tasks', expand=True)
				t.add_column('Name', style='bold')
				t.add_column('Next run', style='cyan')
				t.add_column('Last run', style='yellow')
				t.add_column('Last result', style='green', justify='right')
				t.add_column('Status', style='magenta')
				for entry in tasks:
					last_run = entry.get('last_run', '') or ''
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
					return 0
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
					f'[green]✓ Triggered[/green] task [bold]{name}[/bold]'
				)

		except RuntimeError as e:
			console.print(f'[red]✗ Schedule error:[/red] {e}')
		except ValueError as e:
			console.print(f'[red]✗ Invalid schedule spec:[/red] {e}')

		return 0


__all__ = ['ScheduleCommand']
