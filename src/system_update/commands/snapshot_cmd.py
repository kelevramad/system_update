"""Snapshot listing/show/delete command entry point.

Hardening 3.1.2 — the snapshot logic was extracted from
:meth:`SystemUpdateApp._handle_snapshot` so the command module owns
its own workflow.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, TYPE_CHECKING

from rich.table import Table

from system_update.cli_options import CLIOptions
from system_update.utils import console, display_source

if TYPE_CHECKING:
	from system_update.app import SystemUpdateApp


class SnapshotCommand:
	"""Dispatch snapshot actions."""

	def execute(self, args: Any, app_ctx: 'SystemUpdateApp') -> int:
		args = CLIOptions.from_namespace(args)
		from system_update import subhelp

		action = (args.snapshot or '').lower()
		if action == 'help':
			subhelp.show('snapshot')
			return 0

		from system_update.snapshots import SnapshotStore

		store = SnapshotStore(Path(app_ctx.config.config_dir) / 'history.db')
		with store:
			if action == 'list':
				rows = store.list_snapshots()
				if not rows:
					console.print(
						'[yellow]No snapshots recorded yet.[/yellow]'
					)
					return 0
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
				return 0

			target_id = args.snapshot_id or 'last'

			if action == 'show':
				snap = store.get(target_id)
				if not snap:
					console.print(
						f'[yellow]No snapshot found:[/yellow] {target_id}'
					)
					return 0
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
				return 0

			if action == 'delete':
				ok = store.delete(target_id)
				if ok:
					console.print(
						f'[green]✓ Deleted[/green] snapshot '
						f'[bold]{target_id}[/bold]'
					)
				else:
					console.print(
						f'[yellow]No snapshot found:[/yellow] {target_id}'
					)
				return 0

		return 0


__all__ = ['SnapshotCommand']
