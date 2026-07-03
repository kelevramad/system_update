"""Typed CLI option contract shared by the Typer entry point and app layer."""

from __future__ import annotations

from dataclasses import dataclass, fields
from typing import Any, List, Optional


@dataclass(frozen=True)
class CLIOptions:
	"""Typed representation of all supported CLI flags.

	The Typer command still receives individual parameters, but they are
	converted into this dataclass before entering the app orchestration layer.
	Defaults mirror the legacy namespace values.
	"""

	source: Optional[str] = None
	exclude: Optional[str] = None
	update_source: Optional[str] = None
	update_all: bool = False
	dry_run: bool = False
	show_commands: bool = False
	yes: bool = False
	no_cache: bool = False
	clear_cache: bool = False
	profile: Optional[str] = None
	profile_export: Optional[str] = None
	profile_import: Optional[str] = None
	save_config: bool = False
	format: Optional[str] = None
	theme: Optional[str] = None
	interactive: bool = False
	show_all: bool = False
	notify: bool = False
	export: Optional[str] = None
	output: Optional[str] = None
	html_template: Optional[str] = None
	html_logo: Optional[str] = None
	html_title: Optional[str] = None
	html_company: Optional[str] = None
	package: Optional[str] = None
	version: Optional[str] = None
	history: bool = False
	history_package: Optional[str] = None
	history_trends: bool = False
	history_stale: int = 0
	report: Optional[str] = None
	report_output: Optional[str] = None
	dependency_graph: Optional[str] = None
	graph_output: Optional[str] = None
	import_files: Optional[List[str]] = None
	merge_with_cache: bool = False
	list_plugins: bool = False
	list_plugins_detail: bool = False
	no_plugins: bool = False
	cloud_sync: Optional[str] = None
	schedule: Optional[str] = None
	schedule_name: Optional[str] = 'SystemUpdate_Scan'
	schedule_when: Optional[str] = 'daily'
	schedule_time: Optional[str] = '09:00'
	schedule_days: Optional[str] = ''
	schedule_args: Optional[str] = '--no-cache --notify'
	snapshot: Optional[str] = None
	snapshot_id: Optional[str] = None
	rollback: Optional[str] = None
	remote: Optional[str] = None
	remote_host: Optional[str] = None
	remote_group: Optional[str] = None
	remote_address: Optional[str] = None
	remote_user: Optional[str] = None
	remote_groups: Optional[str] = None
	remote_args: Optional[str] = None
	remote_output: Optional[str] = None
	remote_timeout: int = 600
	remote_verbose: bool = False
	remote_debug: bool = False
	debug: bool = False
	log: bool = False

	@classmethod
	def from_namespace(cls, ns: Any) -> 'CLIOptions':
		"""Build options from a legacy namespace or return existing options."""
		if isinstance(ns, cls):
			return ns
		values = vars(ns)
		payload: dict[str, Any] = {}
		for field in fields(cls):
			if field.name in values:
				payload[field.name] = values[field.name]
		return cls(**payload)

	def validate(self) -> None:
		"""Validate cross-flag constraints that are easier after conversion."""
		if self.update_all and self.package:
			raise ValueError('--update-all cannot be combined with --update-package')


__all__ = ['CLIOptions']
