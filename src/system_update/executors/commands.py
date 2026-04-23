"""Per-source update-command builders.

Each builder returns the argv list for updating one :class:`AppInfo`, or
``None`` if the source can't (yet) perform updates for that package. The
module keeps builders as pure functions so they're trivially unit-testable.
"""

from __future__ import annotations

import sys
from typing import Callable, Dict, List, Optional

from system_update.models import AppInfo

Command = List[str]


def _winget(app: AppInfo) -> Optional[Command]:
	cmd: Command = [
		'winget', 'upgrade', '--id', app.app_id,
		'--accept-source-agreements', '--accept-package-agreements',
	]
	if app.latest_version:
		cmd.extend(['-v', app.latest_version])
	return cmd


def _chocolatey(app: AppInfo) -> Optional[Command]:
	cmd: Command = ['choco', 'upgrade', app.name, '-y']
	if app.latest_version:
		cmd.extend(['--version', app.latest_version])
	return cmd


def _spec(name: str, version: str, separator: str = '@') -> str:
	"""Build a ``name<sep>version`` spec, or just ``name`` when version is empty."""
	return f'{name}{separator}{version}' if version else name


def _npm(app: AppInfo) -> Optional[Command]:
	return ['npm', 'install', '-g', _spec(app.name, app.latest_version)]


def _pnpm(app: AppInfo) -> Optional[Command]:
	return ['pnpm', 'add', '-g', _spec(app.name, app.latest_version)]


def _bun(app: AppInfo) -> Optional[Command]:
	return ['bun', 'add', '-g', _spec(app.name, app.latest_version)]


def _yarn(app: AppInfo) -> Optional[Command]:
	return ['yarn', 'global', 'add', _spec(app.name, app.latest_version)]


def _pip(app: AppInfo) -> Optional[Command]:
	cmd: Command = [
		sys.executable, '-m', 'pip', 'install',
		_spec(app.name, app.latest_version, separator='=='),
	]
	if not app.latest_version:
		cmd.append('--upgrade')
	return cmd


def _rust(app: AppInfo) -> Optional[Command]:
	return ['cargo', 'install-update', app.name]


def _dotnet(app: AppInfo) -> Optional[Command]:
	return ['dotnet', 'tool', 'update', '-g', app.name]


_PATH_UPDATERS: Dict[str, Callable[[AppInfo], Optional[Command]]] = {
	'bun': lambda app: ['bun', 'upgrade'],
	'deno': lambda app: (
		['deno', 'upgrade', '--version', app.latest_version]
		if app.latest_version
		else ['deno', 'upgrade']
	),
	'git': lambda app: ['git', 'update-git-for-windows', '-y'],
	'pwsh': lambda app: [
		'powershell', '-Command',
		'iex "& { $(irm https://aka.ms/install-powershell.ps1) }"',
	],
	'yarn': lambda app: ['npm', 'install', '-g', _spec('yarn', app.latest_version)],
}


def _path(app: AppInfo) -> Optional[Command]:
	builder = _PATH_UPDATERS.get(app.name)
	return builder(app) if builder else None


_BUILDERS: Dict[str, Callable[[AppInfo], Optional[Command]]] = {
	'Winget': _winget,
	'Chocolatey': _chocolatey,
	'NPM': _npm,
	'PNPM': _pnpm,
	'Bun': _bun,
	'Yarn': _yarn,
	'PIP': _pip,
	'Rust': _rust,
	'dotnet': _dotnet,
	'PATH': _path,
}


def build_update_command(app: AppInfo) -> Optional[Command]:
	"""Return the argv for updating ``app``, or ``None`` if unsupported."""
	builder = _BUILDERS.get(app.source)
	return builder(app) if builder else None
