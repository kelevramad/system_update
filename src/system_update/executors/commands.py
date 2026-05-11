"""Per-source update-command builders.

Each builder returns the argv list for updating one :class:`AppInfo`, or
``None`` if the source can't (yet) perform updates for that package. The
module keeps builders as pure functions so they're trivially unit-testable.
"""

from __future__ import annotations

import sys
from typing import Callable, Dict, List, Literal, Optional

from system_update.models import AppInfo

Command = List[str]
CommandAction = Literal['upgrade', 'rollback']


def _winget(action: CommandAction, app: AppInfo) -> Optional[Command]:
	if action == 'rollback':
		if not app.app_id or not app.latest_version:
			return None
		return [
			'winget', 'install', '--id', app.app_id, '-v', app.latest_version,
			'--accept-source-agreements', '--accept-package-agreements',
			'--force',
		]
	cmd: Command = [
		'winget', 'upgrade', '--id', app.app_id,
		'--accept-source-agreements', '--accept-package-agreements',
	]
	if app.latest_version:
		cmd.extend(['-v', app.latest_version])
	return cmd


def _chocolatey(action: CommandAction, app: AppInfo) -> Optional[Command]:
	if action == 'rollback':
		if not app.latest_version:
			return None
		return [
			'choco', 'install', app.name, '--version', app.latest_version,
			'--allow-downgrade', '-y', '-f',
		]
	cmd: Command = ['choco', 'upgrade', app.name, '-y']
	if app.latest_version:
		cmd.extend(['--version', app.latest_version])
	return cmd


def _spec(name: str, version: str, separator: str = '@') -> str:
	"""Build a ``name<sep>version`` spec, or just ``name`` when version is empty."""
	return f'{name}{separator}{version}' if version else name


def _npm(action: CommandAction, app: AppInfo) -> Optional[Command]:
	if action == 'rollback' and not app.latest_version:
		return None
	return ['npm', 'install', '-g', _spec(app.name, app.latest_version)]


def _pnpm(action: CommandAction, app: AppInfo) -> Optional[Command]:
	if action == 'rollback' and not app.latest_version:
		return None
	return ['pnpm', 'add', '-g', _spec(app.name, app.latest_version)]


def _bun(action: CommandAction, app: AppInfo) -> Optional[Command]:
	if action == 'rollback' and not app.latest_version:
		return None
	return ['bun', 'add', '-g', _spec(app.name, app.latest_version)]


def _yarn(action: CommandAction, app: AppInfo) -> Optional[Command]:
	if action == 'rollback' and not app.latest_version:
		return None
	return ['yarn', 'global', 'add', _spec(app.name, app.latest_version)]


def _pip_interpreter(app: AppInfo) -> str:
	"""Return the interpreter to invoke for ``app``.

	Pip packages get scanned from multiple interpreters (active venv + user-site
	+ globals), so the install command must target the one that actually owns
	the package — otherwise ``pip install Pygments==2.20.0`` lands in the wrong
	site-packages and the next ``pip list --outdated`` keeps reporting it.
	"""
	hint = (app.install_path or '').strip()
	if hint and (hint.lower().endswith('python.exe') or hint.lower().endswith('python')):
		return hint
	return sys.executable


def _pip(action: CommandAction, app: AppInfo) -> Optional[Command]:
	if action == 'rollback':
		if not app.latest_version:
			return None
		return [
			_pip_interpreter(app), '-m', 'pip', 'install',
			_spec(app.name, app.latest_version, separator='=='),
			'--force-reinstall', '--no-deps',
		]
	cmd: Command = [
		_pip_interpreter(app), '-m', 'pip', 'install',
		_spec(app.name, app.latest_version, separator='=='),
		'--upgrade',
	]
	return cmd


def _rust(action: CommandAction, app: AppInfo) -> Optional[Command]:
	if action == 'rollback':
		return None
	return ['cargo', 'install-update', app.name]


def _dotnet(action: CommandAction, app: AppInfo) -> Optional[Command]:
	if action == 'rollback':
		return None
	return ['dotnet', 'tool', 'update', '-g', app.name]


def _appx(action: CommandAction, app: AppInfo) -> Optional[Command]:
	if action == 'rollback':
		return None
	if not app.app_id:
		return None
	return [
		'winget', 'upgrade', '--id', app.app_id, '--source', 'msstore',
		'--accept-source-agreements', '--accept-package-agreements',
	]


def _ps_single_quote(value: str) -> str:
	return "'" + value.replace("'", "''") + "'"


def _psmodules(action: CommandAction, app: AppInfo) -> Optional[Command]:
	if action == 'rollback':
		return None
	return [
		'powershell', '-NoProfile', '-Command',
		f'Update-Module -Name {_ps_single_quote(app.name)} -Force',
	]


def _vsextensions(action: CommandAction, app: AppInfo) -> Optional[Command]:
	if action == 'rollback':
		return None
	return ['code', '--install-extension', app.app_id or app.name, '--force']


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


def _path(action: CommandAction, app: AppInfo) -> Optional[Command]:
	if action == 'rollback':
		return None
	builder = _PATH_UPDATERS.get(app.name)
	return builder(app) if builder else None


_BUILDERS: Dict[str, Callable[[CommandAction, AppInfo], Optional[Command]]] = {
	'winget': _winget,
	'chocolatey': _chocolatey,
	'npm': _npm,
	'pnpm': _pnpm,
	'bun': _bun,
	'yarn': _yarn,
	'pip': _pip,
	'rust': _rust,
	'dotnet': _dotnet,
	'appx': _appx,
	'psmodules': _psmodules,
	'vsextensions': _vsextensions,
	'path': _path,
}
_ROLLBACK_SOURCES = frozenset({
	'winget',
	'chocolatey',
	'npm',
	'pnpm',
	'bun',
	'yarn',
	'pip',
})


def build_update_command(app: AppInfo) -> Optional[Command]:
	"""Return the argv for updating ``app``, or ``None`` if unsupported."""
	builder = _BUILDERS.get((app.source or '').lower())
	return builder('upgrade', app) if builder else None


def build_rollback_command(app: AppInfo) -> Optional[Command]:
	"""Return the argv to install ``app.latest_version`` (treated as TARGET).

	The caller stages an :class:`AppInfo` whose ``latest_version`` holds the
	*old* version they want to restore. ``None`` means rollback isn't
	supported for this source (e.g. PATH/registry/scoop tools without
	version pinning).
	"""
	builder = _BUILDERS.get((app.source or '').lower())
	return builder('rollback', app) if builder else None


def supports_rollback(source: str) -> bool:
	return (source or '').lower() in _ROLLBACK_SOURCES
