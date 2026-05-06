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


def _pip(app: AppInfo) -> Optional[Command]:
	cmd: Command = [
		_pip_interpreter(app), '-m', 'pip', 'install',
		_spec(app.name, app.latest_version, separator='=='),
		'--upgrade',
	]
	return cmd


def _rust(app: AppInfo) -> Optional[Command]:
	return ['cargo', 'install-update', app.name]


def _dotnet(app: AppInfo) -> Optional[Command]:
	return ['dotnet', 'tool', 'update', '-g', app.name]


def _appx(app: AppInfo) -> Optional[Command]:
	if not app.app_id:
		return None
	return [
		'winget', 'upgrade', '--id', app.app_id, '--source', 'msstore',
		'--accept-source-agreements', '--accept-package-agreements',
	]


def _ps_single_quote(value: str) -> str:
	return "'" + value.replace("'", "''") + "'"


def _psmodules(app: AppInfo) -> Optional[Command]:
	return [
		'powershell', '-NoProfile', '-Command',
		f'Update-Module -Name {_ps_single_quote(app.name)} -Force',
	]


def _vsextensions(app: AppInfo) -> Optional[Command]:
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


def _path(app: AppInfo) -> Optional[Command]:
	builder = _PATH_UPDATERS.get(app.name)
	return builder(app) if builder else None


_BUILDERS: Dict[str, Callable[[AppInfo], Optional[Command]]] = {
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


def build_update_command(app: AppInfo) -> Optional[Command]:
	"""Return the argv for updating ``app``, or ``None`` if unsupported."""
	builder = _BUILDERS.get((app.source or '').lower())
	return builder(app) if builder else None


# ─── 6.2.2 — Rollback builders ─────────────────────────────────────────────
#
# A rollback is "install version X" where X is the captured pre-update
# version. Most package managers we target accept a version argument on
# install/upgrade; the heavy lifting is per-source argv shape.


def _winget_rb(app: AppInfo) -> Optional[Command]:
	if not app.app_id or not app.latest_version:
		return None
	return [
		'winget', 'install', '--id', app.app_id, '-v', app.latest_version,
		'--accept-source-agreements', '--accept-package-agreements',
		'--force',
	]


def _chocolatey_rb(app: AppInfo) -> Optional[Command]:
	if not app.latest_version:
		return None
	return [
		'choco', 'install', app.name, '--version', app.latest_version,
		'--allow-downgrade', '-y', '-f',
	]


def _npm_rb(app: AppInfo) -> Optional[Command]:
	if not app.latest_version:
		return None
	return ['npm', 'install', '-g', f'{app.name}@{app.latest_version}']


def _pnpm_rb(app: AppInfo) -> Optional[Command]:
	if not app.latest_version:
		return None
	return ['pnpm', 'add', '-g', f'{app.name}@{app.latest_version}']


def _bun_rb(app: AppInfo) -> Optional[Command]:
	if not app.latest_version:
		return None
	return ['bun', 'add', '-g', f'{app.name}@{app.latest_version}']


def _yarn_rb(app: AppInfo) -> Optional[Command]:
	if not app.latest_version:
		return None
	return ['yarn', 'global', 'add', f'{app.name}@{app.latest_version}']


def _pip_rb(app: AppInfo) -> Optional[Command]:
	if not app.latest_version:
		return None
	return [
		_pip_interpreter(app), '-m', 'pip', 'install',
		f'{app.name}=={app.latest_version}',
		'--force-reinstall', '--no-deps',
	]


_ROLLBACK_BUILDERS: Dict[str, Callable[[AppInfo], Optional[Command]]] = {
	'winget': _winget_rb,
	'chocolatey': _chocolatey_rb,
	'npm': _npm_rb,
	'pnpm': _pnpm_rb,
	'bun': _bun_rb,
	'yarn': _yarn_rb,
	'pip': _pip_rb,
}


def build_rollback_command(app: AppInfo) -> Optional[Command]:
	"""Return the argv to install ``app.latest_version`` (treated as TARGET).

	The caller stages an :class:`AppInfo` whose ``latest_version`` holds the
	*old* version they want to restore. ``None`` means rollback isn't
	supported for this source (e.g. PATH/registry/scoop tools without
	version pinning).
	"""
	builder = _ROLLBACK_BUILDERS.get((app.source or '').lower())
	return builder(app) if builder else None


def supports_rollback(source: str) -> bool:
	return (source or '').lower() in _ROLLBACK_BUILDERS
