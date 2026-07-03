"""Per-source update-command builders.

Each builder returns the argv list for updating one :class:`AppInfo`, or
``None`` if the source can't (yet) perform updates for that package. The
module keeps builders as pure functions so they're trivially unit-testable.
"""

from __future__ import annotations

import logging
import re
import sys
from typing import Callable, Dict, List, Literal, Optional

from system_update.models import AppInfo

logger = logging.getLogger(__name__)

Command = List[str]
CommandAction = Literal['upgrade', 'rollback']


# Hardening 1.2.3 — strict allowlist for cache strings interpolated as
# argv tokens. Anything that wouldn't appear in a real package id or
# version (whitespace, quotes, semicolons, leading dashes) is rejected so
# a tampered cache file can't perform flag-injection on the underlying
# package manager (e.g. ``-v "1.0 --override"`` becoming a separate flag).
_SAFE_TOKEN_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9.+\-_~]*$')


def _safe_argv_token(value: Optional[str], *, field: str) -> Optional[str]:
	"""Return ``value`` unchanged if it looks like a valid argv token.

	Returns ``None`` (and logs a warning) if ``value`` is empty or fails
	the allowlist. Callers treat ``None`` as "skip this flag".
	"""
	if not value:
		return None
	if _SAFE_TOKEN_RE.match(value) is None:
		logger.warning(
			'Refusing unsafe %s value %r — does not match argv allowlist; '
			'cache file may be tampered with.',
			field,
			value,
		)
		return None
	return value


def _winget(action: CommandAction, app: AppInfo) -> Optional[Command]:
	app_id = _safe_argv_token(app.app_id, field='app_id')
	version = _safe_argv_token(app.latest_version, field='latest_version')
	if action == 'rollback':
		if not app_id or not version:
			return None
		return [
			'winget',
			'install',
			'--id',
			app_id,
			'-v',
			version,
			'--accept-source-agreements',
			'--accept-package-agreements',
			'--force',
		]
	if not app_id:
		return None
	cmd: Command = [
		'winget',
		'upgrade',
		'--id',
		app_id,
		'--accept-source-agreements',
		'--accept-package-agreements',
	]
	if version:
		cmd.extend(['-v', version])
	return cmd


def _chocolatey(action: CommandAction, app: AppInfo) -> Optional[Command]:
	version = _safe_argv_token(app.latest_version, field='latest_version')
	if action == 'rollback':
		if not version:
			return None
		return [
			'choco',
			'install',
			app.name,
			'--version',
			version,
			'--allow-downgrade',
			'-y',
			'-f',
		]
	cmd: Command = ['choco', 'upgrade', app.name, '-y']
	if version:
		cmd.extend(['--version', version])
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
			_pip_interpreter(app),
			'-m',
			'pip',
			'install',
			_spec(app.name, app.latest_version, separator='=='),
			'--force-reinstall',
			'--no-deps',
		]
	cmd: Command = [
		_pip_interpreter(app),
		'-m',
		'pip',
		'install',
		_spec(app.name, app.latest_version, separator='=='),
		'--upgrade',
	]
	return cmd


def _rust(action: CommandAction, app: AppInfo) -> Optional[Command]:
	if action == 'rollback':
		return None
	return ['cargo', 'install', app.name, '--force']


def _dotnet(action: CommandAction, app: AppInfo) -> Optional[Command]:
	if action == 'rollback':
		return None
	return ['dotnet', 'tool', 'update', '-g', app.name]


def _deno_updater(app: AppInfo) -> Command:
	version = _safe_argv_token(app.latest_version, field='latest_version')
	if version:
		return ['deno', 'upgrade', '--version', version]
	return ['deno', 'upgrade']


def _pwsh_updater(app: AppInfo) -> Command:
	"""Update PowerShell via winget (hash-verified by the manifest).

	**Hardening 1.2.2:** the previous implementation ran
	``iex "& { $(irm https://aka.ms/install-powershell.ps1) }"``, fetching
	and executing a remote script with no integrity check. winget verifies
	the installer's SHA-256 against its source manifest, so the install is
	tied to a known-good binary. Source pinned to ``winget`` to avoid Store
	packages with different upgrade semantics.
	"""
	return [
		'winget',
		'install',
		'--id',
		'Microsoft.PowerShell',
		'--source',
		'winget',
		'--accept-source-agreements',
		'--accept-package-agreements',
		'--force',
	]


_PATH_UPDATERS: Dict[str, Callable[[AppInfo], Optional[Command]]] = {
	'bun': lambda app: ['bun', 'upgrade'],
	'deno': _deno_updater,
	'git': lambda app: ['git', 'update-git-for-windows', '-y'],
	'pwsh': _pwsh_updater,
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
	'path': _path,
}

# Plugin-provided command builders keyed by source name.  Populated by
# ``register_plugin_command_builders`` after plugins are loaded.
_plugin_builders: Dict[str, Callable[[CommandAction, AppInfo], Optional[Command]]] = {}


def register_plugin_command_builders(
	builders: Dict[str, Callable[[str, AppInfo], Optional[Command]]],
) -> None:
	"""Register command builder functions from plugins.

	Each builder receives ``(action, app)`` where *action* is ``'upgrade'``
	or ``'rollback'`` and returns an argv list or ``None``.
	"""
	_plugin_builders.clear()
	for source, builder in builders.items():
		_plugin_builders[source.lower()] = builder  # type: ignore[assignment]


_ROLLBACK_SOURCES = frozenset(
	{
		'winget',
		'chocolatey',
		'npm',
		'pnpm',
		'bun',
		'yarn',
		'pip',
	}
)


def build_update_command(app: AppInfo) -> Optional[Command]:
	"""Return the argv for updating ``app``, or ``None`` if unsupported."""
	source = (app.source or '').lower()
	builder = _BUILDERS.get(source)
	if builder:
		return builder('upgrade', app)
	plugin_builder = _plugin_builders.get(source)
	if plugin_builder:
		return plugin_builder('upgrade', app)
	return None


def build_rollback_command(app: AppInfo) -> Optional[Command]:
	"""Return the argv to install ``app.latest_version`` (treated as TARGET).

	The caller stages an :class:`AppInfo` whose ``latest_version`` holds the
	*old* version they want to restore. ``None`` means rollback isn't
	supported for this source (e.g. PATH/scoop tools without
	version pinning).
	"""
	source = (app.source or '').lower()
	builder = _BUILDERS.get(source)
	if builder:
		return builder('rollback', app)
	plugin_builder = _plugin_builders.get(source)
	if plugin_builder:
		return plugin_builder('rollback', app)
	return None


def supports_rollback(source: str) -> bool:
	return (source or '').lower() in _ROLLBACK_SOURCES
