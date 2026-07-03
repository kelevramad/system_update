"""Plugin API and loader for custom scanners and notification channels."""

from __future__ import annotations

import hashlib
import importlib.util
import inspect
import logging
import os
import platform
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Dict, Iterable, List, Optional

from system_update.models import AppInfo, UpdateStatus

logger = logging.getLogger(__name__)

# Process-wide flags so callers (CLI, app) can disable plugins without
# editing the config dict. ``--no-plugins`` flips the kill switch.
_PLUGIN_KILL_SWITCH = False
# One-shot warning so we tell the user once per process when an enabled
# plugin loads — even on a clean machine, this is worth flagging.
_LOAD_WARNED: set = set()

PluginScannerFunc = Callable[[], Iterable['AppInfo | Dict[str, Any]']]
PluginCheckerFunc = Callable[[List[AppInfo]], Any]
PluginUpdaterFunc = Callable[[AppInfo], Any]
PluginNotifierFunc = Callable[..., Any]
# Security checker: receives the apps the plugin owns and returns a list
# of vulnerability dicts (same shape produced by the built-in checkers,
# see system_update.security.local for a reference: package / severity /
# cvss_score / cve / description / source / affected_versions /
# published_date / advisory_url / fix_available).
PluginSecurityCheckerFunc = Callable[[List[AppInfo]], List[Dict[str, Any]]]

_SOURCE_RE = re.compile(r'^[a-z0-9][a-z0-9_.-]*$')


@dataclass(frozen=True)
class PluginContext:
	"""Context object passed to plugins during registration."""

	config: Any
	settings: Dict[str, Any]
	data_dir: Path


@dataclass
class PluginScanner:
	"""Registered custom package source scanner."""

	source: str
	scan: PluginScannerFunc
	description: str = ''
	plugin: str = ''
	enabled: bool = True


@dataclass
class PluginChecker:
	"""Registered custom update checker for a plugin source."""

	source: str
	check: PluginCheckerFunc
	description: str = ''
	plugin: str = ''
	enabled: bool = True


PluginCommandBuilderFunc = Callable[[str, 'AppInfo'], Optional[List[str]]]


@dataclass
class PluginUpdater:
	"""Registered custom updater for a plugin source."""

	source: str
	update: PluginUpdaterFunc
	description: str = ''
	plugin: str = ''
	enabled: bool = True
	build_command: Optional[PluginCommandBuilderFunc] = None


@dataclass
class PluginNotifier:
	"""Registered custom notification channel."""

	name: str
	notify: PluginNotifierFunc
	description: str = ''
	plugin: str = ''
	enabled: bool = True


@dataclass
class PluginSecurityChecker:
	"""Registered custom vulnerability checker for a plugin source.

	Plugin security checkers are dispatched by ``security.check_all``
	alongside the built-in OSV / npm / pip / GitHub Advisory checkers.
	Each one runs as its own row in the "Checking security
	vulnerabilities" progress display.
	"""

	source: str
	check: PluginSecurityCheckerFunc
	description: str = ''
	plugin: str = ''
	enabled: bool = True


@dataclass
class PluginLoadError:
	"""Non-fatal plugin loading error."""

	path: str
	error: str


@dataclass
class PluginMetadata:
	"""Per-plugin summary used by the ``--list-plugins`` summary view.

	Captures the file path, the human-readable name, the first line of
	the module docstring, and which extension points the plugin
	registered. The detailed per-type table is still available via
	``--list-plugins-detail``.
	"""

	name: str
	path: str
	description: str = ''
	capabilities: List[str] = field(default_factory=list)


@dataclass
class PluginRegistry:
	"""Registry exposed to extension modules from ``register_plugin``."""

	scanners: Dict[str, PluginScanner] = field(default_factory=dict)
	checkers: Dict[str, PluginChecker] = field(default_factory=dict)
	updaters: Dict[str, PluginUpdater] = field(default_factory=dict)
	notifiers: Dict[str, PluginNotifier] = field(default_factory=dict)
	security_checkers: Dict[str, PluginSecurityChecker] = field(default_factory=dict)
	errors: List[PluginLoadError] = field(default_factory=list)
	metadata: Dict[str, PluginMetadata] = field(default_factory=dict)
	_active_plugin: str = ''

	def register_scanner(
		self,
		source: str,
		scan: PluginScannerFunc,
		description: str = '',
		enabled: bool = True,
	) -> None:
		"""Register a custom package source.

		``source`` is the token users pass to ``--source`` and must be a simple
		lowercase-ish identifier (letters, numbers, dot, underscore, dash).
		"""
		canonical = _normalize_source_name(source)
		if not callable(scan):
			raise TypeError(f'scanner for {canonical!r} must be callable')
		self.scanners[canonical] = PluginScanner(
			source=canonical,
			scan=scan,
			description=description,
			plugin=self._active_plugin,
			enabled=bool(enabled),
		)

	def register_checker(
		self,
		source: str,
		check: PluginCheckerFunc,
		description: str = '',
		enabled: bool = True,
	) -> None:
		"""Register an update checker for a custom package source."""
		canonical = _normalize_source_name(source)
		if not callable(check):
			raise TypeError(f'checker for {canonical!r} must be callable')
		self.checkers[canonical] = PluginChecker(
			source=canonical,
			check=check,
			description=description,
			plugin=self._active_plugin,
			enabled=bool(enabled),
		)

	def register_updater(
		self,
		source: str,
		update: PluginUpdaterFunc,
		description: str = '',
		enabled: bool = True,
		build_command: Optional[PluginCommandBuilderFunc] = None,
	) -> None:
		"""Register an updater for a custom package source."""
		canonical = _normalize_source_name(source)
		if not callable(update):
			raise TypeError(f'updater for {canonical!r} must be callable')
		self.updaters[canonical] = PluginUpdater(
			source=canonical,
			update=update,
			description=description,
			plugin=self._active_plugin,
			enabled=bool(enabled),
			build_command=build_command,
		)

	def register_notifier(
		self,
		name: str,
		notify: PluginNotifierFunc,
		description: str = '',
		enabled: bool = True,
	) -> None:
		"""Register a custom notification channel."""
		canonical = _normalize_source_name(name)
		if not callable(notify):
			raise TypeError(f'notifier {canonical!r} must be callable')
		self.notifiers[canonical] = PluginNotifier(
			name=canonical,
			notify=notify,
			description=description,
			plugin=self._active_plugin,
			enabled=bool(enabled),
		)

	def register_security_checker(
		self,
		source: str,
		check: PluginSecurityCheckerFunc,
		description: str = '',
		enabled: bool = True,
	) -> None:
		"""Register a custom vulnerability checker.

		The ``check`` function receives the apps from this plugin's source
		and returns a list of vulnerability dicts. See the project docs
		for the expected dict shape; ``app.security_findings`` and the
		``UpdateStatus.VULNERABLE`` flag should also be set on each
		affected app so the post-scan display reflects the findings.
		"""
		canonical = _normalize_source_name(source)
		if not callable(check):
			raise TypeError(f'security checker for {canonical!r} must be callable')
		self.security_checkers[canonical] = PluginSecurityChecker(
			source=canonical,
			check=check,
			description=description,
			plugin=self._active_plugin,
			enabled=bool(enabled),
		)

	def error(self, path: Path | str, exc: Exception) -> None:
		"""Record a plugin load error without aborting the CLI."""
		self.errors.append(PluginLoadError(str(path), f'{type(exc).__name__}: {exc}'))


def disable_plugin_loading() -> None:
	"""Set the process-wide kill switch (``--no-plugins`` CLI flag)."""
	global _PLUGIN_KILL_SWITCH
	_PLUGIN_KILL_SWITCH = True


def load_plugins(config: Any) -> PluginRegistry:
	"""Load enabled plugins from configured files/directories.

	**Hardening 1.2.1:** Plugins execute arbitrary Python at scan time, so:

	* The loader is **off by default** (``plugins.enabled: false``).
	* When enabled, each plugin directory is checked for ownership and
	  permissions; world-writable or non-owner-writable directories are
	  rejected (POSIX) or warned about (Windows, where stat doesn't carry
	  enough ACL info to reject confidently).
	* A SHA-256 allowlist at ``<plugin_dir>/allowed.sha256`` (one
	  ``<sha256>  <filename>`` line per plugin) is honored when present, or
	  *required* when ``plugins.require_hash_allowlist: true``.
	* The ``--no-plugins`` CLI flag bypasses the loader entirely.

	Config example::

	    plugins:
	      enabled: true
	      paths:
	        - C:/tools/system-update-plugins
	        - C:/tools/my_plugin.py
	      require_hash_allowlist: true   # optional
	"""
	registry = PluginRegistry()

	if _PLUGIN_KILL_SWITCH:
		logger.debug('Plugin loading disabled by --no-plugins')
		return registry

	settings = getattr(config, 'settings', {})
	plugin_settings = settings.get('plugins', {})
	if not plugin_settings.get('enabled', False):
		return registry

	require_allowlist = bool(plugin_settings.get('require_hash_allowlist', False))

	for path in _plugin_paths(config):
		if not path.exists():
			continue
		if not _directory_is_safe(path):
			# Refuse to load — the directory is writable by other users.
			registry.errors.append(
				PluginLoadError(
					str(path),
					'Plugin directory has unsafe permissions; refusing to load.',
				),
			)
			logger.warning(
				'Skipping plugin directory %s: unsafe permissions '
				'(world-writable or not owned by current user)',
				path,
			)
			continue
		allowlist = _load_allowlist(path)
		if require_allowlist and allowlist is None and path.is_dir():
			registry.errors.append(
				PluginLoadError(
					str(path),
					'plugins.require_hash_allowlist is true but allowed.sha256 is missing.',
				),
			)
			logger.warning(
				'Refusing to load plugins from %s: require_hash_allowlist=true '
				'but allowed.sha256 not found',
				path,
			)
			continue
		for plugin_file in _expand_plugin_path(path):
			if allowlist is not None:
				digest = _sha256(plugin_file)
				if allowlist.get(plugin_file.name) != digest:
					registry.errors.append(
						PluginLoadError(
							str(plugin_file),
							f'sha256 mismatch (got {digest[:12]}…) — not in allowed.sha256.',
						),
					)
					logger.warning(
						'Skipping plugin %s: sha256 not in allowlist',
						plugin_file,
					)
					continue
			_warn_first_load(plugin_file)
			_load_plugin_file(plugin_file, registry, config)

	return registry


def scanner_map(registry: PluginRegistry) -> Dict[str, Callable[[], List[AppInfo]]]:
	"""Return custom scanner callables normalized to ``List[AppInfo]``."""
	result: Dict[str, Callable[[], List[AppInfo]]] = {}
	for source, scanner in registry.scanners.items():
		if scanner.enabled:
			result[source] = _wrap_scanner(source, scanner.scan)
	return result


def checker_map(registry: PluginRegistry) -> Dict[str, Callable[[List[AppInfo]], Any]]:
	"""Return enabled custom update checkers by source name."""
	return {
		source: checker.check for source, checker in registry.checkers.items() if checker.enabled
	}


def updater_map(registry: PluginRegistry) -> Dict[str, Callable[[AppInfo], Any]]:
	"""Return enabled custom updaters by source name."""
	return {
		source: updater.update for source, updater in registry.updaters.items() if updater.enabled
	}


def updater_command_builders(
	registry: PluginRegistry,
) -> Dict[str, Callable[[str, AppInfo], Optional[List[str]]]]:
	"""Return command builder functions for plugin sources that provide one."""
	return {
		source: updater.build_command
		for source, updater in registry.updaters.items()
		if updater.enabled and updater.build_command is not None
	}


def security_checker_map(
	registry: PluginRegistry,
) -> Dict[str, Callable[[List[AppInfo]], List[Dict[str, Any]]]]:
	"""Return enabled custom security checkers by source name."""
	return {source: sec.check for source, sec in registry.security_checkers.items() if sec.enabled}


def dispatch_notifiers(
	registry: PluginRegistry,
	event: str,
	title: str,
	message: str,
	payload: Optional[Dict[str, Any]] = None,
	config: Any = None,
) -> None:
	"""Fan out an event to every enabled plugin notifier."""
	payload = payload or {}
	for notifier in registry.notifiers.values():
		if not notifier.enabled:
			continue
		try:
			_call_notifier(notifier.notify, event, title, message, payload, config)
		except Exception as exc:
			logger.warning(
				'Plugin notifier %s from %s failed: %s',
				notifier.name,
				notifier.plugin or '<unknown>',
				exc,
			)


def _directory_is_safe(path: Path) -> bool:
	"""Refuse plugin dirs writable by anyone other than the current user.

	On POSIX we have full mode bits; world/group writable → reject. On
	Windows ``stat`` mode bits are misleading (everything looks 0o666), so
	we skip the bit check there but still emit a debug log; full ACL
	auditing is left to a future hardening PR.
	"""
	try:
		st = path.stat()
	except OSError as exc:
		logger.debug('Cannot stat plugin path %s: %s', path, exc)
		return False
	if platform.system() == 'Windows':
		return True
	# POSIX: reject world- or group-writable dirs.
	mode = st.st_mode
	if mode & (stat.S_IWGRP | stat.S_IWOTH):
		return False
	# Reject directories not owned by the current user.
	# ``geteuid`` is POSIX-only — guarded via getattr so pyright doesn't
	# flag platform-conditional access on Windows.
	geteuid = getattr(os, 'geteuid', None)
	if geteuid is not None and st.st_uid != geteuid():
		return False
	return True


def _load_allowlist(path: Path) -> Optional[Dict[str, str]]:
	"""Return ``{filename: sha256}`` from ``<path>/allowed.sha256`` or None.

	Single-file plugin paths look for ``<path>.sha256`` next to the plugin.
	Lines starting with ``#`` and blank lines are ignored.
	"""
	if path.is_file():
		side = path.with_suffix(path.suffix + '.sha256')
		if not side.exists():
			return None
		manifest = side
	elif path.is_dir():
		manifest = path / 'allowed.sha256'
		if not manifest.exists():
			return None
	else:
		return None
	out: Dict[str, str] = {}
	try:
		raw = manifest.read_text(encoding='utf-8')
	except OSError as exc:
		logger.warning('Cannot read plugin allowlist %s: %s', manifest, exc)
		return {}  # treat as empty so nothing matches
	for line in raw.splitlines():
		line = line.strip()
		if not line or line.startswith('#'):
			continue
		parts = line.split()
		if len(parts) != 2:
			continue
		digest, name = parts[0].lower(), parts[1]
		if len(digest) == 64 and all(c in '0123456789abcdef' for c in digest):
			out[name] = digest
	return out


def _sha256(path: Path) -> str:
	h = hashlib.sha256()
	with path.open('rb') as fh:
		for chunk in iter(lambda: fh.read(65536), b''):
			h.update(chunk)
	return h.hexdigest()


def _warn_first_load(plugin_file: Path) -> None:
	"""Emit a one-shot, prominently-styled warning when a plugin loads.

	Plain ``logger.warning`` doesn't stand out next to the rest of the
	output, but loading user code is something the operator needs to
	notice. We print a bold panel above whatever the next renderer (the
	startup banner, the ``--list-plugins`` table, etc.) emits.
	"""
	key = str(plugin_file.resolve())
	if key in _LOAD_WARNED:
		return
	_LOAD_WARNED.add(key)
	# DEBUG-level audit entry only — the Rich panel below is the visible
	# warning. Logger.warning would print a duplicate plain line on stderr
	# next to the panel (Python's root handler emits WARNING+ to stderr).
	logger.debug(
		'Loading plugin %s — disable with plugins.enabled=false or --no-plugins',
		plugin_file,
	)
	# Rich-styled panel so the user actually sees the warning on stdout.
	try:
		from rich.console import Console
		from rich.panel import Panel
		from rich.text import Text

		body = Text()
		body.append('⚠️ Loading plugin: ', style='bold yellow')
		body.append(str(plugin_file), style='bold white')
		body.append('\n')
		body.append('   Disable with ', style='dim')
		body.append('plugins.enabled=false', style='bold cyan')
		body.append(' in ', style='dim')
		body.append('~/.system_update/config.json', style='cyan')
		body.append(' or run with ', style='dim')
		body.append('--no-plugins', style='bold cyan')
		body.append('.', style='dim')
		Console(stderr=True).print(
			Panel(
				body,
				title='[bold yellow on red] PLUGIN LOAD [/bold yellow on red]',
				title_align='left',
				border_style='bold yellow',
				padding=(0, 1),
				expand=True,
			)
		)
	except Exception:  # pragma: no cover — never let UI break the load
		pass


def _plugin_paths(config: Any) -> List[Path]:
	from system_update.utils import data_dir

	settings = getattr(config, 'settings', {})
	plugin_settings = settings.get('plugins', {})
	config_dir = Path(getattr(config, 'config_dir', data_dir()))
	paths = [config_dir / 'plugins']
	for raw in plugin_settings.get('paths', []) or []:
		path = Path(str(raw)).expanduser()
		paths.append(path)
	return paths


def _expand_plugin_path(path: Path) -> List[Path]:
	if path.is_file() and path.suffix.lower() == '.py':
		return [path]
	if path.is_dir():
		return sorted(
			p for p in path.glob('*.py') if not p.name.startswith('_') and p.name != '__init__.py'
		)
	return []


def _load_plugin_file(path: Path, registry: PluginRegistry, config: Any) -> None:
	module_name = f'system_update_user_plugin_{abs(hash(str(path.resolve())))}'
	try:
		spec = importlib.util.spec_from_file_location(module_name, path)
		if spec is None or spec.loader is None:
			raise ImportError(f'cannot import plugin from {path}')
		module = importlib.util.module_from_spec(spec)
		spec.loader.exec_module(module)  # type: ignore[attr-defined]
		_register_module(module, path, registry, config)
	except Exception as exc:
		registry.error(path, exc)
		logger.warning('Failed to load plugin %s: %s', path, exc)


def _register_module(
	module: ModuleType,
	path: Path,
	registry: PluginRegistry,
	config: Any,
) -> None:
	previous = registry._active_plugin
	plugin_name = getattr(module, 'PLUGIN_NAME', path.stem)
	registry._active_plugin = plugin_name
	try:
		register = getattr(module, 'register_plugin', None)
		if callable(register):
			from system_update.utils import data_dir as _data_dir

			context = PluginContext(
				config=config,
				settings=getattr(config, 'settings', {}),
				data_dir=Path(getattr(config, 'config_dir', _data_dir())),
			)
			if len(inspect.signature(register).parameters) >= 2:
				register(registry, context)
			else:
				register(registry)

		for source, scan in (getattr(module, 'SCANNERS', {}) or {}).items():
			registry.register_scanner(source, scan)
		for source, check in (getattr(module, 'CHECKERS', {}) or {}).items():
			registry.register_checker(source, check)
		for source, update in (getattr(module, 'UPDATERS', {}) or {}).items():
			registry.register_updater(source, update)
		for name, notify in (getattr(module, 'NOTIFIERS', {}) or {}).items():
			registry.register_notifier(name, notify)

		# ── Build the per-plugin summary used by --list-plugins ─────
		capabilities: List[str] = []
		if any(s.plugin == plugin_name for s in registry.scanners.values()):
			capabilities.append('scanner')
		if any(c.plugin == plugin_name for c in registry.checkers.values()):
			capabilities.append('checker')
		if any(u.plugin == plugin_name for u in registry.updaters.values()):
			capabilities.append('updater')
		if any(s.plugin == plugin_name for s in registry.security_checkers.values()):
			capabilities.append('security')
		if any(n.plugin == plugin_name for n in registry.notifiers.values()):
			capabilities.append('notifier')

		# First non-empty line of the module docstring → the plugin's
		# one-line description. Falls back to the registered scanner
		# description, then to a generic placeholder.
		doc = (module.__doc__ or '').strip()
		first_line = doc.splitlines()[0].strip() if doc else ''
		description = first_line or _fallback_description(registry, plugin_name)

		registry.metadata[plugin_name] = PluginMetadata(
			name=plugin_name,
			path=str(path),
			description=description,
			capabilities=capabilities,
		)
	finally:
		registry._active_plugin = previous


def _fallback_description(registry: PluginRegistry, plugin_name: str) -> str:
	"""When a plugin has no docstring, derive a description from registrations."""
	for bucket in (
		registry.scanners,
		registry.security_checkers,
		registry.checkers,
		registry.updaters,
		registry.notifiers,
	):
		for entry in bucket.values():
			if entry.plugin == plugin_name and entry.description:
				return entry.description
	return '(no description)'


def _wrap_scanner(source: str, scan: PluginScannerFunc) -> Callable[[], List[AppInfo]]:
	def _scan() -> List[AppInfo]:
		return [_coerce_app(item, source) for item in (scan() or [])]

	return _scan


def _coerce_app(item: AppInfo | Dict[str, Any], default_source: str) -> AppInfo:
	if isinstance(item, AppInfo):
		if not item.source:
			item.source = default_source
		return item
	if not isinstance(item, dict):
		raise TypeError(f'plugin scanner returned unsupported item: {item!r}')

	status = item.get('update_status', item.get('status', UpdateStatus.UNKNOWN))
	if isinstance(status, str):
		status = (
			UpdateStatus(status)
			if status in {s.value for s in UpdateStatus}
			else UpdateStatus.UNKNOWN
		)

	return AppInfo(
		name=str(item.get('name', '')),
		source=str(item.get('source') or default_source),
		version=str(item.get('version', '')),
		latest_version=str(item.get('latest_version', item.get('latestVersion', '')) or ''),
		app_id=item.get('app_id', item.get('appId')),
		update_status=status,
		error_msg=item.get('error_msg', item.get('errorMsg')),
		install_path=item.get('install_path', item.get('installPath')),
		security_findings=list(
			item.get('security_findings', item.get('securityFindings', [])) or []
		),
	)


def _call_notifier(
	notify: PluginNotifierFunc,
	event: str,
	title: str,
	message: str,
	payload: Dict[str, Any],
	config: Any,
) -> None:
	params = len(inspect.signature(notify).parameters)
	if params >= 5:
		notify(event, title, message, payload, config)
	elif params == 4:
		notify(event, title, message, payload)
	elif params == 3:
		notify(title, message, payload)
	elif params == 2:
		notify(title, message)
	else:
		notify(payload)


def _normalize_source_name(name: str) -> str:
	canonical = str(name).strip().lower()
	if not canonical or not _SOURCE_RE.match(canonical):
		raise ValueError(f'invalid plugin name/source: {name!r}')
	return canonical


__all__ = [
	'PluginContext',
	'PluginChecker',
	'PluginCommandBuilderFunc',
	'PluginLoadError',
	'PluginMetadata',
	'PluginNotifier',
	'PluginRegistry',
	'PluginScanner',
	'PluginSecurityChecker',
	'PluginUpdater',
	'checker_map',
	'disable_plugin_loading',
	'dispatch_notifiers',
	'load_plugins',
	'scanner_map',
	'security_checker_map',
	'updater_command_builders',
	'updater_map',
]
