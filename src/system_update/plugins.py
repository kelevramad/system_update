"""Plugin API and loader for custom scanners and notification channels."""

from __future__ import annotations

import importlib.util
import inspect
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Dict, Iterable, List, Optional

from system_update.config import data_dir
from system_update.models import AppInfo, UpdateStatus

logger = logging.getLogger(__name__)

PluginScannerFunc = Callable[[], Iterable[AppInfo | Dict[str, Any]]]
PluginCheckerFunc = Callable[[List[AppInfo]], Any]
PluginUpdaterFunc = Callable[[AppInfo], Any]
PluginNotifierFunc = Callable[..., Any]

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


@dataclass
class PluginUpdater:
	"""Registered custom updater for a plugin source."""

	source: str
	update: PluginUpdaterFunc
	description: str = ''
	plugin: str = ''
	enabled: bool = True


@dataclass
class PluginNotifier:
	"""Registered custom notification channel."""

	name: str
	notify: PluginNotifierFunc
	description: str = ''
	plugin: str = ''
	enabled: bool = True


@dataclass
class PluginLoadError:
	"""Non-fatal plugin loading error."""

	path: str
	error: str


@dataclass
class PluginRegistry:
	"""Registry exposed to extension modules from ``register_plugin``."""

	scanners: Dict[str, PluginScanner] = field(default_factory=dict)
	checkers: Dict[str, PluginChecker] = field(default_factory=dict)
	updaters: Dict[str, PluginUpdater] = field(default_factory=dict)
	notifiers: Dict[str, PluginNotifier] = field(default_factory=dict)
	errors: List[PluginLoadError] = field(default_factory=list)
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

	def error(self, path: Path | str, exc: Exception) -> None:
		"""Record a plugin load error without aborting the CLI."""
		self.errors.append(PluginLoadError(str(path), f'{type(exc).__name__}: {exc}'))


def load_plugins(config: Any) -> PluginRegistry:
	"""Load enabled plugins from configured files/directories.

	Default path is ``~/.system_update/plugins``. Config can add more paths:

	```
	plugins:
	  enabled: true
	  paths:
	    - C:/tools/system-update-plugins
	    - C:/tools/my_plugin.py
	```
	"""
	registry = PluginRegistry()
	settings = getattr(config, 'settings', {})
	plugin_settings = settings.get('plugins', {})
	if not plugin_settings.get('enabled', True):
		return registry

	for path in _plugin_paths(config):
		for plugin_file in _expand_plugin_path(path):
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
		source: checker.check
		for source, checker in registry.checkers.items()
		if checker.enabled
	}


def updater_map(registry: PluginRegistry) -> Dict[str, Callable[[AppInfo], Any]]:
	"""Return enabled custom updaters by source name."""
	return {
		source: updater.update
		for source, updater in registry.updaters.items()
		if updater.enabled
	}


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


def _plugin_paths(config: Any) -> List[Path]:
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
		spec.loader.exec_module(module)
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
	registry._active_plugin = getattr(module, 'PLUGIN_NAME', path.stem)
	try:
		register = getattr(module, 'register_plugin', None)
		if callable(register):
			context = PluginContext(
				config=config,
				settings=getattr(config, 'settings', {}),
				data_dir=Path(getattr(config, 'config_dir', data_dir())),
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
	finally:
		registry._active_plugin = previous


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
	'PluginLoadError',
	'PluginNotifier',
	'PluginRegistry',
	'PluginScanner',
	'PluginUpdater',
	'checker_map',
	'dispatch_notifiers',
	'load_plugins',
	'scanner_map',
	'updater_map',
]
