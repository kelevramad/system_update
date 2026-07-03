"""demo-plugin — minimal reference plugin for system-update.

Implements the five extension points (scanner / checker / updater /
security / notifier) using the public plugin API from
``system_update.plugins``.

This file doubles as a template — copy it to
``~/.system_update/plugins/`` (or any directory listed under
``plugins.paths`` in your ``config.json``), rename ``SOURCE = 'demo'``
to your own source token, and replace the bodies. The shape (type
hints, source filtering, error handling) is what the docs recommend
for any plugin.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Iterable, List, Optional

from system_update.models import AppInfo, UpdateStatus
from system_update.plugins import PluginContext, PluginRegistry

PLUGIN_NAME = 'demo-plugin'
SOURCE = 'demo'

logger = logging.getLogger(f'system_update.plugin.{SOURCE}')


# A tiny in-memory advisory database. A real plugin would query an
# upstream API or read its own DB file; this just demonstrates the
# extension point's contract.
_DEMO_ADVISORIES = {
	'demo-package': [
		{
			'cve': 'DEMO-2026-0001',
			'severity': 'HIGH',
			'cvss_score': 8.1,
			'affected_versions': ['<1.1.0'],
			'fixed_in': '1.1.0',
			'description': 'Synthetic vulnerability in demo-package for plugin demo.',
			'advisory_url': 'https://example.com/advisories/DEMO-2026-0001',
		},
	],
}


# ─── Scanner ─────────────────────────────────────────────────────────────


def scan_demo() -> Iterable[AppInfo]:
	"""Return the inventory this plugin manages.

	Yielding ``AppInfo`` directly is preferred over dicts: it's typed,
	the field names are checked at construction, and the loader doesn't
	need to coerce.
	"""
	return [
		AppInfo(
			name='demo-package',
			source=SOURCE,
			version='1.0.0',
			update_status=UpdateStatus.UNKNOWN,
		),
	]


# ─── Checker ─────────────────────────────────────────────────────────────


def check_demo(apps: List[AppInfo]) -> int:
	"""Set ``latest_version`` and ``update_status`` for our packages only.

	Filtering by ``app.source`` is important — the checker is invoked
	with all packages of the matching source, but defensive plugins
	never mutate apps they don't own.
	"""
	count = 0
	for app in apps:
		if app.source != SOURCE:
			continue
		app.latest_version = '1.1.0'
		app.update_status = UpdateStatus.UPDATE_AVAILABLE
		count += 1
	return count


# ─── Updater ─────────────────────────────────────────────────────────────


def update_demo(app: AppInfo) -> bool:
	"""Pretend to install ``app.latest_version``.

	On success: reflect the new version, clear ``latest_version`` and
	mark ``UP_TO_DATE`` so the post-update UI is accurate.
	"""
	if app.source != SOURCE:
		return False
	app.version = app.latest_version or app.version
	app.latest_version = ''
	app.update_status = UpdateStatus.UP_TO_DATE
	return True


def build_demo_command(action: str, app: AppInfo) -> Optional[List[str]]:
	"""Return the argv for updating or rolling back ``app`` via the demo source.

	For ``'upgrade'`` the command installs ``app.latest_version`` (the
	newer release).  For ``'rollback'`` the caller sets
	``app.latest_version`` to the *old* version it wants to restore.
	"""
	if app.source != SOURCE:
		return None
	version = app.latest_version
	if not version:
		return None
	return ['demo', 'install', app.name, '--version', version]


# ─── Security checker ───────────────────────────────────────────────────


def security_check_demo(apps: List[AppInfo]) -> List[dict]:
	"""Return vulnerability findings for the demo source.

	Contract:
	* Receives only the apps whose ``source`` matches this plugin.
	* Returns a list of vulnerability dicts (same shape produced by the
	  built-in checkers — see ``system_update/security/local.py``).
	* Mutates each affected app: appends the finding to
	  ``app.security_findings`` and sets
	  ``app.update_status = UpdateStatus.VULNERABLE`` so the post-scan
	  display reflects the result.
	"""
	findings: List[dict] = []
	for app in apps:
		if app.source != SOURCE:
			continue
		for adv in _DEMO_ADVISORIES.get(app.name, ()):
			finding = {
				'package': app.name,
				'severity': adv['severity'],
				'cvss_score': adv.get('cvss_score'),
				'cve': adv.get('cve', 'N/A'),
				'description': adv.get('description', '')[:200],
				'source': 'demo-plugin',
				'affected_versions': adv.get('affected_versions', []),
				'published_date': adv.get('published_date', ''),
				'advisory_url': adv.get('advisory_url', ''),
				'fix_available': bool(adv.get('fixed_in')),
				'fixed_version': adv.get('fixed_in', ''),
				'installed_version': app.version,
			}
			app.security_findings.append(finding)
			app.update_status = UpdateStatus.VULNERABLE
			findings.append(finding)
	return findings


# ─── Notifier ────────────────────────────────────────────────────────────


_LOG_PATH: Optional[Path] = None  # populated in register_plugin


def notify_demo(
	event: str,
	title: str,
	message: str,
	payload: dict,
	config: Any,
) -> None:
	"""Append one line per dispatched event to ``demo_plugin_events.log``."""
	target = _LOG_PATH or (Path(config.config_dir) / 'demo_plugin_events.log')
	try:
		target.parent.mkdir(parents=True, exist_ok=True)
		with target.open('a', encoding='utf-8') as fh:
			fh.write(f'{event}|{title}|{message!r}|{payload!r}\n')
	except OSError as exc:
		logger.warning('demo notifier write failed: %s', exc)


# ─── Registration ────────────────────────────────────────────────────────


def register_plugin(registry: PluginRegistry, context: PluginContext) -> None:
	global _LOG_PATH
	_LOG_PATH = context.data_dir / 'demo_plugin_events.log'

	registry.register_scanner(SOURCE, scan_demo, description='Demo package source')
	registry.register_checker(SOURCE, check_demo, description='Demo update checker')
	registry.register_updater(
		SOURCE,
		update_demo,
		description='Demo package updater',
		build_command=build_demo_command,
	)
	registry.register_security_checker(
		SOURCE,
		security_check_demo,
		description='Demo vulnerability feed',
	)
	registry.register_notifier(
		'demo-log',
		notify_demo,
		description='Demo notification logger',
	)
