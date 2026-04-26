"""Conditional actions — enhancement section 6.1.3.

After a scan finishes the orchestrator can evaluate a list of user-defined
rules and trigger actions like notify / log / auto-update. Rules live under
the ``conditional_actions`` key in ``~/.system_update/config.json`` and are
intended to be paired with a scheduled task (see :mod:`scheduler`):

    {
      "conditional_actions": [
        {"when": "any_critical_cves",      "do": "notify"},
        {"when": "n_updates_gte:20",       "do": "notify"},
        {"when": "security_updates_only",  "do": "auto_update"},
        {"when": "any_vulnerabilities",    "do": "log"}
      ]
    }

Conditions implemented:

* ``any_updates``           — at least one package has an update available
* ``any_vulnerabilities``   — at least one package has security findings
* ``any_critical_cves``     — at least one finding has CRITICAL severity
* ``security_updates_only`` — every available update is a security update
* ``n_updates_gte:N``       — total updates >= N
* ``n_vulns_gte:N``         — total vulnerabilities >= N

Actions implemented:

* ``notify``      — fire :class:`NotificationManager` channels
* ``log``         — emit a WARNING-level log entry
* ``auto_update`` — run ``UpdateExecutor.execute_updates`` on update candidates
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from system_update.models import AppInfo, UpdateStatus

logger = logging.getLogger(__name__)


# ─── Models ────────────────────────────────────────────────────────────────


@dataclass
class ConditionalAction:
	"""One rule loaded from config: a predicate (``when``) + an action (``do``)."""

	when: str
	do: str
	extra: Dict[str, Any] = field(default_factory=dict)

	@classmethod
	def from_dict(cls, raw: Dict) -> 'ConditionalAction':
		return cls(
			when=str(raw.get('when', '')),
			do=str(raw.get('do', '')),
			extra={k: v for k, v in raw.items() if k not in ('when', 'do')},
		)


# ─── Predicates ────────────────────────────────────────────────────────────


def _has_any_update(apps: List[AppInfo]) -> bool:
	return any(a.has_update for a in apps)


def _has_any_vuln(apps: List[AppInfo]) -> bool:
	return any(a.is_vulnerable for a in apps)


def _critical_cves_present(apps: List[AppInfo]) -> bool:
	for a in apps:
		for f in a.security_findings or []:
			sev = str(f.get('severity', '')).upper()
			if sev == 'CRITICAL':
				return True
	return False


def _security_updates_only(apps: List[AppInfo]) -> bool:
	"""True if every package needing an update is also vulnerable.

	Vacuously False when there are no updates at all — an empty result set
	shouldn't trigger an "all updates are security" rule.
	"""
	upd = [a for a in apps if a.has_update or a.is_vulnerable]
	return bool(upd) and all(a.is_vulnerable for a in upd)


def _matches(rule: ConditionalAction, apps: List[AppInfo]) -> bool:
	when = rule.when.strip().lower()
	if when == 'any_updates':
		return _has_any_update(apps)
	if when == 'any_vulnerabilities':
		return _has_any_vuln(apps)
	if when == 'any_critical_cves':
		return _critical_cves_present(apps)
	if when == 'security_updates_only':
		return _security_updates_only(apps)
	if when.startswith('n_updates_gte:'):
		try:
			threshold = int(when.split(':', 1)[1])
		except ValueError:
			return False
		return sum(1 for a in apps if a.has_update) >= threshold
	if when.startswith('n_vulns_gte:'):
		try:
			threshold = int(when.split(':', 1)[1])
		except ValueError:
			return False
		return sum(1 for a in apps if a.is_vulnerable) >= threshold
	logger.warning(f'Unknown condition: {rule.when!r}')
	return False


# ─── Evaluator ─────────────────────────────────────────────────────────────


def evaluate(
	apps: List[AppInfo], settings: Optional[Dict] = None
) -> List[ConditionalAction]:
	"""Return the rules from config that match the current scan results."""
	raw_rules = (settings or {}).get('conditional_actions') or []
	matched: List[ConditionalAction] = []
	for raw in raw_rules:
		if not isinstance(raw, dict):
			continue
		rule = ConditionalAction.from_dict(raw)
		if not rule.when or not rule.do:
			continue
		try:
			if _matches(rule, apps):
				matched.append(rule)
		except Exception as e:
			logger.warning(f'Rule evaluation error for {rule.when!r}: {e}')
	return matched


# ─── Action runner ─────────────────────────────────────────────────────────


def apply(
	actions: List[ConditionalAction],
	apps: List[AppInfo],
	*,
	notifier=None,
	executor=None,
	console=None,
	dry_run: bool = False,
) -> List[Dict]:
	"""Execute each matching action; returns a list of result dicts.

	``notifier`` / ``executor`` / ``console`` are optional collaborators —
	tests inject mocks; the orchestrator passes its real instances.
	"""
	results: List[Dict] = []
	for action in actions:
		do = action.do.strip().lower()
		entry: Dict[str, Any] = {'when': action.when, 'do': action.do, 'ok': False}
		try:
			if do == 'log':
				logger.warning(
					f'[conditional] {action.when} matched — '
					f'updates={sum(1 for a in apps if a.has_update)} '
					f'vulns={sum(1 for a in apps if a.is_vulnerable)}'
				)
				entry['ok'] = True
			elif do == 'notify' and notifier is not None:
				updates = sum(1 for a in apps if a.has_update)
				vulns = sum(1 for a in apps if a.is_vulnerable)
				notifier.notify_updates_available(updates, vulns, force=True)
				entry['ok'] = True
			elif do == 'auto_update' and executor is not None:
				targets = [
					a for a in apps
					if a.update_status in (
						UpdateStatus.UPDATE_AVAILABLE,
						UpdateStatus.VULNERABLE,
					) and a.latest_version
				]
				if targets:
					executor.execute_updates(targets, dry_run=dry_run)
				entry['ok'] = True
				entry['count'] = len(targets)
			else:
				entry['error'] = (
					f'Action {do!r} unsupported or missing collaborator'
				)
		except Exception as e:
			entry['error'] = str(e)
			logger.error(f'Conditional action failed: {e}')
		results.append(entry)
		if console is not None and entry.get('ok'):
			console.print(
				f'[cyan]✓ Conditional rule[/cyan] '
				f'[bold]{action.when}[/bold] → [yellow]{action.do}[/yellow]'
			)
	return results


__all__ = ['ConditionalAction', 'evaluate', 'apply']
