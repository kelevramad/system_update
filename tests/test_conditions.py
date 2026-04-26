"""Tests for conditional actions (6.1.3)."""

from __future__ import annotations

from unittest.mock import MagicMock

from system_update import conditions
from system_update.models import AppInfo, UpdateStatus


def _app(name='pkg', source='pip', version='1.0', latest='', vulns=None,
         status=UpdateStatus.UP_TO_DATE):
	return AppInfo(
		name=name, source=source, version=version,
		latest_version=latest, update_status=status,
		security_findings=list(vulns or []),
	)


# ─── Predicates ────────────────────────────────────────────────────────────


def test_any_updates_matches_when_present():
	apps = [_app(latest='2.0', status=UpdateStatus.UPDATE_AVAILABLE)]
	rules = conditions.evaluate(
		apps, {'conditional_actions': [{'when': 'any_updates', 'do': 'log'}]}
	)
	assert len(rules) == 1


def test_any_updates_no_match():
	apps = [_app()]
	rules = conditions.evaluate(
		apps, {'conditional_actions': [{'when': 'any_updates', 'do': 'log'}]}
	)
	assert rules == []


def test_any_vulnerabilities_matches():
	apps = [_app(vulns=[{'cve': 'CVE-1', 'severity': 'HIGH'}])]
	rules = conditions.evaluate(
		apps, {'conditional_actions': [{'when': 'any_vulnerabilities', 'do': 'log'}]}
	)
	assert len(rules) == 1


def test_any_critical_cves_matches_critical_only():
	apps = [_app(vulns=[{'cve': 'CVE-1', 'severity': 'HIGH'}])]
	rules = conditions.evaluate(
		apps, {'conditional_actions': [{'when': 'any_critical_cves', 'do': 'log'}]}
	)
	assert rules == []
	apps2 = [_app(vulns=[{'cve': 'CVE-2', 'severity': 'CRITICAL'}])]
	rules2 = conditions.evaluate(
		apps2, {'conditional_actions': [{'when': 'any_critical_cves', 'do': 'log'}]}
	)
	assert len(rules2) == 1


def test_security_updates_only_when_all_vuln():
	apps = [
		_app(vulns=[{'cve': 'CVE-1'}], status=UpdateStatus.VULNERABLE, latest='2.0'),
		_app(name='b', vulns=[{'cve': 'CVE-2'}], status=UpdateStatus.VULNERABLE, latest='2.0'),
	]
	rules = conditions.evaluate(
		apps, {'conditional_actions': [{'when': 'security_updates_only', 'do': 'log'}]}
	)
	assert len(rules) == 1


def test_security_updates_only_false_when_mixed():
	apps = [
		_app(vulns=[{'cve': 'CVE-1'}], status=UpdateStatus.VULNERABLE, latest='2.0'),
		_app(name='b', latest='2.0', status=UpdateStatus.UPDATE_AVAILABLE),
	]
	rules = conditions.evaluate(
		apps, {'conditional_actions': [{'when': 'security_updates_only', 'do': 'log'}]}
	)
	assert rules == []


def test_security_updates_only_false_when_no_updates():
	apps = [_app()]
	rules = conditions.evaluate(
		apps, {'conditional_actions': [{'when': 'security_updates_only', 'do': 'log'}]}
	)
	assert rules == []


def test_n_updates_gte_threshold():
	apps = [_app(latest='2.0', status=UpdateStatus.UPDATE_AVAILABLE) for _ in range(5)]
	cfg = {'conditional_actions': [
		{'when': 'n_updates_gte:3', 'do': 'log'},
		{'when': 'n_updates_gte:10', 'do': 'log'},
	]}
	rules = conditions.evaluate(apps, cfg)
	assert len(rules) == 1
	assert rules[0].when == 'n_updates_gte:3'


def test_n_vulns_gte_threshold():
	apps = [_app(vulns=[{'cve': f'CVE-{i}'}]) for i in range(3)]
	cfg = {'conditional_actions': [{'when': 'n_vulns_gte:2', 'do': 'log'}]}
	rules = conditions.evaluate(apps, cfg)
	assert len(rules) == 1


def test_unknown_predicate_logs_and_skips():
	apps = [_app()]
	cfg = {'conditional_actions': [{'when': 'made_up_rule', 'do': 'log'}]}
	rules = conditions.evaluate(apps, cfg)
	assert rules == []


def test_evaluate_skips_malformed_rules():
	apps = [_app()]
	cfg = {'conditional_actions': [
		'not-a-dict',
		{'when': '', 'do': 'log'},
		{'when': 'any_updates', 'do': ''},
		{'when': 'any_updates', 'do': 'log'},  # only this one valid
	]}
	apps[0].latest_version = '2.0'
	apps[0].update_status = UpdateStatus.UPDATE_AVAILABLE
	rules = conditions.evaluate(apps, cfg)
	assert len(rules) == 1


# ─── apply() — actions ─────────────────────────────────────────────────────


def test_apply_log_action_returns_ok():
	rule = conditions.ConditionalAction(when='any_updates', do='log')
	results = conditions.apply([rule], [_app()])
	assert results[0]['ok'] is True


def test_apply_notify_calls_notifier():
	notifier = MagicMock()
	rule = conditions.ConditionalAction(when='any_updates', do='notify')
	apps = [_app(latest='2.0', status=UpdateStatus.UPDATE_AVAILABLE)]
	conditions.apply([rule], apps, notifier=notifier)
	notifier.notify_updates_available.assert_called_once()


def test_apply_auto_update_calls_executor():
	executor = MagicMock()
	rule = conditions.ConditionalAction(when='any_updates', do='auto_update')
	apps = [
		_app(latest='2.0', status=UpdateStatus.UPDATE_AVAILABLE),
		_app(name='b', vulns=[{'cve': 'CVE-1'}],
		     status=UpdateStatus.VULNERABLE, latest='3.0'),
		_app(name='c'),  # no update — must not be passed
	]
	conditions.apply([rule], apps, executor=executor)
	executor.execute_updates.assert_called_once()
	called_args = executor.execute_updates.call_args[0][0]
	assert len(called_args) == 2
	assert {a.name for a in called_args} == {'pkg', 'b'}


def test_apply_auto_update_passes_dry_run():
	executor = MagicMock()
	rule = conditions.ConditionalAction(when='any_updates', do='auto_update')
	apps = [_app(latest='2.0', status=UpdateStatus.UPDATE_AVAILABLE)]
	conditions.apply([rule], apps, executor=executor, dry_run=True)
	assert executor.execute_updates.call_args.kwargs.get('dry_run') is True


def test_apply_unknown_action_marked_unsupported():
	rule = conditions.ConditionalAction(when='any_updates', do='magic_dance')
	results = conditions.apply([rule], [_app()])
	assert results[0]['ok'] is False
	assert 'unsupported' in results[0].get('error', '')


def test_apply_handles_action_exceptions():
	notifier = MagicMock()
	notifier.notify_updates_available.side_effect = RuntimeError('SMTP down')
	rule = conditions.ConditionalAction(when='any_updates', do='notify')
	results = conditions.apply([rule], [_app()], notifier=notifier)
	assert results[0]['ok'] is False
	assert 'SMTP down' in results[0]['error']
