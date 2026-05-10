"""Shared helpers for security checkers — severity mapping + OSV ecosystem table."""

from __future__ import annotations

from typing import Dict, Optional


OSV_ECOSYSTEM_MAP = {
	'npm': 'npm',
	'pip': 'PyPI',
	'pypi': 'PyPI',
	'cargo': 'crates.io',
	'rust': 'crates.io',
	'gem': 'RubyGems',
	'ruby': 'RubyGems',
	'go': 'Go',
	'cocoapods': 'CocoaPods',
	'hex': 'Hex',
}


def score_to_severity(cvss_score: Optional[float]) -> str:
	"""Convert a CVSS v3 numeric score to a severity label (CRITICAL/HIGH/MEDIUM/LOW/NONE)."""
	if cvss_score is None:
		return 'MEDIUM'
	if cvss_score >= 9.0:
		return 'CRITICAL'
	if cvss_score >= 7.0:
		return 'HIGH'
	if cvss_score >= 4.0:
		return 'MEDIUM'
	if cvss_score > 0:
		return 'LOW'
	return 'NONE'


def security_issue(source: str, status: str, message: str) -> Dict:
	"""Return a structured non-vulnerability security scan issue marker."""
	return {
		'type': 'security_issue',
		'source': source,
		'status': status,
		'message': message,
		'error': message,
	}


def is_security_issue(item: Dict) -> bool:
	"""Return True when ``item`` is a scanner failure/skip marker, not a CVE."""
	return item.get('type') == 'security_issue'
