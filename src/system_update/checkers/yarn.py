"""Check Yarn-installed global package updates via the NPM registry."""

from __future__ import annotations

from typing import List

from system_update.checkers._npm_registry import check_via_npm_info
from system_update.models import AppInfo


def check(apps: List[AppInfo]) -> int:
	"""Delegate to the shared ``npm info`` registry lookup."""
	return check_via_npm_info(apps)
