"""Windows service version checker."""

from __future__ import annotations

from typing import List

from system_update.models import AppInfo, UpdateStatus


def check(apps: List[AppInfo]) -> int:
	"""Mark service executable inventory records as checked.

	Services are not a package source by themselves; the scanner captures their
	executable versions so admins can spot stale service binaries in exports and
	history. Actual updates are handled by the package source that installed the
	service.
	"""
	for app in apps:
		app.update_status = UpdateStatus.UP_TO_DATE
	return 0
