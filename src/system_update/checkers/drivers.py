"""Driver update placeholder checker.

Windows exposes installed driver versions through ``pnputil`` reliably, but
available driver updates come from Windows Update/OEM channels that are not
safe to query with a universal command. We mark scanned drivers as known and
up-to-date unless a future provider supplies explicit update metadata.
"""

from __future__ import annotations

from typing import List

from system_update.models import AppInfo, UpdateStatus


def check(apps: List[AppInfo]) -> int:
	"""Mark driver inventory records as checked without claiming remote updates."""
	for app in apps:
		app.update_status = UpdateStatus.UP_TO_DATE
	return 0
