"""Check Rust crate updates via the crates.io API."""

from __future__ import annotations

from typing import List, Optional

from system_update.models import AppInfo, UpdateStatus
from system_update.network import fetch_json
from system_update.utils import console, run_command  # noqa: F401


def _fetch_crate_latest(name: str) -> Optional[str]:
	"""Return the newest version number for ``name`` from crates.io, or ``None``."""
	url = f'https://crates.io/api/v1/crates/{name}'
	try:
		data = fetch_json(url)
		versions = data.get('versions', []) if isinstance(data, dict) else []
		return versions[0].get('num') if versions else None
	except Exception:
		return None


def check(apps: List[AppInfo]) -> int:
	"""Mark every crate with the newest published version returned by crates.io."""
	updates = 0
	errors = 0
	for app in apps:
		latest = _fetch_crate_latest(app.name)
		if latest:
			app.latest_version = latest
			app.update_status = UpdateStatus.UPDATE_AVAILABLE
			updates += 1
		else:
			errors += 1

	if errors:
		console.print(f'[dim]⚠️ {errors} Rust crate(s) could not be checked via API[/dim]')

	return updates
