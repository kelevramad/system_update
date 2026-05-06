"""Check PATH-installed CLI tool updates via vendor-specific lookups.

Each tool has its own upstream of truth (GitHub releases/tags, npm registry,
``winget show``, or native ``upgrade --dry-run`` output) so this checker is a
dispatch-by-name switch. All network calls go through :func:`_fetch_json`.
"""

from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional, Tuple

from system_update.models import AppInfo, UpdateStatus
from system_update.network import fetch_json
from system_update.utils import run_command


def _fetch_json(url: str):
	"""GET ``url`` with a User-Agent header and return decoded JSON (``None`` on failure)."""
	try:
		return fetch_json(url)
	except Exception:
		return None


def _parse_version(ver_str: str) -> Tuple[int, int, int, bool]:
	"""Return ``(major, minor, patch, is_stable)`` with pre-release detection."""
	ver_str = re.sub(r'^[^\d]+', '', ver_str).strip()
	match = re.match(r'(\d+)\.(\d+)\.(\d+)', ver_str)
	if not match:
		match = re.match(r'(\d+)\.(\d+)', ver_str)
		if match:
			return (int(match.group(1)), int(match.group(2)), 0, 'preview' not in ver_str.lower())
		return (0, 0, 0, False)
	is_stable = not any(x in ver_str.lower() for x in ['preview', 'rc', 'beta', 'alpha', '-pre'])
	return (int(match.group(1)), int(match.group(2)), int(match.group(3)), is_stable)


def _is_newer_version(current: str, latest: str) -> bool:
	"""True when ``latest`` semantically supersedes ``current``.

	Pre-release handling: a newer preview is not downgraded to an older stable
	sharing the same base triplet, and the routine refuses to "upgrade" from a
	newer major/minor preview down to an older stable.
	"""
	curr = _parse_version(current)
	latest_p = _parse_version(latest)

	if curr[0] > latest_p[0]:
		return False
	if curr[0] == latest_p[0] and curr[1] > latest_p[1]:
		return False

	if curr[3] and latest_p[3]:
		return latest_p[:3] > curr[:3]
	if not curr[3] and curr[:3] == latest_p[:3]:
		return False
	return latest_p[:3] > curr[:3]


# ── per-tool resolvers ────────────────────────────────────────────────────────


def _latest_bun(app: AppInfo) -> str:
	output = run_command(
		['bun', 'upgrade', '--dry-run'], allow_failure=True, include_stderr=True
	)
	if output:
		match = re.search(r'Bun v([0-9.]+)\s+is out!', output)
		if match:
			return match.group(1)
		return app.version
	return ''


def _latest_deno(app: AppInfo) -> str:
	output = run_command(
		['deno', 'upgrade', '--dry-run'], allow_failure=True, include_stderr=True
	)
	if output:
		match = re.search(
			r'Found latest stable version\s+v?([0-9.]+)', output, re.IGNORECASE
		)
		return match.group(1) if match else app.version
	return ''


def _latest_via_npm_view(app: AppInfo) -> str:
	output = run_command(['npm', 'view', app.name, 'version'], allow_failure=True)
	if output and 'ERR' not in output:
		return output.strip()
	return app.version


def _latest_python(app: AppInfo) -> str:
	data = _fetch_json('https://api.github.com/repos/python/cpython/tags?per_page=1')
	if isinstance(data, list) and data and data[0].get('name'):
		match = re.search(r'v?([0-9.]+)', data[0]['name'])
		if match:
			return match.group(1)
	return app.version


def _latest_git(app: AppInfo) -> str:
	data = _fetch_json('https://api.github.com/repos/git-for-windows/git/releases/latest')
	if isinstance(data, dict) and data.get('tag_name'):
		match = re.search(r'v?([0-9.]+?)(?:\.windows)', data['tag_name'])
		return match.group(1) if match else data['tag_name'].replace('v', '')
	return app.version


def _latest_pwsh(app: AppInfo) -> str:
	data = _fetch_json('https://api.github.com/repos/PowerShell/PowerShell/releases/latest')
	if isinstance(data, dict) and data.get('tag_name'):
		return data['tag_name'].replace('v', '')
	return app.version


def _latest_dotnet(app: AppInfo) -> str:
	output = run_command(
		['winget', 'show', 'Microsoft.DotNet.SDK.9', '--accept-source-agreements'],
		allow_failure=True,
	)
	if output:
		match = re.search(r'Version:\s+([0-9.]+)', output)
		if match:
			return match.group(1)
	return app.version


def _latest_rust(app: AppInfo) -> str:
	data = _fetch_json('https://api.github.com/repos/rust-lang/rust/releases/latest')
	if isinstance(data, dict) and data.get('tag_name'):
		match = re.search(r'([0-9.]+)', data['tag_name'])
		if match:
			return match.group(1)
	return app.version


_RESOLVERS: Dict[str, Callable[[AppInfo], str]] = {
	'bun': _latest_bun,
	'deno': _latest_deno,
	'yarn': _latest_via_npm_view,
	'npm': _latest_via_npm_view,
	'pnpm': _latest_via_npm_view,
	'node': _latest_via_npm_view,
	'python': _latest_python,
	'git': _latest_git,
	'pwsh': _latest_pwsh,
	'dotnet': _latest_dotnet,
	'rustc': _latest_rust,
	'cargo': _latest_rust,
}


def _resolve_latest(app: AppInfo) -> Optional[str]:
	resolver = _RESOLVERS.get(app.name)
	if resolver is None:
		return None
	try:
		return resolver(app)
	except Exception:
		return None


def check(apps: List[AppInfo]) -> int:
	"""Resolve each PATH tool's upstream latest and mark status accordingly."""
	updates = 0
	for app in apps:
		latest = _resolve_latest(app)
		if not latest:
			app.latest_version = '-'
			app.update_status = UpdateStatus.UP_TO_DATE
			continue

		app.latest_version = re.sub(r'^[^\d]+', '', latest).strip()
		if _is_newer_version(app.version, latest):
			app.update_status = UpdateStatus.UPDATE_AVAILABLE
			updates += 1
		else:
			app.update_status = UpdateStatus.UP_TO_DATE

	return updates
