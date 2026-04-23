"""Discover common developer tools on the system PATH."""

from __future__ import annotations

import platform
import re
from typing import List

from system_update.models import AppInfo
from system_update.utils import run_command

_EXECUTABLES = [
	'node',
	'npm',
	'pnpm',
	'yarn',
	'python',
	'git',
	'go',
	'bun',
	'deno',
	'rustc',
	'cargo',
	'dotnet',
	'java',
	'pwsh',
]


def scan() -> List[AppInfo]:
	"""Resolve each known CLI tool via ``where``/``which`` and capture its version."""
	apps: List[AppInfo] = []
	locate_cmd = 'where' if platform.system() == 'Windows' else 'which'

	for exe in _EXECUTABLES:
		path = run_command([locate_cmd, exe], allow_failure=True)
		if not path:
			continue
		version_output = run_command([exe, '--version'], allow_failure=True)
		if not version_output:
			continue
		match = re.search(r'(\d+\.\d+(\.\d+)*([-.].*)?)', version_output)
		if match:
			apps.append(
				AppInfo(
					name=exe,
					source='PATH',
					version=match.group(0),
					install_path=path.split('\n')[0],
				)
			)

	return apps
