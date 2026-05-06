"""Version normalization helpers for scanner output."""

from __future__ import annotations

import re
from typing import Any

_VERSION_RE = re.compile(r'\b\d+(?:\.\d+)+(?:[-+][0-9A-Za-z.-]+)?\b')


def clean_version(value: Any, default: str = 'unknown') -> str:
	"""Return a compact version string from noisy command/PowerShell values."""
	if value in (None, ''):
		return default
	if isinstance(value, dict):
		major = value.get('Major')
		minor = value.get('Minor')
		build = value.get('Build')
		revision = value.get('Revision')
		parts = [major, minor, build, revision]
		if major is not None and minor is not None:
			while parts and parts[-1] in (None, -1):
				parts.pop()
			return '.'.join(str(part) for part in parts if part is not None)

	text = str(value).strip()
	match = _VERSION_RE.search(text)
	return match.group(0) if match else text or default
