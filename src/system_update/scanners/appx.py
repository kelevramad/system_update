"""Scan Store-signed AppX packages (Microsoft Store apps)."""

from __future__ import annotations

from typing import List

from system_update.models import AppInfo
from system_update.scanners._appx_common import scan_appx_variant


def scan() -> List[AppInfo]:
	"""Return Store-signed AppX packages; empty list on non-Windows."""
	return scan_appx_variant("-eq 'Store'", 'appx')
