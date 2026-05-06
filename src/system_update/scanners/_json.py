"""Helpers for scanner command output that should contain JSON."""

from __future__ import annotations

import json
from typing import Any, Dict, List


def parse_json_items(output: str | None) -> List[Dict[str, Any]]:
	"""Return object rows from noisy JSON command output.

	PowerShell commands can emit warnings before ``ConvertTo-Json`` output, and
	``ConvertTo-Json`` may return either one object, an array, or ``null``.
	"""
	if not output:
		return []

	text = output.strip()
	candidates = [text]
	for start, end_char in ((idx, end) for idx, char in enumerate(text) for end in '}]' if char in '[{'):
		end = text.rfind(end_char)
		if end > start:
			candidates.append(text[start : end + 1])

	for candidate in candidates:
		try:
			data = json.loads(candidate)
		except (TypeError, json.JSONDecodeError):
			continue
		if isinstance(data, dict):
			return [data]
		if isinstance(data, list):
			return [item for item in data if isinstance(item, dict)]
		return []

	return []
