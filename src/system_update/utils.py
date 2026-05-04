"""Shared utilities — subprocess wrapper, theme tables, display helpers.

This module has no upward dependencies within the package so it can be
imported from anywhere. The only internal dependency is :mod:`.models` for
:class:`CommandError`.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import shutil
import subprocess
from typing import Dict, List, Optional

from rich import box
from rich.console import Console

from system_update.models import CommandError

console = Console()

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# SUBPROCESS WRAPPER
# ═══════════════════════════════════════════════════════════════════════════════


def _log_excerpt(text: str, limit: int = 8000) -> str:
	"""Return enough command output for failure diagnostics without huge logs."""
	if len(text) <= limit:
		return text
	return f'{text[:limit]}...[truncated {len(text) - limit} chars]'


def run_command(
	cmd: List[str],
	timeout: int = 45,
	allow_failure: bool = False,
	include_stderr: bool = False,
	scrub_venv: bool = False,
	env_overrides: Optional[Dict[str, str]] = None,
) -> Optional[str]:
	"""Execute a command with UTF-8 encoding, timeout, and structured errors.

	On Windows the executable is resolved via ``shutil.which`` before invocation
	for reliable PATH lookup. All failure modes log at DEBUG and return ``None``.

	Args:
		cmd: Argument vector (e.g. ``['winget', 'list']``).
		timeout: Maximum runtime in seconds. Defaults to 45.
		allow_failure: If True, return whatever was captured on stdout even when
			the process exits non-zero. If False, return None on non-zero exit.
		include_stderr: If True, concatenate stdout + stderr in the return value.
		scrub_venv: If True, drop ``VIRTUAL_ENV``, ``CONDA_PREFIX``,
			``PYTHONHOME``, and ``PIP_*`` env vars from the child process. Use
			when invoking a Python interpreter that should NOT see the parent's
			active venv (e.g. a global Python pip listing under ``uv run``).
		env_overrides: Extra environment variables to set for the child process.

	Returns:
		Stripped stdout (or combined stdout+stderr) on success, else ``None``.
	"""
	cmd_str = ' '.join(cmd)
	logger.debug(f'[EXEC] Starting: {cmd_str}')

	try:
		if platform.system() == 'Windows':
			executable = shutil.which(cmd[0])
			if executable:
				logger.debug(f'[EXEC] Resolved {cmd[0]} to: {executable}')
				cmd[0] = executable
			else:
				logger.debug(f'[EXEC] Command not found in PATH: {cmd[0]}')

		env = None
		if scrub_venv or env_overrides:
			env = os.environ.copy()
		if scrub_venv and env is not None:
			# uv / poetry / activate-scripts set VIRTUAL_ENV; pip respects it
			# for some operations and can shadow the interpreter we explicitly
			# invoke. Strip these so the child's own sys.prefix wins.
			for k in ('VIRTUAL_ENV', 'CONDA_PREFIX', 'PYTHONHOME'):
				env.pop(k, None)
			# Remove every PIP_* override; the only one most users care about
			# (PIP_INDEX_URL) is preserved on the child if present in user
			# config, not env.
			for k in [k for k in env if k.startswith('PIP_')]:
				env.pop(k, None)
		if env_overrides and env is not None:
			env.update(env_overrides)

		result = subprocess.run(
			cmd,
			capture_output=True,
			text=True,
			check=False,
			encoding='utf-8',
			errors='ignore',
			timeout=timeout,
			env=env,
		)

		logger.debug(f'[EXEC] Exit code: {result.returncode}')

		stdout_len = len(result.stdout) if result.stdout else 0
		stderr_len = len(result.stderr) if result.stderr else 0

		if stdout_len > 0:
			stdout_trunc = (
				result.stdout[:300] + '...[truncated]' if stdout_len > 300 else result.stdout
			)
			logger.debug(f'[EXEC] stdout ({stdout_len} chars): {stdout_trunc}')
		else:
			logger.debug('[EXEC] stdout (empty)')

		if stderr_len > 0:
			stderr_trunc = (
				result.stderr[:300] + '...[truncated]' if stderr_len > 300 else result.stderr
			)
			logger.debug(f'[EXEC] stderr ({stderr_len} chars): {stderr_trunc}')

		if result.returncode != 0 and not allow_failure:
			details = []
			if result.stdout:
				details.append(f'stdout:\n{_log_excerpt(result.stdout.rstrip())}')
			if result.stderr:
				details.append(f'stderr:\n{_log_excerpt(result.stderr.rstrip())}')
			joined_details = '\n'.join(details)
			output = f'\n{joined_details}' if joined_details else ''
			logger.warning(
				f'[EXEC] Command failed (exit {result.returncode}): {cmd_str}{output}'
			)
			return None

		if include_stderr:
			combined = f'{result.stdout}\n{result.stderr}'.strip()
			return combined or None

		logger.debug(f'[EXEC] Success: {cmd_str} ({stdout_len} output chars)')
		return result.stdout.strip() or None

	except subprocess.TimeoutExpired as exc:
		error = CommandError.classify(exc, cmd_str)
		logger.warning(f'[EXEC] Timeout: {cmd_str} - {error.suggestion}')
		logger.debug(f'[EXEC] Timeout details: {exc}')
		return None
	except FileNotFoundError as exc:
		error = CommandError.classify(exc, cmd_str)
		logger.debug(f'[EXEC] Not found: {cmd_str} - {error.suggestion}')
		logger.debug(f'[EXEC] FileNotFoundError: {exc}')
		return None
	except PermissionError as exc:
		error = CommandError.classify(exc, cmd_str)
		logger.warning(f'[EXEC] Permission denied: {cmd_str} - {error.suggestion}')
		logger.debug(f'[EXEC] PermissionError: {exc}')
		return None
	except (json.JSONDecodeError, ValueError) as exc:
		error = CommandError.classify(exc, cmd_str)
		logger.warning(f'[EXEC] Parse error: {cmd_str} - {error.suggestion}')
		logger.debug(f'[EXEC] Parse error details: {exc}')
		return None
	except Exception as exc:  # noqa: BLE001 — intentional catch-all with classification
		error = CommandError.classify(exc, cmd_str)
		logger.warning(
			f'[EXEC] Error: {error.category.value}: {error.message} - {error.suggestion}'
		)
		logger.debug(f'[EXEC] Exception details: {exc}')
		return None


# ═══════════════════════════════════════════════════════════════════════════════
# SOURCE BADGE (Rich markup wrapper)
# ═══════════════════════════════════════════════════════════════════════════════


_SOURCE_BADGE_STYLES = {
	'winget': 'blue',
	'chocolatey': 'yellow',
	'npm': 'red',
	'pnpm': 'color(206)',
	'pip': 'cyan',
	'bun': 'bright_blue',
	'yarn': 'bright_white',
	'rust': 'color(129)',
	'path': 'green',
	'registry': 'grey37',
	'scoop': 'bright_yellow',
	'dotnet': 'gold',
}


def source_badge(source: str) -> str:
	"""Return ``source`` wrapped in Rich style tags for coloured display."""
	source_lower = (source or 'unknown').lower()
	style = _SOURCE_BADGE_STYLES.get(source_lower, 'bright_white')
	return f'[{style}]{source_lower}[/{style}]'


def display_source(source: str) -> str:
	"""Return the canonical user-facing source label."""
	return (source or 'unknown').lower()


# ═══════════════════════════════════════════════════════════════════════════════
# UI THEMES & SOURCE ICONS
# ═══════════════════════════════════════════════════════════════════════════════


THEMES = {
	'default': {
		'name': 'Default',
		'source_colors': {
			'winget': 'blue',
			'chocolatey': 'yellow',
			'npm': 'red',
			'pnpm': 'color(206)',
			'pip': 'magenta',
			'bun': 'bright_blue',
			'yarn': 'bright_white',
			'rust': 'color(129)',
			'path': 'green',
			'registry': 'grey37',
			'scoop': 'yellow',
			'dotnet': 'gold',
		},
		'status_colors': {
			'up_to_date': 'green',
			'update_available': 'bold yellow',
			'error': 'bold red',
			'vulnerable': 'bold red',
			'security_update': 'bold magenta',
			'unknown': 'dim white',
		},
		'header_style': 'bold cyan',
		'border_style': 'dim white',
		'box': box.SIMPLE,
		'show_lines': False,
	},
	'vibrant': {
		'name': 'Vibrant',
		'source_colors': {
			'winget': 'bright_cyan',
			'chocolatey': 'bright_yellow',
			'npm': 'bright_red',
			'pnpm': 'color(219)',
			'pip': 'bright_magenta',
			'bun': 'bright_blue',
			'yarn': 'bright_white',
			'rust': 'color(171)',
			'path': 'bright_green',
			'registry': 'grey37',
			'scoop': 'bright_yellow',
			'dotnet': 'bright_gold',
		},
		'status_colors': {
			'up_to_date': 'bold green',
			'update_available': 'bold yellow',
			'error': 'bold bright_red',
			'vulnerable': 'bold bright_red',
			'security_update': 'bold bright_magenta',
			'unknown': 'dim white',
		},
		'header_style': 'bold bright_cyan',
		'border_style': 'cyan',
		'box': box.ROUNDED,
		'show_lines': True,
	},
	'minimal': {
		'name': 'Minimal',
		'source_colors': {
			'winget': 'dim cyan',
			'chocolatey': 'dim yellow',
			'npm': 'dim red',
			'pnpm': 'dim magenta',
			'pip': 'dim green',
			'bun': 'dim blue',
			'yarn': 'dim white',
			'rust': 'dim color(207)',
			'path': 'dim green',
			'registry': 'dim grey',
			'scoop': 'dim yellow',
			'dotnet': 'dim gold',
		},
		'status_colors': {
			'up_to_date': 'green',
			'update_available': 'yellow',
			'error': 'red',
			'vulnerable': 'red',
			'security_update': 'magenta',
			'unknown': 'dim',
		},
		'header_style': 'bold white',
		'border_style': 'white',
		'box': box.SIMPLE_HEAD,
		'show_lines': False,
	},
	'dark': {
		'name': 'Dark',
		'source_colors': {
			'winget': 'cyan',
			'chocolatey': 'yellow',
			'npm': 'red',
			'pnpm': 'magenta',
			'pip': 'color(201)',
			'bun': 'bright_blue',
			'yarn': 'white',
			'rust': 'color(207)',
			'path': 'green',
			'registry': 'grey',
			'scoop': 'yellow',
			'dotnet': 'gold',
		},
		'status_colors': {
			'up_to_date': 'green',
			'update_available': 'yellow',
			'error': 'red',
			'vulnerable': 'red',
			'security_update': 'color(201)',
			'unknown': 'dim',
		},
		'header_style': 'bold cyan',
		'border_style': 'dim cyan',
		'box': box.HEAVY,
		'show_lines': True,
	},
	'neon': {
		'name': 'Neon',
		'source_colors': {
			'winget': 'color(39)',
			'chocolatey': 'color(226)',
			'npm': 'color(196)',
			'pnpm': 'color(219)',
			'pip': 'color(201)',
			'bun': 'color(75)',
			'yarn': 'color(255)',
			'rust': 'color(171)',
			'path': 'color(82)',
			'registry': 'color(242)',
			'scoop': 'color(226)',
			'dotnet': 'color(220)',
		},
		'status_colors': {
			'up_to_date': 'bold color(82)',
			'update_available': 'bold color(226)',
			'error': 'bold color(196)',
			'vulnerable': 'bold color(196)',
			'security_update': 'bold color(201)',
			'unknown': 'dim white',
		},
		'header_style': 'bold color(75)',
		'border_style': 'color(75)',
		'box': box.DOUBLE,
		'show_lines': True,
	},
}


SOURCE_ICONS = {
	'winget': '📦',
	'chocolatey': '🍫',
	'npm': '📚',
	'pnpm': '📦',
	'pip': '🐍',
	'bun': '🧈',
	'yarn': '🧶',
	'rust': '🦀',
	'path': '📁',
	'registry': '🖥️',
	'scoop': '🥄',
	'dotnet': '🔷',
	'appx': '🪟',
	'msix': '📱',
}
