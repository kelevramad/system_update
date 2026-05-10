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
import tempfile
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Union

from rich import box
from rich.console import Console

from system_update.models import AppInfo, CommandError

console = Console()

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# DATA DIR + SECURE WRITES (Hardening 1.4)
# ═══════════════════════════════════════════════════════════════════════════════


_HOME_ENV = 'SYSTEM_UPDATE_HOME'


def data_dir() -> Path:
	"""Return the data directory, creating it with restrictive permissions.

	Hardening 1.4.2 — single accessor for ``~/.system_update`` so every
	module agrees on the path *and* the permissions. Honors the
	``SYSTEM_UPDATE_HOME`` env var documented in AGENTS.md / README.

	The directory is created with mode 0o700 on POSIX (only the current
	user can list/write). On Windows ``mkdir`` ignores POSIX mode bits;
	full ACL hardening would require ``icacls`` — applied per-file by
	:func:`secure_write` rather than at the directory level since the
	parent dir often inherits user-profile ACLs already.
	"""
	override = os.environ.get(_HOME_ENV)
	path = Path(override).expanduser() if override else (Path.home() / '.system_update')
	# mode is masked by the current umask on POSIX; that's fine — the
	# common case (~/.system_update being u=rwx already) means 0o700 is
	# at most a tightening, never a loosening.
	path.mkdir(parents=True, exist_ok=True, mode=0o700)
	return path


def _harden_file_permissions(path: Path) -> None:
	"""Restrict ``path`` to the current user.

	POSIX: ``chmod 0o600`` (owner read/write only).
	Windows: ``icacls /inheritance:r /grant "%USERNAME%":(F)`` so only the
	user holds full control. The icacls call is best-effort — if it
	fails (no PATH, locked-down account, etc.) we log a debug line and
	carry on; the file itself is already written, just with default
	ACLs.
	"""
	try:
		if platform.system() == 'Windows':
			username = os.environ.get('USERNAME')
			if not username:
				return
			subprocess.run(
				[
					'icacls', str(path),
					'/inheritance:r',
					'/grant', f'{username}:(F)',
				],
				check=False,
				capture_output=True,
				timeout=5,
			)
		else:
			os.chmod(path, 0o600)
	except Exception as exc:  # pragma: no cover — defensive
		logger.debug('Failed to harden permissions on %s: %s', path, exc)


def secure_write(
	path: Union[str, Path],
	data: Union[str, bytes],
	*,
	encoding: str = 'utf-8',
) -> None:
	"""Atomically write ``data`` to ``path`` with restrictive permissions.

	Hardening 1.4.1 — replaces direct ``path.write_text(...)`` /
	``json.dump(open(path, 'w'))`` patterns. Behavior:

	1. Write to a temp file in the same directory (so ``os.replace`` is
	   atomic — same filesystem).
	2. Apply 0o600 (POSIX) / icacls user-only ACL (Windows) to the temp
	   file *before* the rename, so the file never exists with looser
	   permissions.
	3. ``os.replace`` to swap into place.

	If anything fails before the rename, the temp file is removed.
	"""
	target = Path(path)
	target.parent.mkdir(parents=True, exist_ok=True)

	mode = 'wb' if isinstance(data, (bytes, bytearray)) else 'w'
	fd, tmp_path = tempfile.mkstemp(
		prefix=f'.{target.name}.', suffix='.tmp', dir=str(target.parent)
	)
	tmp = Path(tmp_path)
	try:
		# Tighten permissions on the temp file before any data hits disk.
		_harden_file_permissions(tmp)
		with os.fdopen(fd, mode, encoding=None if 'b' in mode else encoding) as f:
			f.write(data)
		# os.replace is atomic on POSIX and (since Python 3.3) on Windows.
		os.replace(tmp, target)
		# Belt and suspenders — re-harden the destination in case the
		# replace inherited weaker ACLs from the parent.
		_harden_file_permissions(target)
	except Exception:
		try:
			tmp.unlink(missing_ok=True)
		except Exception:
			pass
		raise


def harden_existing_file(path: Union[str, Path]) -> None:
	"""Public hook to apply 0o600/icacls to a file written by something else.

	SQLite databases are opened by ``sqlite3.connect`` (which uses raw
	``open(..., O_CREAT)``); we cannot route those writes through
	:func:`secure_write`. Call this once after the connection is
	established to bring the file's ACLs in line.
	"""
	target = Path(path)
	if target.exists():
		_harden_file_permissions(target)


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
                result.stdout[:300] +
                '...[truncated]' if stdout_len > 300 else result.stdout
            )
            logger.debug(f'[EXEC] stdout ({stdout_len} chars): {stdout_trunc}')
        else:
            logger.debug('[EXEC] stdout (empty)')

        if stderr_len > 0:
            stderr_trunc = (
                result.stderr[:300] +
                '...[truncated]' if stderr_len > 300 else result.stderr
            )
            logger.debug(f'[EXEC] stderr ({stderr_len} chars): {stderr_trunc}')

        if result.returncode != 0 and not allow_failure:
            details = []
            if result.stdout:
                details.append(
                    f'stdout:\n{_log_excerpt(result.stdout.rstrip())}')
            if result.stderr:
                details.append(
                    f'stderr:\n{_log_excerpt(result.stderr.rstrip())}')
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
        logger.warning(
            f'[EXEC] Permission denied: {cmd_str} - {error.suggestion}')
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


def dedupe_apps(apps: Iterable[AppInfo]) -> List[AppInfo]:
    """Return apps deduplicated by source/name/version, preserving the last record."""
    return list(
        {
            f'{app.source}|{app.name}|{app.version}'.lower(): app
            for app in apps
        }.values()
    )


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
    'drivers': 'bright_blue',
    'services': 'bright_green',
    'psmodules': 'bright_magenta',
    'vsextensions': 'bright_cyan',
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
                        'drivers': 'bright_blue',
                        'services': 'bright_green',
                        'psmodules': 'bright_magenta',
                        'vsextensions': 'bright_cyan',
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
                        'drivers': 'bright_blue',
                        'services': 'bright_green',
                        'psmodules': 'bright_magenta',
                        'vsextensions': 'bright_cyan',
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
                        'drivers': 'dim blue',
                        'services': 'dim green',
                        'psmodules': 'dim magenta',
                        'vsextensions': 'dim cyan',
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
                        'drivers': 'blue',
                        'services': 'green',
                        'psmodules': 'magenta',
                        'vsextensions': 'cyan',
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
                        'drivers': 'color(45)',
                        'services': 'color(82)',
                        'psmodules': 'color(201)',
                        'vsextensions': 'color(51)',
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


# Bare emojis (no U+FE0F variation selector). Rich miscounts cell-width
# for VS-augmented emoji vs. how the terminal renders them, which would
# desynchronise panel borders from their content. ``registry`` previously
# used ``🖥️`` with a VS — replaced with the unqualified ``🖥``.
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
    'registry': '🖥 ',
    'scoop': '🥄',
    'dotnet': '🔷',
    'appx': '🪟',
    'msix': '📱',
    'drivers': '🧰',
    'services': '⚙ ',
    'psmodules': '💠',
    'vsextensions': '🔌',
}


def source_icon(source: str) -> str:
    """Return the icon for a source, using the plugin glyph for custom sources."""
    return SOURCE_ICONS.get(display_source(source), '🧩')


def source_chip(source: str) -> str:
    """Return an icon plus colored source badge for Rich progress labels."""
    return f'{source_icon(source)} {source_badge(source)}'
