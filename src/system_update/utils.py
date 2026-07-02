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
from datetime import datetime, timezone
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
# WINDOWS ENCODING + ISO TIMESTAMP HELPERS (Hardening 2.2)
# ═══════════════════════════════════════════════════════════════════════════════


def parse_iso_utc(s: str) -> datetime:
	"""Parse an ISO-8601 timestamp into a timezone-aware UTC ``datetime``.

	Hardening 2.2.3 — the previous pattern
	``datetime.fromisoformat(s.replace('Z', ''))`` produced a *naive*
	datetime in local time, which compares wrongly against
	``datetime.now(timezone.utc)`` and silently invalidates the cache
	(or, depending on sign, never invalidates it). Always returns an
	aware UTC datetime; legacy naive entries are interpreted as UTC.

	Raises ``ValueError`` for unparseable input — keep the same blast
	radius the caller already handles around ``fromisoformat``.
	"""
	if not s:
		raise ValueError('parse_iso_utc: empty string')
	# Python <3.11 doesn't accept the trailing ``Z`` alias. Normalise.
	if s.endswith('Z'):
		s = s[:-1] + '+00:00'
	dt = datetime.fromisoformat(s)
	if dt.tzinfo is None:
		# Legacy entries assumed to be UTC — preserves the previous
		# *intended* semantics across cache files written before the fix.
		dt = dt.replace(tzinfo=timezone.utc)
	return dt.astimezone(timezone.utc)


# Decoder priority list for ``decode_command_output`` — first to fully
# decode wins. ``utf-8-sig`` strips an optional BOM. ``cp850`` is the
# default OEM page on en-US Windows; ``cp1252`` is the default ANSI
# page; both come up in legacy ``cmd.exe`` console output.
_DECODE_FALLBACKS = ('utf-8-sig', 'utf-16-le', 'cp1252')


def _oem_codepage() -> Optional[str]:
	"""Return the active Windows OEM code page (e.g. 'cp850'), or None.

	The OEM page is what ``cmd.exe``-spawned tools write to stdout.
	Different from the ANSI page (``GetACP``), which is what GUI APIs
	use. Falls back to ``None`` on non-Windows or if ctypes lookup
	fails for any reason.
	"""
	if platform.system() != 'Windows':
		return None
	try:
		import ctypes
		cp = ctypes.windll.kernel32.GetOEMCP()  # type: ignore[attr-defined]
		return f'cp{int(cp)}' if cp else None
	except Exception:
		return None


def decode_command_output(data: Union[bytes, str, None]) -> str:
	"""Decode raw subprocess stdout/stderr, preserving accented characters.

	Hardening 2.2.1 — ``subprocess.run(..., text=True, encoding='utf-8',
	errors='ignore')`` corrupts Windows tool output that's not UTF-8
	(it silently drops bytes), producing mojibake for names like
	``Café``, ``Software Müller``, or any pt-BR / DE / ES vendor name.
	Capture as bytes and decode with a fallback chain instead.

	Order: UTF-8 (with BOM strip) → UTF-16-LE (if the BOM is present)
	→ active OEM code page (`GetOEMCP`) on Windows → CP1252 → UTF-8
	with ``errors='replace'`` as the final fallback (logs a debug
	line so the failure is visible without crashing the scanner).

	Tolerant of ``str`` input: if a caller passes already-decoded text
	(common in test mocks), it's returned unchanged.
	"""
	if not data:
		return ''
	# Already-decoded — pass through. Lets existing test mocks that
	# return ``stdout='...'`` keep working after the bytes migration.
	if isinstance(data, str):
		return data

	# UTF-16-LE BOM is unmistakable; check it first to avoid the
	# UTF-8-sig path mangling a UTF-16 stream.
	if data[:2] == b'\xff\xfe':
		try:
			return data.decode('utf-16-le')[1:]  # drop the BOM character
		except UnicodeDecodeError:
			pass

	candidates: List[str] = list(_DECODE_FALLBACKS)
	oem = _oem_codepage()
	if oem and oem not in candidates:
		# Insert OEM page after UTF-8 so genuine UTF-8 still wins, but
		# legacy OEM output beats the generic CP1252 fallback.
		candidates.insert(1, oem)

	for codec in candidates:
		try:
			return data.decode(codec)
		except UnicodeDecodeError:
			continue

	logger.debug(
		'decode_command_output: all decoders failed (%d bytes); '
		'falling back to utf-8/replace.', len(data),
	)
	return data.decode('utf-8', errors='replace')


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
    logger.debug('Starting: %s', cmd_str, extra={'source': 'exec', 'phase': 'start'})

    try:
        if platform.system() == 'Windows':
            executable = shutil.which(cmd[0])
            if executable:
                logger.debug('Resolved %s to: %s', cmd[0], executable, extra={'source': 'exec', 'phase': 'resolve'})
                cmd[0] = executable
            else:
                logger.debug('Command not found in PATH: %s', cmd[0], extra={'source': 'exec', 'phase': 'resolve'})

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

        # Hardening 2.2.1 — capture as bytes so accented characters in
        # tool output (winget, reg query, choco list) survive. Decoding
        # is delegated to ``decode_command_output`` which tries UTF-8 →
        # UTF-16-LE (BOM-detected) → active OEM code page → CP1252,
        # falling back to UTF-8/replace only if everything fails.
        result = subprocess.run(
            cmd,
            capture_output=True,
            check=False,
            timeout=timeout,
            env=env,
        )

        # Reattach decoded strings to a SimpleNamespace-like shim so
        # downstream code keeps using ``result.stdout`` / ``result.stderr``
        # as ``str`` without further changes.
        decoded_stdout = decode_command_output(result.stdout or b'')
        decoded_stderr = decode_command_output(result.stderr or b'')

        class _Decoded:
            def __init__(self, returncode: int, stdout: str, stderr: str) -> None:
                self.returncode = returncode
                self.stdout = stdout
                self.stderr = stderr

        result = _Decoded(result.returncode, decoded_stdout, decoded_stderr)  # type: ignore[assignment]

        logger.debug('Exit code: %s', result.returncode, extra={'source': 'exec', 'phase': 'complete'})

        stdout_len = len(result.stdout) if result.stdout else 0
        stderr_len = len(result.stderr) if result.stderr else 0

        if stdout_len > 0:
            stdout_trunc = (
                result.stdout[:300] +
                '...[truncated]' if stdout_len > 300 else result.stdout
            )
            logger.debug('stdout (%s chars): %s', stdout_len, stdout_trunc, extra={'source': 'exec', 'phase': 'io'})
        else:
            logger.debug('stdout (empty)', extra={'source': 'exec', 'phase': 'io'})

        if stderr_len > 0:
            stderr_trunc = (
                result.stderr[:300] +
                '...[truncated]' if stderr_len > 300 else result.stderr
            )
            logger.debug('stderr (%s chars): %s', stderr_len, stderr_trunc, extra={'source': 'exec', 'phase': 'io'})

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
                'Command failed (exit %s): %s%s', result.returncode, cmd_str, output,
                extra={'source': 'exec', 'phase': 'complete', 'level': 'warning'},
            )
            return None

        if include_stderr:
            combined = f'{result.stdout}\n{result.stderr}'.strip()
            return combined or None

        logger.debug('Success: %s (%s output chars)', cmd_str, stdout_len, extra={'source': 'exec', 'phase': 'complete'})
        return result.stdout.strip() or None

    except subprocess.TimeoutExpired as exc:
        error = CommandError.classify(exc, cmd_str)
        logger.warning('Timeout: %s - %s', cmd_str, error.suggestion, extra={'source': 'exec', 'phase': 'error'})
        logger.debug('Timeout details: %s', exc, extra={'source': 'exec', 'phase': 'error'})
        return None

    except FileNotFoundError as exc:
        error = CommandError.classify(exc, cmd_str)
        logger.debug('Not found: %s - %s', cmd_str, error.suggestion, extra={'source': 'exec', 'phase': 'error'})
        logger.debug('FileNotFoundError: %s', exc, extra={'source': 'exec', 'phase': 'error'})
        return None
    except PermissionError as exc:
        error = CommandError.classify(exc, cmd_str)
        logger.warning(
            'Permission denied: %s - %s', cmd_str, error.suggestion, extra={'source': 'exec', 'phase': 'error'})
        logger.debug('PermissionError: %s', exc, extra={'source': 'exec', 'phase': 'error'})
        return None
    except (json.JSONDecodeError, ValueError) as exc:
        error = CommandError.classify(exc, cmd_str)
        logger.warning('Parse error: %s - %s', cmd_str, error.suggestion, extra={'source': 'exec', 'phase': 'error'})
        logger.debug('Parse error details: %s', exc, extra={'source': 'exec', 'phase': 'error'})
        return None
    except Exception as exc:  # noqa: BLE001 — intentional catch-all with classification
        error = CommandError.classify(exc, cmd_str)
        logger.warning(
            'Error: %s: %s - %s', error.category.value, error.message, error.suggestion,
            extra={'source': 'exec', 'phase': 'error'},
        )
        logger.debug('Exception details: %s', exc, extra={'source': 'exec', 'phase': 'error'})


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
    'scoop': 'bright_yellow',
    'dotnet': 'gold',
    'drivers': 'bright_blue',
    'services': 'bright_green',
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
                        'scoop': 'yellow',
                        'dotnet': 'gold',
                        'drivers': 'bright_blue',
                        'services': 'bright_green',
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
                        'scoop': 'bright_yellow',
                        'dotnet': 'bright_gold',
                        'drivers': 'bright_blue',
                        'services': 'bright_green',
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
                        'scoop': 'dim yellow',
                        'dotnet': 'dim gold',
                        'drivers': 'dim blue',
                        'services': 'dim green',
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
                        'scoop': 'yellow',
                        'dotnet': 'gold',
                        'drivers': 'blue',
                        'services': 'green',
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
                        'scoop': 'color(226)',
                        'dotnet': 'color(220)',
                        'drivers': 'color(45)',
                        'services': 'color(82)',
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
    'scoop': '🥄',
    'dotnet': '🔷',
    'drivers': '🧰',
    'services': '⚙ ',
}


def source_icon(source: str) -> str:
    """Return the icon for a source, using the plugin glyph for custom sources."""
    return SOURCE_ICONS.get(display_source(source), '🧩')


def source_chip(source: str) -> str:
    """Return an icon plus colored source badge for Rich progress labels."""
    return f'{source_icon(source)} {source_badge(source)}'
