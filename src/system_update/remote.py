"""Remote management — enhancement section 6.4.

Implements:
    6.4.1 — WinRM remote execution via Windows ``winrs`` (no extra dep)
    6.4.2 — Inventory of named hosts and host groups
    6.4.3 — Consolidated reports across multiple hosts
    6.4.4 — Mass update fan-out

Inventory lives at ``~/.system_update/inventory.json``::

    {
      "hosts": [
        {
          "name": "build01",
          "address": "build01.corp",
          "user": "DOMAIN\\\\admin",
          "transport": "winrs",
          "groups": ["builders", "windows"],
          "description": "CI builder"
        }
      ]
    }

Remote execution is intentionally minimal: we shell out to ``winrs`` (built
into every Windows install) so there's no external Python dependency. The
remote command is always the JSON-export form of ``system-update`` so the
output is parseable for aggregation.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import subprocess
import time
from dataclasses import dataclass, field
from json import JSONDecodeError
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ─── Models ────────────────────────────────────────────────────────────────


@dataclass
class RemoteHost:
	"""One inventory entry — addressable target for remote execution."""

	name: str
	address: str = ''
	user: str = ''
	transport: str = 'winrs'  # winrs | pywinrm | ssh
	port: Optional[int] = None
	description: str = ''
	groups: List[str] = field(default_factory=list)

	def __post_init__(self) -> None:
		if not self.address:
			self.address = self.name

	@classmethod
	def from_dict(cls, data: Dict) -> 'RemoteHost':
		return cls(
			name=str(data.get('name', '')),
			address=str(data.get('address', '') or data.get('name', '')),
			user=str(data.get('user', '')),
			transport=str(data.get('transport', 'winrs')),
			port=data.get('port'),
			description=str(data.get('description', '')),
			groups=list(data.get('groups') or []),
		)

	def to_dict(self) -> Dict:
		out = {
			'name': self.name,
			'address': self.address,
			'user': self.user,
			'transport': self.transport,
			'description': self.description,
			'groups': list(self.groups),
		}
		if self.port:
			out['port'] = self.port
		return out


@dataclass
class RemoteResult:
	"""Outcome of one remote run — used by aggregation."""

	host: str
	ok: bool
	exit_code: int = 0
	stdout: str = ''
	stderr: str = ''
	duration: float = 0.0
	# decoded JSON when remote returned a scan — may be a dict (newer
	# payload shape) or a bare list (legacy export format)
	parsed: Optional[Any] = None

	def to_dict(self) -> Dict:
		out = {
			'host': self.host,
			'ok': self.ok,
			'exit_code': self.exit_code,
			'duration': round(self.duration, 2),
		}
		if self.stdout:
			out['stdout'] = self.stdout[-2000:]  # tail
		if self.stderr:
			out['stderr'] = self.stderr[-2000:]
		if self.parsed is not None:
			out['scan'] = self.parsed
		return out


# ─── Inventory ─────────────────────────────────────────────────────────────


class Inventory:
	"""JSON-file inventory at ``~/.system_update/inventory.json``."""

	def __init__(self, path: Optional[Path] = None) -> None:
		from system_update.utils import data_dir

		self.path = path or (data_dir() / 'inventory.json')
		self.hosts: List[RemoteHost] = []
		self._load()

	def _load(self) -> None:
		if not self.path.exists():
			return
		try:
			with open(self.path, 'r', encoding='utf-8') as f:
				data = json.load(f)
		except Exception as e:
			logger.warning(f'Failed to load inventory: {e}')
			return
		raw = data.get('hosts') if isinstance(data, dict) else data
		if isinstance(raw, list):
			self.hosts = [RemoteHost.from_dict(h) for h in raw if isinstance(h, dict)]

	def save(self) -> None:
		from system_update.utils import secure_write

		# Inventory contains hostnames and usernames — restrict to 0o600
		# so other local users cannot enumerate the fleet.
		payload = {'hosts': [h.to_dict() for h in self.hosts]}
		secure_write(self.path, json.dumps(payload, indent=2))

	# ── 6.4.2 — CRUD ─────────────────────────────────────────────────────

	def add(self, host: RemoteHost) -> None:
		"""Add or replace a host (matched by name)."""
		self.hosts = [h for h in self.hosts if h.name.lower() != host.name.lower()]
		self.hosts.append(host)
		self.save()

	def remove(self, name: str) -> bool:
		before = len(self.hosts)
		self.hosts = [h for h in self.hosts if h.name.lower() != name.lower()]
		if len(self.hosts) != before:
			self.save()
			return True
		return False

	def get(self, name: str) -> Optional[RemoteHost]:
		for h in self.hosts:
			if h.name.lower() == name.lower():
				return h
		return None

	def by_group(self, group: str) -> List[RemoteHost]:
		g = group.lower()
		return [h for h in self.hosts if g in (x.lower() for x in h.groups)]

	def all(self) -> List[RemoteHost]:
		return list(self.hosts)

	def resolve(self, host: Optional[str], group: Optional[str]) -> List[RemoteHost]:
		"""Resolve CLI flags to a concrete list of hosts.

		Precedence: ``host`` (single) → ``group`` (multiple) → all hosts.
		"""
		if host:
			h = self.get(host)
			return [h] if h else []
		if group:
			return self.by_group(group)
		return self.all()


# ─── 6.4.1 — Remote execution ──────────────────────────────────────────────


_DEFAULT_REMOTE_TIMEOUT = 600
_DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024


_SUPPORTED_TRANSPORTS = ('winrs', 'pywinrm')

# One-shot guard so the winrs-with-password warning fires once per process.
_WINRS_WARNED = False


def _max_response_bytes() -> int:
	"""Return the configured remote JSON response cap in bytes."""
	try:
		from system_update.config import SystemConfig

		remote_cfg = SystemConfig().settings.get('remote', {})
		value = remote_cfg.get('max_response_bytes', _DEFAULT_MAX_RESPONSE_BYTES)
		if isinstance(value, int) and value > 0:
			return value
	except Exception:
		logger.warning('Failed to read remote.max_response_bytes; using default.', exc_info=True)
	return _DEFAULT_MAX_RESPONSE_BYTES


def _format_bytes(size: int) -> str:
	"""Format bytes in a compact form for remote parse errors."""
	if size % (1024 * 1024) == 0:
		return f'{size // (1024 * 1024)} MiB'
	if size % 1024 == 0:
		return f'{size // 1024} KiB'
	return f'{size} bytes'


def _parse_remote_stdout(stdout: str, max_response_bytes: Optional[int] = None) -> Tuple[Any, str]:
	"""Parse JSON remote stdout after enforcing the configured size cap.

	Returns ``(parsed, error)``. Non-JSON-looking stdout is left untouched and
	does not count as a parse error.
	"""
	stripped = stdout.strip()
	if not stripped.startswith(('{', '[')):
		return None, ''

	limit = max_response_bytes or _max_response_bytes()
	response_size = len(stdout.encode('utf-8'))
	if response_size > limit:
		return None, (
			f'Remote JSON response exceeded {_format_bytes(limit)} '
			f'({response_size} bytes received).'
		)

	try:
		return json.loads(stdout), ''
	except JSONDecodeError as e:
		return None, f'Remote JSON response was invalid: {e.msg}.'


def _build_winrs_argv(host: RemoteHost, command: str, password: str = '') -> List[str]:
	"""Build the ``winrs`` argv. Password comes from env if not provided.

	Note: the password ends up on the spawned process's command line. Other
	local users can read it via ``Get-CimInstance Win32_Process``. The
	``pywinrm`` transport (see :func:`_execute_via_pywinrm`) avoids this.
	"""
	target = host.address or host.name
	argv = ['winrs', f'-r:{target}']
	if host.user:
		argv.append(f'-u:{host.user}')
	pw = password or os.environ.get('SYSTEM_UPDATE_REMOTE_PASS', '')
	if pw:
		argv.append(f'-p:{pw}')
	argv.append(command)
	return argv


def _password_for(host: RemoteHost, password: str) -> str:
	return password or os.environ.get('SYSTEM_UPDATE_REMOTE_PASS', '')


def build_debug_argv(host: RemoteHost, command: str) -> List[str]:
	"""Return the local command argv with secrets redacted for debug output."""
	argv = _build_winrs_argv(host, command)
	return ['-p:***' if item.startswith('-p:') else item for item in argv]


def argv_to_display(argv: List[str]) -> str:
	"""Format argv as a copy/pasteable command line for diagnostics."""
	return ' '.join(shlex.quote(part) if re.search(r'\s', part) else part for part in argv)


def _warn_winrs_password_in_argv() -> None:
	"""Emit a one-shot warning that ``winrs`` leaks the password via argv."""
	global _WINRS_WARNED
	if _WINRS_WARNED:
		return
	_WINRS_WARNED = True
	logger.warning(
		"WinRS password is visible to other local users via Win32_Process. "
		"Install 'pywinrm' and set host transport='pywinrm' for HTTPS-based delivery: "
		"uv pip install 'system-update-cli[remote-secure]'"
	)


def _execute_via_pywinrm(
	host: RemoteHost,
	command: str,
	timeout: int,
	password: str,
) -> RemoteResult:
	"""Run ``command`` on ``host`` via the ``pywinrm`` HTTPS transport.

	The password is sent inside the SOAP request body and never appears on
	the local process's command line.
	"""
	try:
		import winrm  # type: ignore[import-not-found]
	except ImportError:
		return RemoteResult(
			host=host.name,
			ok=False,
			exit_code=-1,
			stderr=(
				"pywinrm is not installed. Install with: "
				"uv pip install 'system-update-cli[remote-secure]'"
			),
		)

	pw = _password_for(host, password)
	target = host.address or host.name
	port = host.port or 5986
	endpoint = f'https://{target}:{port}/wsman'

	start = time.monotonic()
	try:
		session = winrm.Session(
			endpoint,
			auth=(host.user, pw),
			transport='ntlm',
			server_cert_validation='validate',
			operation_timeout_sec=max(1, timeout - 5),
			read_timeout_sec=timeout,
		)
		response = session.run_cmd(command)
	except Exception as e:
		return RemoteResult(
			host=host.name,
			ok=False,
			exit_code=-1,
			stderr=f'pywinrm error: {type(e).__name__}: {e}',
			duration=time.monotonic() - start,
		)

	duration = time.monotonic() - start
	stdout = response.std_out.decode('utf-8', errors='replace') if response.std_out else ''
	stderr = response.std_err.decode('utf-8', errors='replace') if response.std_err else ''
	parsed, parse_error = _parse_remote_stdout(stdout)
	if parse_error:
		stderr = f'{stderr}\n{parse_error}'.strip()
	return RemoteResult(
		host=host.name,
		ok=response.status_code == 0 and not parse_error,
		exit_code=response.status_code,
		stdout=stdout,
		stderr=stderr,
		duration=duration,
		parsed=parsed,
	)


def _execute_via_winrs(
	host: RemoteHost,
	command: str,
	timeout: int,
	password: str,
) -> RemoteResult:
	"""Legacy ``winrs`` transport — password ends up on argv (see warning)."""
	if _password_for(host, password):
		_warn_winrs_password_in_argv()

	argv = _build_winrs_argv(host, command, password=password)
	start = time.monotonic()
	try:
		proc = subprocess.run(
			argv,
			capture_output=True,
			text=True,
			encoding='utf-8',
			errors='replace',
			timeout=timeout,
		)
		duration = time.monotonic() - start
		stdout = proc.stdout or ''
		stderr = proc.stderr or ''
		parsed, parse_error = _parse_remote_stdout(stdout)
		if parse_error:
			stderr = f'{stderr}\n{parse_error}'.strip()
		return RemoteResult(
			host=host.name,
			ok=proc.returncode == 0 and not parse_error,
			exit_code=proc.returncode,
			stdout=stdout,
			stderr=stderr,
			duration=duration,
			parsed=parsed,
		)
	except subprocess.TimeoutExpired:
		return RemoteResult(
			host=host.name, ok=False, exit_code=-1,
			stderr=f'Timeout after {timeout}s', duration=time.monotonic() - start,
		)
	except FileNotFoundError:
		return RemoteResult(
			host=host.name, ok=False, exit_code=-1,
			stderr='winrs.exe not found on this machine — Windows only.',
		)
	except Exception as e:  # pragma: no cover — defensive
		return RemoteResult(
			host=host.name, ok=False, exit_code=-1,
			stderr=f'Unexpected error: {e}',
			duration=time.monotonic() - start,
		)


def execute_remote(
	host: RemoteHost,
	command: str,
	timeout: int = _DEFAULT_REMOTE_TIMEOUT,
	password: str = '',
) -> RemoteResult:
	"""Run ``command`` on ``host`` and return a :class:`RemoteResult`.

	Supported transports:
	    * ``winrs`` (default, legacy) — password leaks on argv; warns once.
	    * ``pywinrm`` — HTTPS WinRM via ``pywinrm`` extra; password kept off argv.
	"""
	if host.transport == 'pywinrm':
		return _execute_via_pywinrm(host, command, timeout, password)
	if host.transport == 'winrs':
		return _execute_via_winrs(host, command, timeout, password)
	return RemoteResult(
		host=host.name, ok=False,
		stderr=(
			f'Transport {host.transport!r} not supported. '
			f'Use one of: {", ".join(_SUPPORTED_TRANSPORTS)}.'
		),
	)


def execute_many(
	hosts: List[RemoteHost],
	command: str,
	timeout: int = _DEFAULT_REMOTE_TIMEOUT,
	password: str = '',
	max_workers: int = 4,
	tick_interval: float = 30.0,
	on_start=None,
	on_tick=None,
	on_complete=None,
) -> List[RemoteResult]:
	"""Run ``command`` on every host in parallel.

	``on_start(host)`` fires just before submitting a host.
	``on_tick(host, elapsed)`` fires periodically while the host is still running.
	``on_complete(host, result)`` is invoked from the calling thread as each
	future finishes — used by the CLI to give the user live feedback instead
	of staring at a frozen prompt.
	"""
	from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

	results: List[RemoteResult] = []
	if not hosts:
		return results
	with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(hosts)))) as ex:
		futures = {}
		for h in hosts:
			if on_start is not None:
				try:
					on_start(h)
				except Exception:  # callback shouldn't break execution
					logger.warning('on_start callback raised', exc_info=True)
			futures[ex.submit(execute_remote, h, command, timeout, password)] = h

		started = {fut: time.monotonic() for fut in futures}
		last_tick = dict(started)
		pending = set(futures)
		while pending:
			done, pending = wait(
				pending,
				timeout=max(0.01, min(float(tick_interval), 1.0)),
				return_when=FIRST_COMPLETED,
			)
			now = time.monotonic()
			if on_tick is not None:
				for fut in list(pending):
					if now - last_tick[fut] >= tick_interval:
						try:
							on_tick(futures[fut], now - started[fut])
						except Exception:
							logger.warning('on_tick callback raised', exc_info=True)
						last_tick[fut] = now
			for fut in done:
				res = fut.result()
				results.append(res)
				if on_complete is not None:
					try:
						on_complete(futures[fut], res)
					except Exception:  # callback shouldn't break execution
						logger.warning('on_complete callback raised', exc_info=True)
	# Stable order by host name for predictable output.
	results.sort(key=lambda r: r.host.lower())
	return results


# ─── Command builders ──────────────────────────────────────────────────────


def build_remote_scan_command(extra_args: str = '') -> str:
	"""Return the ``system-update`` invocation that runs on the remote.

	The remote is asked to dump JSON to stdout so :func:`aggregate_scans`
	can decode it. Caller can append additional flags.
	"""
	parts = [
		'system-update',
		'--no-cache',
		'--export', 'json',
		'-o', '-',
	]
	if extra_args:
		parts.extend(shlex.split(extra_args))
	return ' '.join(shlex.quote(p) if ' ' in p else p for p in parts)


def build_remote_update_command(extra_args: str = '') -> str:
	"""Build the remote ``--update-all --yes`` command line."""
	parts = ['system-update', '--update-all', '--yes']
	if extra_args:
		parts.extend(shlex.split(extra_args))
	return ' '.join(shlex.quote(p) if ' ' in p else p for p in parts)


# ─── 6.4.3 — Aggregation ───────────────────────────────────────────────────


def aggregate_scans(results: List[RemoteResult]) -> Dict:
	"""Combine per-host scan JSON into a consolidated report.

	Only hosts whose remote run succeeded AND returned parseable JSON
	contribute to the package totals; hosts with errors are surfaced in
	the ``errors`` block so the operator sees what failed.
	"""
	by_host: Dict[str, Any] = {}
	per_host_summary: List[Dict] = []
	errors: List[Dict] = []

	all_packages: Dict[str, Dict] = {}  # key = source|name → row

	for r in results:
		if not r.ok or r.parsed is None:
			errors.append({
				'host': r.host,
				'exit_code': r.exit_code,
				'stderr': (r.stderr or '')[-500:],
			})
			continue
		payload = r.parsed
		# Accept either a list (newer export shape) or {"packages": [...]}.
		pkgs = payload if isinstance(payload, list) else payload.get('packages') or []
		updates = sum(1 for p in pkgs if p.get('status') == 'update_available')
		vulns = sum(1 for p in pkgs if p.get('status') == 'vulnerable')
		per_host_summary.append({
			'host': r.host,
			'total': len(pkgs),
			'updates': updates,
			'vulnerable': vulns,
			'duration': round(r.duration, 2),
		})
		by_host[r.host] = payload
		for p in pkgs:
			if not isinstance(p, dict):
				continue
			key = f'{p.get("source", "")}|{p.get("name", "")}'.lower()
			row = all_packages.setdefault(
				key, {
					'source': p.get('source', ''),
					'name': p.get('name', ''),
					'hosts': [],
					'versions': set(),
				},
			)
			row['hosts'].append(r.host)
			if p.get('version'):
				row['versions'].add(p['version'])

	# Render set → sorted list for JSON-safety.
	package_index = []
	for row in all_packages.values():
		package_index.append({
			'source': row['source'],
			'name': row['name'],
			'host_count': len(set(row['hosts'])),
			'hosts': sorted(set(row['hosts'])),
			'versions': sorted(row['versions']),
			'consistent': len(row['versions']) <= 1,
		})

	return {
		'host_count': len(per_host_summary),
		'error_count': len(errors),
		'summary_per_host': per_host_summary,
		'package_index': sorted(
			package_index, key=lambda r: (r['source'], r['name'].lower())
		),
		'errors': errors,
		'raw_per_host': by_host,
	}


__all__ = [
	'RemoteHost',
	'RemoteResult',
	'Inventory',
	'argv_to_display',
	'build_debug_argv',
	'execute_remote',
	'execute_many',
	'build_remote_scan_command',
	'build_remote_update_command',
	'aggregate_scans',
]
