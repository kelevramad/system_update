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
from pathlib import Path
from typing import Dict, List, Optional

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
	parsed: Optional[Dict] = None  # decoded JSON when remote returned a scan

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
		self.path = path or (Path.home() / '.system_update' / 'inventory.json')
		self.hosts: List[RemoteHost] = []
		self._load()

	def _load(self) -> None:
		if not self.path.exists():
			return
		try:
			data = json.loads(self.path.read_text(encoding='utf-8'))
		except Exception as e:
			logger.warning(f'Failed to load inventory: {e}')
			return
		raw = data.get('hosts') if isinstance(data, dict) else data
		if isinstance(raw, list):
			self.hosts = [RemoteHost.from_dict(h) for h in raw if isinstance(h, dict)]

	def save(self) -> None:
		self.path.parent.mkdir(parents=True, exist_ok=True)
		payload = {'hosts': [h.to_dict() for h in self.hosts]}
		self.path.write_text(json.dumps(payload, indent=2), encoding='utf-8')

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


def _build_winrs_argv(host: RemoteHost, command: str, password: str = '') -> List[str]:
	"""Build the ``winrs`` argv. Password comes from env if not provided."""
	target = host.address or host.name
	argv = ['winrs', f'-r:{target}']
	if host.user:
		argv.append(f'-u:{host.user}')
	pw = password or os.environ.get('SYSTEM_UPDATE_REMOTE_PASS', '')
	if pw:
		argv.append(f'-p:{pw}')
	argv.append(command)
	return argv


def build_debug_argv(host: RemoteHost, command: str) -> List[str]:
	"""Return the local command argv with secrets redacted for debug output."""
	argv = _build_winrs_argv(host, command)
	return ['-p:***' if item.startswith('-p:') else item for item in argv]


def argv_to_display(argv: List[str]) -> str:
	"""Format argv as a copy/pasteable command line for diagnostics."""
	return ' '.join(shlex.quote(part) if re.search(r'\s', part) else part for part in argv)


def execute_remote(
	host: RemoteHost,
	command: str,
	timeout: int = _DEFAULT_REMOTE_TIMEOUT,
	password: str = '',
) -> RemoteResult:
	"""Run ``command`` on ``host`` and return a :class:`RemoteResult`.

	Currently only the ``winrs`` transport is implemented. Other values are
	rejected with a clear error so the user knows what's missing.
	"""
	if host.transport != 'winrs':
		return RemoteResult(
			host=host.name, ok=False,
			stderr=(
				f'Transport {host.transport!r} not supported yet — only "winrs". '
				f'Patches welcome.'
			),
		)

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
		parsed = None
		if stdout.strip().startswith('{') or stdout.strip().startswith('['):
			try:
				parsed = json.loads(stdout)
			except Exception:
				parsed = None
		return RemoteResult(
			host=host.name,
			ok=proc.returncode == 0,
			exit_code=proc.returncode,
			stdout=stdout,
			stderr=proc.stderr or '',
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
	by_host: Dict[str, Dict] = {}
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
