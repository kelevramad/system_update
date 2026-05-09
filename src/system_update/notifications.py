"""Outbound notification dispatch — Windows toast, email, webhook, script hook."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import platform
import socket
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List, Optional

from system_update.config import SystemConfig
from system_update.plugins import PluginRegistry, dispatch_notifiers
from system_update.utils import run_command

logger = logging.getLogger(__name__)


# Hardening 1.3 — webhook URL validation guards against SSRF.
_ALLOWED_WEBHOOK_SCHEMES = frozenset({'http', 'https'})


class UnsafeWebhookUrl(ValueError):
	"""Raised when a webhook URL fails the SSRF allowlist."""


def _is_private_address(addr: str) -> bool:
	"""True if ``addr`` is loopback, link-local, RFC1918, or unique-local."""
	try:
		ip = ipaddress.ip_address(addr)
	except ValueError:
		return False
	return (
		ip.is_loopback
		or ip.is_link_local
		or ip.is_private
		or ip.is_reserved
		or ip.is_multicast
		or ip.is_unspecified
	)


def _validate_webhook_url(url: str, allow_private_hosts: bool) -> None:
	"""Refuse non-HTTP(S) and (by default) private/loopback webhook targets.

	A webhook URL that resolves to ``127.0.0.1``, ``169.254.169.254``
	(cloud metadata endpoint), or any RFC1918 range turns the CLI into a
	credentialed SSRF probe. Block by default; ``allow_private_hosts``
	is the single opt-in for self-hosted endpoints.
	"""
	parsed = urllib.parse.urlparse(url)
	scheme = (parsed.scheme or '').lower()
	if scheme not in _ALLOWED_WEBHOOK_SCHEMES:
		raise UnsafeWebhookUrl(
			f'Webhook URL must be http(s); got scheme={scheme!r}'
		)
	host = parsed.hostname
	if not host:
		raise UnsafeWebhookUrl(f'Webhook URL has no host: {url!r}')
	if allow_private_hosts:
		return

	# Literal private IP in the URL.
	try:
		addr = ipaddress.ip_address(host)
	except ValueError:
		addr = None
	if addr is not None and _is_private_address(str(addr)):
		raise UnsafeWebhookUrl(
			f'Refusing webhook to private/loopback address: {host}'
		)

	# DNS-resolved private IP. Best-effort: a single A/AAAA lookup. DNS
	# rebinding could still defeat a check-then-connect pattern, but for
	# a long-lived user-configured webhook URL this is acceptable —
	# document the residual risk in the setting docstring.
	if addr is None:
		try:
			infos = socket.getaddrinfo(host, None)
		except socket.gaierror:
			# DNS failure is not an SSRF signal — let urlopen surface
			# the connection error to the user.
			return
		for family, _type, _proto, _canon, sockaddr in infos:
			if family not in (socket.AF_INET, socket.AF_INET6) or not sockaddr:
				continue
			# sockaddr[0] is a str for AF_INET/AF_INET6 — pyright sees the
			# generic ``str | int`` from ``socket.getaddrinfo`` and needs
			# the explicit cast.
			ip_str = str(sockaddr[0])
			if _is_private_address(ip_str):
				raise UnsafeWebhookUrl(
					f'Refusing webhook to {host} → {ip_str} '
					'(private/loopback). Set notifications.allow_private_hosts=true '
					'to opt in.'
				)


def _custom_script_command(script_path: str) -> List[str]:
	"""Build a shell-free argv for custom notification hooks."""
	resolved = os.path.abspath(os.path.expanduser(script_path))
	if platform.system() == 'Windows' and os.path.splitext(resolved)[1].lower() == '.ps1':
		return [
			'powershell',
			'-NoProfile',
			'-ExecutionPolicy',
			'Bypass',
			'-File',
			resolved,
		]
	return [resolved]


class NotificationManager:
	"""Dispatches notifications through every configured channel.

	A single :class:`SystemConfig` is required; the ``notifications`` section
	of its settings drives which channels are enabled and their credentials.
	"""

	def __init__(self, config: Optional[SystemConfig] = None) -> None:
		self.config = config or SystemConfig()
		self.settings = self.config.settings.get('notifications', {})
		self.plugin_registry: Optional[PluginRegistry] = None

	# ── channel: Windows toast ────────────────────────────────────────────

	def send_system_notification(self, title: str, message: str) -> bool:
		"""Show a Windows NotifyIcon balloon tooltip; no-op on other platforms."""
		if platform.system() != 'Windows':
			logger.debug('System notifications only available on Windows')
			return False

		try:
			logger.debug(f'Sending Windows notification: {title} - {message}')

			escaped_title = title.replace('"', "'").replace("'", "''")
			escaped_message = message.replace('"', "'").replace("'", "''").replace('\n', ' ')

			ps_script = f'''
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Windows.Forms

$icon = New-Object System.Windows.Forms.NotifyIcon
$icon.Icon = [System.Drawing.SystemIcons]::Information
$icon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
$icon.BalloonTipTitle = "{escaped_title}"
$icon.BalloonTipText = "{escaped_message}"
$icon.Visible = $true
$icon.ShowBalloonTip(15000)
Start-Sleep -Seconds 3
$icon.Dispose()
'''
			run_command(['powershell', '-NoProfile', '-Command', ps_script], allow_failure=True)
			logger.debug(f'System notification sent: {title}')
			return True
		except Exception as e:
			logger.debug(f'Failed to send system notification: {e}')
			return False

	# ── channel: email (SMTP or HTTP API) ─────────────────────────────────

	def send_email(
		self,
		to_address: str,
		subject: str,
		body: str,
		smtp_server: Optional[str] = None,
		smtp_port: int = 587,
		username: Optional[str] = None,
		password: Optional[str] = None,
		use_tls: bool = True,
	) -> bool:
		"""Send email via SMTP, or via HTTP API when ``smtp_server`` is an API URL."""
		smtp_server = smtp_server or self.settings.get('smtp_server')
		smtp_port = smtp_port or self.settings.get('smtp_port', 587)
		username = username or self.settings.get('smtp_username')
		password = password or self.settings.get('smtp_password')

		if not smtp_server or not username:
			logger.debug('SMTP/API configuration not available')
			return False

		try:
			logger.debug(f'Attempting to send email to {to_address}')
			if 'api' in smtp_server.lower() or '/api/' in smtp_server:
				return self._send_email_via_api(smtp_server, username, to_address, subject, body)
			return self._send_email_via_smtp(
				smtp_server, smtp_port, username, password, to_address, subject, body, use_tls
			)
		except Exception as e:
			logger.debug(f'Failed to send email: {type(e).__name__}: {e}')
			return False

	@staticmethod
	def _send_email_via_api(
		api_url: str, token: str, to_address: str, subject: str, body: str
	) -> bool:
		"""POST the message to a REST email API.

		Uses ``urllib.request`` so the bearer token never appears on a
		subprocess command line (``curl`` argv is readable to other local
		users via ``Get-CimInstance Win32_Process``).
		"""
		body_bytes = json.dumps(
			{
				'from': {'email': 'hello@demomailtrap.co', 'name': 'System Update'},
				'to': [{'email': to_address}],
				'subject': subject,
				'text': body,
			}
		).encode('utf-8')

		req = urllib.request.Request(
			api_url,
			data=body_bytes,
			method='POST',
			headers={
				'Authorization': f'Bearer {token}',
				'Content-Type': 'application/json',
			},
		)
		try:
			with urllib.request.urlopen(req, timeout=30) as resp:
				payload = resp.read().decode('utf-8', errors='replace')
				if 200 <= resp.status < 300 and 'success' in payload:
					logger.debug(f'Email API sent to {to_address}')
					return True
				logger.debug(f'Email API failed: status={resp.status} body={payload[:200]!r}')
				return False
		except urllib.error.HTTPError as e:
			logger.debug(f'Email API HTTP error: {e.code} {e.reason}')
			return False
		except urllib.error.URLError as e:
			logger.debug(f'Email API connection error: {e.reason}')
			return False
		except (TimeoutError, OSError) as e:
			logger.debug(f'Email API I/O error: {type(e).__name__}: {e}')
			return False

	@staticmethod
	def _send_email_via_smtp(
		server: str,
		port: int,
		username: str,
		password: str,
		to_address: str,
		subject: str,
		body: str,
		use_tls: bool,
	) -> bool:
		"""Deliver the message through an SMTP server."""
		import smtplib
		from email.mime.multipart import MIMEMultipart
		from email.mime.text import MIMEText

		msg = MIMEMultipart()
		msg['From'] = username
		msg['To'] = to_address
		msg['Subject'] = subject
		msg.attach(MIMEText(body, 'plain'))

		smtp = smtplib.SMTP(server, port)
		if use_tls:
			smtp.starttls()
		smtp.login(username, password)
		smtp.send_message(msg)
		smtp.quit()

		logger.debug(f'Email SMTP sent to {to_address}: {subject}')
		return True

	# ── channel: webhook ──────────────────────────────────────────────────

	def send_webhook(
		self,
		url: str,
		payload: Dict,
		method: str = 'POST',
		headers: Optional[Dict] = None,
	) -> bool:
		"""POST a JSON payload to an arbitrary webhook URL.

		Hardening 1.3.2 — refuses URLs that aren't ``http(s)`` and (by
		default) URLs that resolve to private/loopback/link-local IP
		ranges. Set ``notifications.allow_private_hosts=true`` to permit
		on-prem endpoints.
		"""
		headers = headers or self.settings.get('webhook_headers', {})
		headers.setdefault('Content-Type', 'application/json')
		allow_private = bool(self.settings.get('allow_private_hosts', False))

		try:
			_validate_webhook_url(url, allow_private)
		except UnsafeWebhookUrl as exc:
			logger.warning('Refusing webhook delivery: %s', exc)
			return False

		try:
			data = json.dumps(payload).encode('utf-8')
			req = urllib.request.Request(url, data=data, method=method, headers=headers)
			with urllib.request.urlopen(req, timeout=10) as response:
				logger.debug(f'Webhook sent to {url}: {response.status}')
				return True
		except Exception as e:
			logger.debug(f'Failed to send webhook: {e}')
			return False

	# ── channel: custom script ────────────────────────────────────────────

	def run_custom_script(self, script_path: str, env_vars: Optional[Dict] = None) -> bool:
		"""Invoke a user-supplied script with optional extra env vars."""
		if not os.path.exists(script_path):
			logger.debug(f'Custom script not found: {script_path}')
			return False

		env = os.environ.copy()
		if env_vars:
			env.update(env_vars)

		try:
			command = _custom_script_command(script_path)
			result = subprocess.run(
				command,
				env=env,
				capture_output=True,
				text=True,
				timeout=30,
			)
			logger.debug(f'Custom script executed: {script_path}, exit code: {result.returncode}')
			return result.returncode == 0
		except Exception as e:
			logger.debug(f'Failed to run custom script: {e}')
			return False

	# ── high-level dispatchers ────────────────────────────────────────────

	def _dispatch_all(
		self,
		title: str,
		message: str,
		extra_payload: Optional[Dict] = None,
		event: str = 'notification',
	) -> None:
		"""Fan out ``(title, message)`` across every enabled channel."""
		if self.settings.get('system_notifications'):
			self.send_system_notification(title, message)
		if self.settings.get('email_enabled'):
			self.send_email(self.settings.get('email_to'), title, message)
		if self.settings.get('webhook_enabled'):
			payload = {'title': title, 'message': message}
			if extra_payload:
				payload.update(extra_payload)
			self.send_webhook(self.settings.get('webhook_url'), payload)
		self._dispatch_plugin_notifiers(event, title, message, extra_payload)

	def _dispatch_plugin_notifiers(
		self,
		event: str,
		title: str,
		message: str,
		payload: Optional[Dict] = None,
	) -> None:
		"""Invoke custom notification channels registered by plugins."""
		if self.plugin_registry:
			dispatch_notifiers(self.plugin_registry, event, title, message, payload, self.config)

	def notify_updates_available(
		self, updates_count: int, vulnerable_count: int = 0, force: bool = False
	) -> None:
		"""Notify that ``updates_count`` updates (and optionally CVEs) are available."""
		if updates_count == 0:
			return

		title = '🚀 System Update'
		if vulnerable_count > 0:
			message = f'🔔 {updates_count} updates\n🔥 {vulnerable_count} security vulnerabilities!'
		else:
			message = f'✅ {updates_count} updates available'

		# ``force`` bypasses the per-channel config gates for system/email/webhook,
		# but the custom-script hook is always subject to its own enabled flag.
		if force:
			self.send_system_notification(title, message)
			if self.settings.get('email_enabled'):
				self.send_email(self.settings.get('email_to'), title, message)
			if self.settings.get('webhook_enabled'):
				self.send_webhook(
					self.settings.get('webhook_url'),
					{'title': title, 'message': message},
				)
			self._dispatch_plugin_notifiers(
				'updates_available',
				title,
				message,
				{'updates': updates_count, 'vulnerable': vulnerable_count},
			)
		elif self.settings.get('notify_on_updates', True):
			self._dispatch_all(
				title,
				message,
				{'updates': updates_count, 'vulnerable': vulnerable_count},
				event='updates_available',
			)

		# Custom script hook runs on both branches when enabled.
		if (force or self.settings.get('notify_on_updates', True)) and self.settings.get(
			'custom_script_enabled'
		):
			self.run_custom_script(
				self.settings.get('custom_script_path'),
				{'UPDATES': str(updates_count)},
			)

	def notify_scan_complete(self, total_apps: int, scan_time: float, force: bool = False) -> None:
		"""Notify that a scan finished (only when ``force`` or explicitly enabled)."""
		title = '🚀 System Update'
		message = f'📦 Scanned {total_apps} apps in {scan_time:.1f}s'
		notify_enabled = self.settings.get('notify_on_scan_complete', False)

		if force or (notify_enabled and self.settings.get('system_notifications', False)):
			self.send_system_notification(title, message)
		if force or (notify_enabled and self.settings.get('email_enabled', False)):
			self.send_email(self.settings.get('email_to'), title, message)
		if force or (notify_enabled and self.settings.get('webhook_enabled', False)):
			self.send_webhook(
				self.settings.get('webhook_url'),
				{
					'title': title,
					'message': message,
					'total_apps': total_apps,
					'scan_time': scan_time,
				},
			)
		if force or notify_enabled:
			self._dispatch_plugin_notifiers(
				'scan_complete',
				title,
				message,
				{'total_apps': total_apps, 'scan_time': scan_time},
			)
