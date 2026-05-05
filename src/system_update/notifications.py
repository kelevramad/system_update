"""Outbound notification dispatch — Windows toast, email, webhook, script hook."""

from __future__ import annotations

import json
import logging
import os
import platform
import subprocess
import urllib.request
from typing import Dict, Optional

from system_update.config import SystemConfig
from system_update.plugins import PluginRegistry, dispatch_notifiers
from system_update.utils import run_command

logger = logging.getLogger(__name__)


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
		"""POST the message to a REST email API via curl."""
		payload = json.dumps(
			{
				'from': {'email': 'hello@demomailtrap.co', 'name': 'System Update'},
				'to': [{'email': to_address}],
				'subject': subject,
				'text': body,
			}
		).replace('"', '\\"')

		curl_cmd = [
			'curl',
			'-s',
			'-X',
			'POST',
			api_url,
			'-H',
			f'Authorization: Bearer {token}',
			'-H',
			'Content-Type: application/json',
			'-d',
			payload,
		]

		result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=30)
		if result.returncode == 0 and 'success' in result.stdout:
			logger.debug(f'Email API sent to {to_address}')
			return True
		logger.debug(f'Email API failed: {result.stderr or result.stdout}')
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
		"""POST a JSON payload to an arbitrary webhook URL."""
		headers = headers or self.settings.get('webhook_headers', {})
		headers.setdefault('Content-Type', 'application/json')

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
			result = subprocess.run(
				[script_path],
				env=env,
				capture_output=True,
				text=True,
				timeout=30,
				shell=True,
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
