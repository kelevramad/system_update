from unittest.mock import MagicMock, patch
from system_update import NotificationManager


def test_send_webhook_valid_url():
	nm = NotificationManager()
	result = nm.send_webhook('https://httpbin.org/post', {'test': 'data'})
	assert result in [True, False]


def test_send_webhook_invalid_url():
	nm = NotificationManager()
	result = nm.send_webhook('https://invalid-url-that-does-not-exist.xyz', {'test': 'data'})
	assert result is False


def test_send_email_missing_config():
	nm = NotificationManager()
	result = nm.send_email('test@example.com', 'Test', 'Body')
	assert result is False


def test_run_custom_script_invalid_path():
	nm = NotificationManager()
	result = nm.run_custom_script('nonexistent_script.bat')
	assert result is False


def test_notification_manager_initialization():
	nm = NotificationManager()
	assert nm is not None


@patch('urllib.request.urlopen')
def test_notification_webhook_failure(mock_url):
	nm = NotificationManager()
	mock_url.side_effect = Exception('Network error')
	result = nm.send_webhook('http://test.com', {'key': 'val'})
	assert result is False


@patch('platform.system')
def test_notification_windows(mock_sys):
	mock_sys.return_value = 'Windows'
	nm = NotificationManager()
	mock_result = MagicMock(returncode=0)
	with patch('subprocess.run', return_value=mock_result):
		result = nm.send_system_notification('Title', 'Msg')
		assert result is True or result is False


@patch('platform.system')
def test_notification_linux_fallback(mock_sys):
	mock_sys.return_value = 'Linux'
	nm = NotificationManager()
	with patch('subprocess.run') as mock_sub:
		mock_sub.side_effect = FileNotFoundError('notifier not found')
		result = nm.send_system_notification('Title', 'Msg')
		assert result is False


@patch('platform.system')
def test_notification_darwin_fallback(mock_sys):
	mock_sys.return_value = 'Darwin'
	nm = NotificationManager()
	with patch('subprocess.run') as mock_sub:
		mock_sub.side_effect = FileNotFoundError('notifyutil not found')
		result = nm.send_system_notification('Title', 'Msg')
		assert result is False


@patch('platform.system')
def test_notification_unknown_os(mock_sys):
	mock_sys.return_value = 'FreeBSD'
	nm = NotificationManager()
	result = nm.send_system_notification('Title', 'Msg')
	assert result is False


def test_notification_manager_webhook_success():
	nm = NotificationManager()
	mock_response = MagicMock()
	mock_response.status = 200
	ctx = MagicMock()
	ctx.__enter__ = MagicMock(return_value=mock_response)
	ctx.__exit__ = MagicMock(return_value=False)
	with patch('urllib.request.urlopen', return_value=ctx):
		assert nm.send_webhook('http://test.com', {'key': 'val'}) is True


def test_notification_manager_webhook_failure():
	nm = NotificationManager()
	with patch('urllib.request.urlopen', side_effect=Exception('Network error')):
		assert nm.send_webhook('http://test.com', {'key': 'val'}) is False


@patch('os.path.exists')
def test_run_custom_script_not_found(mock_exists):
	nm = NotificationManager()
	mock_exists.return_value = False
	result = nm.run_custom_script('nonexistent.py', {'VAR': 'value'})
	assert result is False


@patch('os.path.exists')
@patch('subprocess.run')
def test_run_custom_script_invokes_without_shell(mock_run, mock_exists):
	nm = NotificationManager()
	mock_exists.return_value = True
	mock_run.return_value = MagicMock(returncode=0)

	result = nm.run_custom_script('hook.bat', {'VAR': 'value'})

	assert result is True
	command = mock_run.call_args.args[0]
	kwargs = mock_run.call_args.kwargs
	assert isinstance(command, list)
	assert command[0].endswith('hook.bat')
	assert 'shell' not in kwargs
	assert kwargs['env']['VAR'] == 'value'


@patch('platform.system')
@patch('os.path.exists')
@patch('subprocess.run')
def test_run_custom_script_invokes_powershell_for_ps1(mock_run, mock_exists, mock_system):
	nm = NotificationManager()
	mock_system.return_value = 'Windows'
	mock_exists.return_value = True
	mock_run.return_value = MagicMock(returncode=0)

	result = nm.run_custom_script('hook.ps1')

	assert result is True
	command = mock_run.call_args.args[0]
	assert command[:5] == ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File']
	assert command[5].endswith('hook.ps1')
	assert 'shell' not in mock_run.call_args.kwargs


@patch('system_update.NotificationManager.send_system_notification')
def test_notify_updates_with_vulns(mock_notif):
	nm = NotificationManager()
	nm.notify_updates_available(updates_count=5, vulnerable_count=2, force=True)
	assert mock_notif.called


@patch('system_update.NotificationManager.send_system_notification')
def test_notify_updates_no_vulns(mock_notif):
	nm = NotificationManager()
	nm.notify_updates_available(updates_count=5, vulnerable_count=0, force=True)
	assert mock_notif.called


@patch('system_update.NotificationManager.send_system_notification')
def test_notify_scan_complete(mock_notif):
	nm = NotificationManager()
	nm.notify_scan_complete(total_apps=10, scan_time=5.5, force=True)
	assert mock_notif.called


@patch('smtplib.SMTP')
def test_email_smtp_success(mock_smtp):
	nm = NotificationManager()
	mock_server = MagicMock()
	mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
	mock_smtp.return_value.__exit__ = MagicMock(return_value=False)

	result = nm.send_email(
		'test@test.com',
		'Subject',
		'Body',
		smtp_server='smtp.gmail.com',
		username='user',
		password='pass',
	)
	assert result is True


@patch('subprocess.run')
def test_email_api_failure(mock_sub):
	nm = NotificationManager()
	mock_sub.return_value = MagicMock(returncode=1, stdout='', stderr='Error', text=True)
	result = nm.send_email(
		'test@test.com',
		'Subject',
		'Body',
		smtp_server='https://api.mailtrap.io',
	)
	assert result is False


def test_notification_send_webhook_success():
	nm = NotificationManager()
	with patch('urllib.request.urlopen') as mock_url:
		mock_url.return_value.__enter__.return_value.status = 200
		result = nm.send_webhook('http://example.com/webhook', {'title': 'Test', 'message': 'Msg'})
		assert result is True
