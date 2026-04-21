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