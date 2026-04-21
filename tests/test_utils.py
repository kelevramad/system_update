import subprocess as sp
from system_update import ThemeManager, SOURCE_ICONS, CommandError, ErrorCategory

def test_all_source_icons():
    for source, expected_icon in SOURCE_ICONS.items():
        assert ThemeManager.get_source_icon(source) == expected_icon
    assert ThemeManager.get_source_icon('WINGET') == '📦'
    assert ThemeManager.get_source_icon('unknown_xyz') == ''

def test_theme_manager_get_source_color():
    assert ThemeManager.get_source_color('winget', 'default') == 'blue'
    assert ThemeManager.get_source_color('npm', 'vibrant') == 'bright_red'

def test_theme_manager_get_source_icon():
    assert ThemeManager.get_source_icon('npm') == '📚'
    assert ThemeManager.get_source_icon('winget') == '📦'

def test_error_category_classification():
    err = CommandError.classify(FileNotFoundError(), 'test-command')
    assert err.category == ErrorCategory.NOT_FOUND
    assert 'not found' in err.message.lower()

    err = CommandError.classify(sp.TimeoutExpired('cmd', 1), 'test-command')
    assert err.category == ErrorCategory.TIMEOUT

    err = CommandError.classify(PermissionError(), 'test-command')
    assert err.category == ErrorCategory.PERMISSION_DENIED

    err = CommandError.classify(ValueError(), 'test-command')
    assert err.category == ErrorCategory.PARSE_ERROR

    err = CommandError.classify(Exception('unknown'), 'test-command')
    assert err.category == ErrorCategory.UNKNOWN

def test_command_error_suggestions():
    from system_update import CommandError, ErrorCategory
    err = CommandError(
        category=ErrorCategory.NOT_FOUND,
        message='Command not found',
        command='test-cmd',
        suggestion='Ensure test-cmd is installed',
    )
    assert err.suggestion != ''
    assert 'install' in err.suggestion.lower()