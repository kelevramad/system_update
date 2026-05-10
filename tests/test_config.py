import json
import builtins
import logging
from types import SimpleNamespace
from typing import cast
from unittest.mock import patch

import pytest

from system_update.config import SystemConfig


def _as_config(ns: SimpleNamespace) -> SystemConfig:
	"""Cast a duck-typed SimpleNamespace to SystemConfig for setup_logging.

	``setup_logging`` only reads ``config.log_file`` and ``config.config_dir``,
	so a SimpleNamespace with those attributes is sufficient at runtime. The
	cast keeps the type checker quiet without changing test behavior.
	"""
	return cast(SystemConfig, ns)


def _close_root_handlers():
	root_logger = logging.getLogger()
	for handler in root_logger.handlers[:]:
		root_logger.removeHandler(handler)
		handler.close()


def test_log_flag_writes_info_without_console_output(tmp_path, capsys):
	from system_update.config import setup_logging

	config = SimpleNamespace(log_file=tmp_path / 'system.log', config_dir=tmp_path)
	try:
		setup_logging(_as_config(config), enable_log=True)
		logging.getLogger('system_update.security').info("Security check sources: ['npm']")
		for handler in logging.getLogger().handlers:
			handler.flush()

		captured = capsys.readouterr()
		assert 'Security check sources' not in captured.out
		assert 'Security check sources' not in captured.err
		log_content = config.log_file.read_text(encoding='utf-8')
		assert 'System Update execution started:' in log_content
		assert 'Security check sources' in log_content
	finally:
		_close_root_handlers()


def test_logging_divider_precedes_first_log_entry(tmp_path):
	from system_update.config import setup_logging

	config = SimpleNamespace(log_file=tmp_path / 'system.log', config_dir=tmp_path)
	try:
		setup_logging(_as_config(config), enable_log=True)
		logging.getLogger('system_update.test').info('First real log line')
		for handler in logging.getLogger().handlers:
			handler.flush()

		log_content = config.log_file.read_text(encoding='utf-8')
		assert log_content.index('System Update execution started:') < log_content.index(
			'First real log line'
		)
		assert '====================================================================================================' in log_content
	finally:
		_close_root_handlers()


def test_logging_setup_without_records_does_not_write_orphan_divider(tmp_path):
	from system_update.config import setup_logging

	config = SimpleNamespace(log_file=tmp_path / 'system.log', config_dir=tmp_path)
	try:
		setup_logging(_as_config(config), enable_log=True)
		_close_root_handlers()

		setup_logging(_as_config(config), enable_log=True)
		logging.getLogger('system_update.test').info('First real log line')
		for handler in logging.getLogger().handlers:
			handler.flush()

		log_content = config.log_file.read_text(encoding='utf-8')
		assert log_content.count('System Update execution started:') == 1
		assert 'First real log line' in log_content
	finally:
		_close_root_handlers()


def test_debug_flag_echoes_info_to_stderr(tmp_path, capsys):
	from system_update.config import setup_logging

	config = SimpleNamespace(log_file=tmp_path / 'system.log', config_dir=tmp_path)
	try:
		setup_logging(_as_config(config), debug=True, enable_log=True)
		logging.getLogger('system_update.security').info("Security check sources: ['npm']")

		captured = capsys.readouterr()
		assert 'Security check sources' not in captured.out
		assert "INFO: Security check sources: ['npm']" in captured.err
	finally:
		_close_root_handlers()


def test_failed_exec_warning_is_system_log_only(tmp_path, capsys):
	from system_update.config import setup_logging

	config = SimpleNamespace(log_file=tmp_path / 'system.log', config_dir=tmp_path)
	try:
		setup_logging(_as_config(config), enable_log=True)
		logging.getLogger('system_update.utils').warning(
			'[EXEC] Command failed (exit 1): choco upgrade dbeaver -y\nstdout:\ndenied'
		)
		for handler in logging.getLogger().handlers:
			handler.flush()

		captured = capsys.readouterr()
		assert '[EXEC] Command failed' not in captured.out
		assert '[EXEC] Command failed' not in captured.err

		log_content = config.log_file.read_text(encoding='utf-8')
		assert '[EXEC] Command failed' in log_content
		assert 'stdout:' in log_content
		error_content = (config.config_dir / 'errors.log').read_text(encoding='utf-8')
		assert '[EXEC] Command failed' not in error_content
	finally:
		_close_root_handlers()


def test_system_config_migration(tmp_path, monkeypatch):
	from system_update import SystemConfig
	import json

	config_dir = tmp_path / '.system_update'
	config_dir.mkdir()
	config_file = config_dir / 'config.json'

	old_config = {'cache': {'duration_hours': 4, 'enabled': False}}
	with open(config_file, 'w', encoding='utf-8') as f:
		json.dump(old_config, f)

	monkeypatch.setattr(SystemConfig, '__init__', lambda self: None)
	config = SystemConfig()
	config.config_dir = config_dir
	config.config_file = config_file
	config.yaml_config_file = config_dir / 'config.yaml'
	config.yml_config_file = config_dir / 'config.yml'
	config.settings = {
		'version': 1,
		'cache': {'duration_hours': 2, 'enabled': True},
		'performance': {'max_workers': 6, 'timeout_seconds': 45},
		'security': {'severity_threshold': 'medium', 'enabled': True},
	}
	config.load()

	assert config.settings['version'] == 1
	assert config.settings['cache']['duration_hours'] == 4
	assert config.settings['cache']['enabled'] is False


def test_system_config_validation(tmp_path, monkeypatch):
	from system_update import SystemConfig
	import json

	config_dir = tmp_path / '.system_update'
	config_dir.mkdir()
	config_file = config_dir / 'config.json'

	invalid_config = {
		'version': 1,
		'cache': {'duration_hours': -5, 'enabled': 'not_a_bool'},
		'performance': {'max_workers': 0, 'timeout_seconds': -10},
		'security': {'severity_threshold': 'super_critical', 'enabled': 'yes'},
	}
	with open(config_file, 'w', encoding='utf-8') as f:
		json.dump(invalid_config, f)

	monkeypatch.setattr(SystemConfig, '__init__', lambda self: None)
	config = SystemConfig()
	config.config_dir = config_dir
	config.config_file = config_file
	config.yaml_config_file = config_dir / 'config.yaml'
	config.yml_config_file = config_dir / 'config.yml'
	config.settings = {
		'version': 1,
		'cache': {'duration_hours': 2, 'enabled': True},
		'performance': {'max_workers': 6, 'timeout_seconds': 45},
		'security': {'severity_threshold': 'medium', 'enabled': True},
	}
	config.load()

	assert config.settings['cache']['duration_hours'] == 2
	assert config.settings['cache']['enabled'] is True
	assert config.settings['performance']['max_workers'] == 6
	assert config.settings['performance']['timeout_seconds'] == 45
	assert config.settings['security']['severity_threshold'] == 'medium'
	assert config.settings['security']['enabled'] is True


def test_system_config_yaml_support(tmp_path, monkeypatch):
	pytest.importorskip('yaml')
	from system_update import SystemConfig
	import yaml

	config_dir = tmp_path / '.system_update'
	config_dir.mkdir()
	yaml_config_file = config_dir / 'config.yaml'

	yaml_data = {'version': 1, 'cache': {'duration_hours': 10}}
	with open(yaml_config_file, 'w', encoding='utf-8') as f:
		yaml.dump(yaml_data, f)

	monkeypatch.setattr(SystemConfig, '__init__', lambda self: None)
	config = SystemConfig()
	config.config_dir = config_dir
	config.config_file = config_dir / 'config.json'
	config.yaml_config_file = yaml_config_file
	config.yml_config_file = config_dir / 'config.yml'
	config.settings = {
		'version': 1,
		'cache': {'duration_hours': 2, 'enabled': True},
		'performance': {'max_workers': 6, 'timeout_seconds': 45},
		'security': {'severity_threshold': 'medium', 'enabled': True},
	}
	config.load()

	assert config.settings['cache']['duration_hours'] == 10


def test_system_config_yaml_missing_pyyaml_raises_clear_error(tmp_path, monkeypatch):
	from system_update import SystemConfig

	config_dir = tmp_path / '.system_update'
	config_dir.mkdir()
	yaml_config_file = config_dir / 'config.yaml'
	yaml_config_file.write_text('cache:\n  duration_hours: 10\n', encoding='utf-8')

	monkeypatch.setattr(SystemConfig, '__init__', lambda self: None)
	config = SystemConfig()
	config.config_dir = config_dir
	config.config_file = config_dir / 'config.json'
	config.yaml_config_file = yaml_config_file
	config.yml_config_file = config_dir / 'config.yml'
	config.settings = {
		'version': 1,
		'cache': {'duration_hours': 2, 'enabled': True},
		'performance': {'max_workers': 6, 'timeout_seconds': 45},
		'security': {'severity_threshold': 'medium', 'enabled': True},
	}

	real_import = builtins.__import__

	def fake_import(name, *args, **kwargs):
		if name == 'yaml':
			raise ImportError('No module named yaml')
		return real_import(name, *args, **kwargs)

	with patch('builtins.__import__', side_effect=fake_import):
		with pytest.raises(RuntimeError, match='PyYAML is required to load'):
			config.load()


def test_system_config_json_does_not_import_yaml(tmp_path, monkeypatch):
	from system_update import SystemConfig

	config_dir = tmp_path / '.system_update'
	config_dir.mkdir()
	json_config_file = config_dir / 'config.json'
	json_config_file.write_text(
		json.dumps({'version': 1, 'cache': {'duration_hours': 12}}),
		encoding='utf-8',
	)

	monkeypatch.setattr(SystemConfig, '__init__', lambda self: None)
	config = SystemConfig()
	config.config_dir = config_dir
	config.config_file = json_config_file
	config.yaml_config_file = config_dir / 'config.yaml'
	config.yml_config_file = config_dir / 'config.yml'
	config.settings = {
		'version': 1,
		'cache': {'duration_hours': 2, 'enabled': True},
		'performance': {'max_workers': 6, 'timeout_seconds': 45},
		'security': {'severity_threshold': 'medium', 'enabled': True},
	}

	real_import = builtins.__import__

	def fake_import(name, *args, **kwargs):
		if name == 'yaml':
			raise AssertionError('yaml should not be imported when config.json exists')
		return real_import(name, *args, **kwargs)

	with patch('builtins.__import__', side_effect=fake_import):
		config.load()

	assert config.settings['cache']['duration_hours'] == 12


def test_system_config_prefers_json_when_yaml_also_exists(tmp_path, monkeypatch):
	from system_update import SystemConfig

	config_dir = tmp_path / '.system_update'
	config_dir.mkdir()
	json_config_file = config_dir / 'config.json'
	yaml_config_file = config_dir / 'config.yaml'
	json_config_file.write_text(
		json.dumps({'version': 1, 'cache': {'duration_hours': 12}}),
		encoding='utf-8',
	)
	yaml_config_file.write_text('cache:\n  duration_hours: 4\n', encoding='utf-8')

	monkeypatch.setattr(SystemConfig, '__init__', lambda self: None)
	config = SystemConfig()
	config.config_dir = config_dir
	config.config_file = json_config_file
	config.yaml_config_file = yaml_config_file
	config.yml_config_file = config_dir / 'config.yml'
	config.settings = {
		'version': 1,
		'cache': {'duration_hours': 2, 'enabled': True},
		'performance': {'max_workers': 6, 'timeout_seconds': 45},
		'security': {'severity_threshold': 'medium', 'enabled': True},
	}

	config.load()

	assert config.settings['cache']['duration_hours'] == 12


def test_system_config_sources_default(tmp_path, monkeypatch):
	from system_update import SystemConfig

	config_dir = tmp_path / '.system_update'
	config_dir.mkdir()

	monkeypatch.setattr(SystemConfig, '__init__', lambda self: None)
	config = SystemConfig()
	config.config_dir = config_dir
	config.config_file = config_dir / 'config.json'
	config.yaml_config_file = config_dir / 'config.yaml'
	config.yml_config_file = config_dir / 'config.yml'
	config.settings = {
		'version': 1,
		'sources': {
			'winget': True,
			'npm': True,
			'pip': True,
		},
		'cache': {'duration_hours': 2, 'enabled': True},
		'performance': {'max_workers': 6, 'timeout_seconds': 45},
		'security': {'severity_threshold': 'medium', 'enabled': True},
	}
	config.load()

	assert config.settings['sources']['winget'] is True


def test_system_config_security_threshold(tmp_path, monkeypatch):
	from system_update import SystemConfig

	config_dir = tmp_path / '.system_update'
	config_dir.mkdir()

	monkeypatch.setattr(SystemConfig, '__init__', lambda self: None)
	config = SystemConfig()
	config.config_dir = config_dir
	config.config_file = config_dir / 'config.json'
	config.yaml_config_file = config_dir / 'config.yaml'
	config.yml_config_file = config_dir / 'config.yml'
	config.settings = {
		'version': 1,
		'sources': {'winget': True},
		'cache': {'duration_hours': 2, 'enabled': True},
		'performance': {'max_workers': 6, 'timeout_seconds': 45},
		'security': {'severity_threshold': 'medium', 'enabled': True},
	}
	config.load()

	assert 'severity_threshold' in config.settings['security']


def test_system_config_performance_settings(tmp_path, monkeypatch):
	from system_update import SystemConfig

	config_dir = tmp_path / '.system_update'
	config_dir.mkdir()

	monkeypatch.setattr(SystemConfig, '__init__', lambda self: None)
	config = SystemConfig()
	config.config_dir = config_dir
	config.config_file = config_dir / 'config.json'
	config.yaml_config_file = config_dir / 'config.yaml'
	config.yml_config_file = config_dir / 'config.yml'
	config.settings = {
		'version': 1,
		'sources': {'winget': True},
		'cache': {'duration_hours': 2, 'enabled': True},
		'performance': {'max_workers': 6, 'timeout_seconds': 45},
		'security': {'severity_threshold': 'medium', 'enabled': True},
	}
	config.load()

	assert 'max_workers' in config.settings['performance']


def test_system_config_reinit_profile(tmp_path, monkeypatch):
	from system_update import SystemConfig

	with patch('pathlib.Path.home', return_value=tmp_path):
		cfg = SystemConfig()
		cfg.settings = cfg._get_default_settings()
		cfg.reinit('test_profile')
		assert cfg.current_profile == 'test_profile'


def test_system_config_export_profile(tmp_path, monkeypatch):
	from system_update import SystemConfig

	with patch('pathlib.Path.home', return_value=tmp_path):
		cfg = SystemConfig()
		cfg.settings = cfg._get_default_settings()

		output_file = tmp_path / 'exported_profile.json'
		result = cfg.export_profile(str(output_file))
		assert result is True
		assert output_file.exists()


def test_system_config_import_profile(tmp_path, monkeypatch):
	from system_update import SystemConfig

	with patch('pathlib.Path.home', return_value=tmp_path):
		cfg = SystemConfig()
		cfg.settings = cfg._get_default_settings()

		import_file = tmp_path / 'import_profile.json'
		import_data = {
			'profile_name': 'imported',
			'settings': cfg._get_default_settings(),
		}
		import_data['settings']['cache']['duration_hours'] = 5
		with open(import_file, 'w', encoding='utf-8') as f:
			json.dump(import_data, f)

		result = cfg.import_profile(str(import_file))
		assert result is True


def test_system_config_get_default_settings():
	from system_update import SystemConfig

	cfg = SystemConfig()
	settings = cfg._get_default_settings()
	assert 'cache' in settings
	assert 'performance' in settings
	assert 'security' in settings
	assert 'sources' in settings


def test_system_config_validate_settings():
	from system_update import SystemConfig

	cfg = SystemConfig()
	cfg.settings = cfg._get_default_settings()
	result = cfg._validate_config()
	assert result is None or isinstance(result, list)
