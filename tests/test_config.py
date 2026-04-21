import pytest
import sys
from pathlib import Path

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