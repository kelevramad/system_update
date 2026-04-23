from system_update import SystemConfig


def test_env_vars_specific_shortcuts(monkeypatch, tmp_path):
	config_dir = tmp_path / '.system_update'
	config_dir.mkdir()
	monkeypatch.setattr(SystemConfig, '__init__', lambda self: None)

	monkeypatch.setenv('SYSTEM_UPDATE_SOURCES', 'choco,npm')
	monkeypatch.setenv('SYSTEM_UPDATE_TIMEOUT', '120')
	monkeypatch.setenv('SYSTEM_UPDATE_WORKERS', '10')
	monkeypatch.setenv('SYSTEM_UPDATE_EXCLUDE', 'pkg1,pkg2')
	monkeypatch.setenv('SYSTEM_UPDATE_LOG_LEVEL', 'DEBUG')

	config = SystemConfig()
	config.config_dir = config_dir
	config.config_file = config_dir / 'config.json'
	config.yaml_config_file = config_dir / 'config.yaml'
	config.yml_config_file = config_dir / 'config.yml'
	config.settings = {
		'version': 1,
		'exclude': [],
		'log_level': 'WARNING',
		'performance': {'max_workers': 6, 'timeout_seconds': 45},
		'sources': {'chocolatey': True, 'npm': True, 'winget': True, 'pip': True},
		'cache': {'duration_hours': 2, 'enabled': True},
		'security': {'severity_threshold': 'medium', 'enabled': True},
	}
	config.load()

	assert config.settings['sources']['chocolatey'] is True
	assert config.settings['sources']['npm'] is True
	assert config.settings['sources']['winget'] is False
	assert config.settings['sources']['pip'] is False
	assert config.settings['performance']['timeout_seconds'] == 120
	assert config.settings['performance']['max_workers'] == 10
	assert config.settings['exclude'] == ['pkg1', 'pkg2']
	assert config.settings['log_level'] == 'DEBUG'


def test_env_vars_dynamic_overrides(monkeypatch, tmp_path):
	config_dir = tmp_path / '.system_update'
	config_dir.mkdir()
	monkeypatch.setattr(SystemConfig, '__init__', lambda self: None)

	monkeypatch.setenv('SYSTEM_UPDATE_CACHE__ENABLED', 'false')
	monkeypatch.setenv('SYSTEM_UPDATE_UI__COLOR_SCHEME', 'neon')
	monkeypatch.setenv('SYSTEM_UPDATE_PERFORMANCE__MAX_WORKERS', '15')

	config = SystemConfig()
	config.config_dir = config_dir
	config.config_file = config_dir / 'config.json'
	config.yaml_config_file = config_dir / 'config.yaml'
	config.yml_config_file = config_dir / 'config.yml'
	config.settings = {
		'version': 1,
		'cache': {'duration_hours': 2, 'enabled': True},
		'performance': {'max_workers': 6, 'timeout_seconds': 45},
		'ui': {'color_scheme': 'minimal'},
		'security': {'severity_threshold': 'medium', 'enabled': True},
	}
	config.load()

	assert config.settings['cache']['enabled'] is False
	assert config.settings['ui']['color_scheme'] == 'neon'
	assert config.settings['performance']['max_workers'] == 15


def test_env_vars_type_casting(monkeypatch, tmp_path):
	config_dir = tmp_path / '.system_update'
	config_dir.mkdir()
	monkeypatch.setattr(SystemConfig, '__init__', lambda self: None)

	monkeypatch.setenv('SYSTEM_UPDATE_CACHE__ENABLED', '0')
	monkeypatch.setenv('SYSTEM_UPDATE_PERFORMANCE__TIMEOUT_SECONDS', '300')
	monkeypatch.setenv('SYSTEM_UPDATE_CACHE__DURATION_HOURS', '3.5')
	monkeypatch.setenv('SYSTEM_UPDATE_SECURITY__AUTO_CHECK', 'YES')

	config = SystemConfig()
	config.config_dir = config_dir
	config.config_file = config_dir / 'config.json'
	config.yaml_config_file = config_dir / 'config.yaml'
	config.yml_config_file = config_dir / 'config.yml'
	config.settings = {
		'version': 1,
		'cache': {'duration_hours': 2, 'enabled': True},
		'performance': {'timeout_seconds': 45, 'max_workers': 6},
		'security': {'auto_check': False, 'severity_threshold': 'medium', 'enabled': True},
	}
	config.load()

	assert config.settings['cache']['enabled'] is False
	assert type(config.settings['performance']['timeout_seconds']) is int
	assert config.settings['performance']['timeout_seconds'] == 300
	assert type(config.settings['cache']['duration_hours']) is float
	assert config.settings['cache']['duration_hours'] == 3.5
	assert config.settings['security']['auto_check'] is True
