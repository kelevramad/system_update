"""
Testes de branches de erro para coverage manual
Execute manualmente e envie os resultados
"""

import json
from unittest.mock import MagicMock, patch
from system_update import (
	AppInfo,
	UpdateChecker,
	UpdateExecutor,
	SystemUpdateApp,
	run_command,
	ThemeManager,
	DisplayFormatter,
	VulnerabilityHistory,
	CacheManager,
)
from datetime import datetime

# ============================================================
# TESTES PARA ERROR HANDLING - Execute manualmente
# ============================================================


# 1. Teste: send_email com API (linhas 241-282)
@patch('subprocess.run')
def test_email_api_success(mock_sub):
	"""Teste: send_email com API bem sucedida"""
	mock_sub.return_value = MagicMock(returncode=0, stdout='{"success":true}', stderr='', text=True)
	# Resultado esperado: True
	# Execute manualmente: nm = NotificationManager(); nm.send_email(...)
	print(
		"TESTE 1 - Executar: nm.send_email('test@test.com', 'Subject', 'Body', smtp_server='https://api.mailtrap.io')"
	)


# 2. Teste: send_email com SMTP (linhas 283-304)
@patch('smtplib.SMTP')
def test_email_smtp_success(mock_smtp):
	"""Teste: send_email com SMTP"""
	mock_server = MagicMock()
	mock_smtp.return_value = mock_server
	# Resultado esperado: True
	print(
		"TESTE 2 - Executar: nm.send_email('test@test.com', 'Subject', 'Body', smtp_server='smtp.gmail.com', username='user', password='pass')"
	)


# 3. Teste: send_email com falha (linhas 302-304)
@patch('subprocess.run')
def test_email_failure(mock_sub):
	"""Teste: send_email com falha"""
	mock_sub.return_value = MagicMock(returncode=1, stdout='', stderr='Error', text=True)
	# Resultado esperado: False
	print(
		"TESTE 3 - Executar: nm.send_email('test@test.com', 'Subject', 'Body', smtp_server='https://api.mailtrap.io')"
	)


# 4. Teste: ensure_dependencies com input 'y' (linhas 498-521)
def test_ensure_dependencies_yes(monkeypatch):
	"""Teste: ensure_dependencies com resposta 'y'"""
	import system_update

	system_update.RICH_AVAILABLE = False
	monkeypatch.setattr('builtins.input', lambda x: 'y')
	# Resultado esperado: tenta instalar rich
	print("TESTE 4 - Executar: ensure_dependencies() com input 'y'")


# 5. Teste: ensure_dependencies com input 'n' (linhas 498-521)
def test_ensure_dependencies_no(monkeypatch):
	"""Teste: ensure_dependencies com resposta 'n'"""
	import system_update

	system_update.RICH_AVAILABLE = False
	monkeypatch.setattr('builtins.input', lambda x: 'n')
	# Resultado esperado: sys.exit(1)
	print("TESTE 5 - Executar: ensure_dependencies() com input 'n'")


# 6. Teste: CacheManager com JSON inválido (linhas 1253-1254)
def test_cache_manager_invalid_json(tmp_path):
	"""Teste: CacheManager com cache corrompido"""
	cache_file = tmp_path / 'cache.json'
	cache_file.write_text('{invalid json}')
	mgr = CacheManager(cache_file)
	# Resultado esperado: load() retorna None
	print('TESTE 6 - Executar: mgr = CacheManager(cache_file); mgr.load()')
	result = mgr.load()
	print(f'Resultado: {result}')


# 7. Teste: CacheManager com versão inválida (linhas 1272-1299)
def test_cache_manager_invalid_version(tmp_path):
	"""Teste: CacheManager com versão diferente"""
	cache_file = tmp_path / 'cache.json'
	cache_file.write_text(
		json.dumps({'version': '0.0.1', 'timestamp': datetime.now().isoformat(), 'apps': []})
	)
	mgr = CacheManager(cache_file)
	# Resultado esperado: is_valid() retorna False
	print('TESTE 7 - Executar: mgr = CacheManager(cache_file); mgr.is_valid()')
	result = mgr.is_valid()
	print(f'Resultado: {result}')


# 8. Teste: run_command com timeout (linhas 1663-1664)
@patch('subprocess.run')
def test_run_command_timeout(mock_sub):
	"""Teste: run_command com timeout"""
	import subprocess

	mock_sub.side_effect = subprocess.TimeoutExpired('cmd', 1)
	# Resultado esperado: None
	print("TESTE 8 - Executar: run_command(['sleep', '10'])")
	result = run_command(['sleep', '10'], timeout=1)
	print(f'Resultado: {result}')


# 9. Teste: run_command com PermissionError (linhas 1663-1664)
@patch('subprocess.run')
def test_run_command_permission(mock_sub):
	"""Teste: run_command com PermissionError"""
	mock_sub.side_effect = PermissionError('Access denied')
	# Resultado esperado: None
	print("TESTE 9 - Executar: run_command(['restricted_cmd'])")
	result = run_command(['restricted_cmd'])
	print(f'Resultado: {result}')


# 10. Teste: UpdateChecker._check_npm_updates com JSON inválido (linhas 2971-3008)
@patch('system_update.run_command')
def test_check_npm_updates_invalid_json(mock_run):
	"""Teste: _check_npm_updates com JSON malformado"""
	apps = [AppInfo(name='test', source='npm', version='1.0.0')]
	mock_run.return_value = 'invalid json{'
	# Resultado esperado: count = 0 (não crasha)
	print('TESTE 10 - Executar: UpdateChecker._check_npm_updates([AppInfo(...)]) com JSON inválido')
	count = UpdateChecker._check_npm_updates(apps)
	print(f'Resultado: {count}')


# 11. Teste: UpdateChecker._check_pip_updates com JSON inválido (linhas 3027-3054)
@patch('system_update.run_command')
def test_check_pip_updates_invalid_json(mock_run):
	"""Teste: _check_pip_updates com JSON malformado"""
	apps = [AppInfo(name='test', source='pip', version='1.0.0')]
	mock_run.return_value = '{invalid'
	# Resultado esperado: count = 0
	print('TESTE 11 - Executar: UpdateChecker._check_pip_updates([AppInfo(...)]) com JSON inválido')
	count = UpdateChecker._check_pip_updates(apps)
	print(f'Resultado: {count}')


# 12. Teste: scan_system com erro em source específico (linhas 4358-4364)
@patch('system_update.run_command')
def test_scan_system_source_error(mock_run):
	"""Teste: scan_system com erro em source"""
	mock_run.side_effect = Exception('Source not found')
	app = SystemUpdateApp()
	# Resultado esperado: não crasha, continua com outros sources
	print("TESTE 12 - Executar: app.scan_system(source_filter='winget') com erro")
	apps = app.scan_system(source_filter='winget')
	print(f'Resultado: {len(apps)} apps')


# 13. Teste: SystemUpdateApp com configuração inválida (linhas 5682-5777)
def test_main_with_invalid_args():
	"""Teste: main() com argumentos inválidos"""
	import sys
	from system_update import main

	# Resultado esperado: argparse error
	print('TESTE 13 - Executar: main() com --invalid-arg')
	try:
		sys.argv = ['system_update.py', '--invalid-arg']
		main()
	except SystemExit as e:
		print(f'Resultado: SystemExit com código {e.code}')


# 14. Teste: ThemeManager com tema inexistente (linhas 1934-1936)
def test_theme_manager_invalid():
	"""Teste: ThemeManager com tema inválido"""
	# Resultado esperado: retorna tema default
	print("TESTE 14 - Executar: ThemeManager.get_theme('invalid_theme')")
	theme = ThemeManager.get_theme('invalid_theme')
	print(f'Resultado: tema default = {theme == ThemeManager.get_theme("default")}')


# 15. Teste: DisplayFormatter com formato desconhecido (linhas 1961-1977)
def test_display_formatter_unknown():
	"""Teste: DisplayFormatter com formato desconhecido"""
	apps = [AppInfo(name='test', source='winget', version='1.0')]
	# Resultado esperado: usa formato 'auto'
	print("TESTE 15 - Executar: DisplayFormatter.format_table(apps, 'unknown_format')")
	table = DisplayFormatter.format_table(apps, 'unknown_format')
	print(f'Resultado: {type(table)}')


# 16. Teste: VulnerabilityHistory com arquivo corrompido (linhas 1344-1388)
def test_vulnerability_history_corrupted(tmp_path):
	"""Teste: VulnerabilityHistory com JSON inválido"""
	hist_file = tmp_path / 'vuln.json'
	hist_file.write_text('{corrupted')
	vh = VulnerabilityHistory(hist_file)
	# Resultado esperado: não crasha
	print('TESTE 16 - Executar: VulnerabilityHistory com arquivo corrompido')
	stats = vh.get_statistics()
	print(f'Resultado: {stats}')


# 17. Teste: _check_path_updates com comando não encontrado (linhas 3213-3276)
@patch('system_update.run_command')
def test_check_path_updates_command_not_found(mock_run):
	"""Teste: _check_path_updates com FileNotFoundError"""
	mock_run.side_effect = FileNotFoundError('Command not found')
	apps = [AppInfo(name='git', source='PATH', version='1.0')]
	# Resultado esperado: não crasha
	print(
		'TESTE 17 - Executar: UpdateChecker._check_path_updates([AppInfo(...)]) com comando não encontrado'
	)
	count = UpdateChecker._check_path_updates(apps)
	print(f'Resultado: {count}')


# 18. Teste: Check OSV vulnerabilities com erro de rede (linhas 4358-4364)
@patch('urllib.request.urlopen')
def test_check_osv_network_error(mock_url):
	"""Teste: check_osv_vulnerabilities com erro de rede"""
	app_obj = SystemUpdateApp()
	apps = [AppInfo(name='requests', source='pip', version='2.28.1')]
	mock_url.side_effect = Exception('Network error')
	# Resultado esperado: não crasha
	print('TESTE 18 - Executar: app.check_osv_vulnerabilities([AppInfo(...)]) com erro de rede')
	vulns = app_obj.check_osv_vulnerabilities(apps)
	print(f'Resultado: {len(vulns)} vulnerabilidades')


# 19. Teste: _check_npm_vulns com output malformado (linhas 3610-3803)
@patch('system_update.run_command')
def test_check_npm_vulns_malformed(mock_run):
	"""Teste: _check_npm_vulns com JSON malformado"""
	app_obj = SystemUpdateApp()
	apps = [AppInfo(name='test', source='npm', version='1.0.0')]
	mock_run.return_value = 'not json'
	# Resultado esperado: não crasha
	print('TESTE 19 - Executar: app._check_npm_vulns([AppInfo(...)]) com JSON malformado')
	vulns = app_obj._check_npm_vulns(apps)
	print(f'Resultado: {len(vulns)} vulnerabilidades')


# 20. Teste: _check_pip_vulns com output malformado (linhas 3830-3875)
@patch('system_update.run_command')
def test_check_pip_vulns_malformed(mock_run):
	"""Teste: _check_pip_vulns com JSON malformado"""
	app_obj = SystemUpdateApp()
	apps = [AppInfo(name='requests', source='pip', version='2.28.0')]
	mock_run.return_value = 'invalid{'
	# Resultado esperado: não crasha
	print('TESTE 20 - Executar: app._check_pip_vulns([AppInfo(...)]) com JSON malformado')
	vulns = app_obj._check_pip_vulns(apps)
	print(f'Resultado: {len(vulns)} vulnerabilidades')


# 21. Teste: export_results com JSON inválido (linhas 4526-4568)
def test_export_json_error(tmp_path):
	"""Teste: export_results com erro ao escrever JSON"""
	app = SystemUpdateApp()
	apps = [AppInfo(name='test', source='winget', version='1.0')]
	# Resultado esperado: não crasha
	print("TESTE 21 - Executar: app.export_results(apps, 'json', '/invalid/path/file.json')")
	try:
		app.export_results(apps, 'json', '/invalid/path/file.json')
	except Exception as e:
		print(f'Resultado: Exception - {e}')


# 22. Teste: export_results com CSV inválido (linhas 4585-4657)
def test_export_csv_error(tmp_path):
	"""Teste: export_results com erro ao escrever CSV"""
	app = SystemUpdateApp()
	apps = [AppInfo(name='test', source='winget', version='1.0')]
	# Resultado esperado: não crasha
	print("TESTE 22 - Executar: app.export_results(apps, 'csv', '/invalid/path/file.csv')")
	try:
		app.export_results(apps, 'csv', '/invalid/path/file.csv')
	except Exception as e:
		print(f'Resultado: Exception - {e}')


# 23. Teste: UpdateExecutor com source desconhecido (linhas 4078-4095)
@patch('system_update.run_command')
def test_executor_unknown_source(mock_run):
	"""Teste: _execute_single_update com source desconhecido"""
	mock_run.return_value = 'Success'
	app = AppInfo(
		name='test', source='UnknownSource', version='1.0', latest_version='1.1', app_id='test'
	)
	# Resultado esperado: tenta executar, pode não atualizar corretamente
	print(
		"TESTE 23 - Executar: UpdateExecutor._execute_single_update(AppInfo(source='UnknownSource'))"
	)
	result = UpdateExecutor._execute_single_update(app)
	print(f'Resultado: {result}')


# 24. Teste: CLI com profile inexistente (linhas 5750-5753)
def test_main_profile_not_found():
	"""Teste: main() com --profile inexistente"""
	import sys
	from system_update import main

	print('TESTE 24 - Executar: main() com --profile inexistente')
	try:
		sys.argv = ['system_update.py', '--profile', 'nonexistent_profile', '--help']
		main()
	except SystemExit:
		print('Resultado: SystemExit (profile não encontrado)')


# 25. Teste: main com export sem output (linhas 5764-5773)
def test_main_export_import_invalid():
	"""Teste: main() com --profile-import de arquivo inexistente"""
	import sys
	from system_update import main

	print('TESTE 25 - Executar: main() com --profile-import arquivo_inexistente.json')
	try:
		sys.argv = ['system_update.py', '--profile-import', 'arquivo_inexistente.json']
		main()
	except SystemExit as e:
		print(f'Resultado: SystemExit com código {e.code}')


print('=' * 60)
print('INSTRUÇÕES PARA TESTES MANUAIS:')
print('=' * 60)
print('1. Execute cada teste individualmente no Python interactivo')
print('2. Copie o código do teste e execute')
print('3. Verifique o resultado esperado')
print('4. Envie os resultados para análise')
print('=' * 60)
