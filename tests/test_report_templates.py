"""Tests for enhancement 5.3 — Report Templates (HTML templates, logo, branding)."""

from __future__ import annotations

import base64
import tempfile
from datetime import datetime
from pathlib import Path

from system_update.models import AppInfo, UpdateStatus
from system_update.report_templates import (
	DEFAULT_HTML_TEMPLATE,
	ReportBranding,
	load_logo_data_uri,
	load_template,
	render_html,
	resolve_branding,
)


def _sample_apps() -> list:
	return [
		AppInfo(
			name='requests',
			source='pip',
			version='2.31.0',
			latest_version='2.32.0',
			update_status=UpdateStatus.UPDATE_AVAILABLE,
			scan_time=datetime.now(),
		),
		AppInfo(
			name='vulnpkg',
			source='pip',
			version='1.0.0',
			latest_version='1.0.1',
			update_status=UpdateStatus.VULNERABLE,
			scan_time=datetime.now(),
			security_findings=[
				{'cve': 'CVE-2024-0001', 'severity': 'HIGH', 'description': 'RCE'}
			],
		),
	]


def test_resolve_branding_uses_config_defaults():
	settings = {
		'report': {
			'branding': {
				'title': 'Corp Report',
				'company_name': 'Acme Inc',
				'primary_color': '#ff0000',
			},
		},
	}
	branding = resolve_branding(settings, None)
	assert branding.title == 'Corp Report'
	assert branding.company_name == 'Acme Inc'
	assert branding.primary_color == '#ff0000'


def test_resolve_branding_cli_overrides_win():
	settings = {'report': {'branding': {'title': 'Config Title'}}}
	overrides = {'title': 'CLI Title', 'company_name': 'Override Co'}
	branding = resolve_branding(settings, overrides)
	assert branding.title == 'CLI Title'
	assert branding.company_name == 'Override Co'


def test_logo_embeds_as_data_uri():
	# 1-pixel PNG bytes
	png_bytes = base64.b64decode(
		b'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII='
	)
	with tempfile.TemporaryDirectory() as d:
		p = Path(d) / 'logo.png'
		p.write_bytes(png_bytes)
		uri = load_logo_data_uri(str(p))
		assert uri.startswith('data:image/png;base64,')
		assert len(uri) > 30


def test_render_html_contains_branding_and_rows():
	branding = ReportBranding(
		title='Custom Title',
		company_name='Acme',
		primary_color='#abcdef',
		footer_text='My Footer',
	)
	out = render_html(_sample_apps(), branding=branding)
	assert 'Custom Title' in out
	assert 'Acme' in out
	assert '#abcdef' in out
	assert 'My Footer' in out
	assert 'requests' in out
	assert 'vulnpkg' in out
	assert 'CVE-2024-0001' in out


def test_custom_template_path_is_used():
	with tempfile.TemporaryDirectory() as d:
		tpl = Path(d) / 'custom.html'
		tpl.write_text('<h1>{title}</h1><main>{packages_rows}</main>', encoding='utf-8')
		out = render_html(
			_sample_apps(),
			branding=ReportBranding(title='TplTitle'),
			template_path=str(tpl),
		)
		assert out.startswith('<h1>TplTitle</h1>')
		assert 'requests' in out


def test_missing_template_falls_back_to_default():
	text = load_template('/nonexistent/path/report.html')
	assert text == DEFAULT_HTML_TEMPLATE


def test_export_html_uses_branding():
	from system_update.export import export

	branding = ReportBranding(title='HTML Export Test', company_name='TestCo')
	with tempfile.TemporaryDirectory() as d:
		out = Path(d) / 'report.html'
		path = export(_sample_apps(), 'html', str(out), branding=branding)
		content = Path(path).read_text(encoding='utf-8')
		assert 'HTML Export Test' in content
		assert 'TestCo' in content
