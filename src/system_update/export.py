"""Scan result export — JSON, CSV, HTML, XML, Markdown, and diff formats.

Each exporter is a pure function that writes ``output_file`` and returns the
path. They have no UI dependencies so they are trivially testable.

XML is generation-only in this module: no untrusted XML input is parsed here.
If XML import support is added later, use ``defusedxml`` and a file-size cap.
"""

from __future__ import annotations

import csv
import json
from datetime import datetime
from typing import Dict, Iterable, List, Optional

from system_update.models import AppInfo, UpdateStatus
from system_update.utils import display_source

_SEVERITIES = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')


# ═══════════════════════════════════════════════════════════════════════════════
# STATISTICS HELPERS
# ═══════════════════════════════════════════════════════════════════════════════


def get_export_stats(apps: List[AppInfo]) -> Dict:
	"""Tally update-status counts and per-source counts."""
	source_counts: Dict[str, int] = {}
	for app in apps:
		source = display_source(app.source)
		source_counts[source] = source_counts.get(source, 0) + 1

	return {
		'total': len(apps),
		'up_to_date': sum(1 for a in apps if a.update_status == UpdateStatus.UP_TO_DATE),
		'update_available': sum(
			1
			for a in apps
			if a.update_status
			in (UpdateStatus.UPDATE_AVAILABLE, UpdateStatus.SECURITY_UPDATE_AVAILABLE)
		),
		'vulnerable': sum(1 for a in apps if a.update_status == UpdateStatus.VULNERABLE),
		'unknown': sum(1 for a in apps if a.update_status == UpdateStatus.UNKNOWN),
		'error': sum(1 for a in apps if a.update_status == UpdateStatus.ERROR),
		'security_vulns': sum(len(a.security_findings) for a in apps),
		'source_counts': source_counts,
	}


def count_by_severity(apps: Iterable[AppInfo]) -> Dict[str, int]:
	"""Count vulnerability findings across ``apps`` bucketed by severity."""
	counts = {sev.lower(): 0 for sev in _SEVERITIES}
	for app in apps:
		for finding in app.security_findings:
			sev = finding.get('severity', 'UNKNOWN')
			key = sev.lower()
			if key in counts:
				counts[key] += 1
	return counts


def security_summary(apps: List[AppInfo]) -> Dict:
	"""Aggregate total vulns, affected packages, and per-severity counts."""
	sev = count_by_severity(apps)
	return {
		'total_vulns': sum(len(a.security_findings) for a in apps),
		'packages_affected': sum(1 for a in apps if a.security_findings),
		**sev,
	}


def _xml_escape(text: str) -> str:
	"""Escape the five XML special characters."""
	return (
		(text or '')
		.replace('&', '&amp;')
		.replace('<', '&lt;')
		.replace('>', '&gt;')
		.replace('"', '&quot;')
		.replace("'", '&apos;')
	)


def resolve_output_file(format_type: str, output_file: Optional[str] = None) -> str:
	"""Generate a timestamped default filename when none is supplied."""
	if output_file:
		return output_file
	timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
	ext_map = {'markdown': 'md'}
	ext = ext_map.get(format_type, format_type)
	return f'system_update_{timestamp}.{ext}'


# ═══════════════════════════════════════════════════════════════════════════════
# EXPORTERS
# ═══════════════════════════════════════════════════════════════════════════════


def export_json(apps: List[AppInfo], output_file: str) -> str:
	"""Write a fully-structured JSON report."""
	stats = get_export_stats(apps)
	sec = security_summary(apps)

	data = {
		'scan_time': datetime.now().isoformat(),
		'summary': {
			'total_apps': len(apps),
			'up_to_date': stats['up_to_date'],
			'update_available': stats['update_available'],
			'vulnerable': stats['vulnerable'],
			'unknown': stats['unknown'],
		},
		'security_summary': sec,
		'sources': stats['source_counts'],
		'apps': [app.to_dict() for app in apps],
	}

	with open(output_file, 'w', encoding='utf-8') as f:
		json.dump(data, f, indent=2)
	return output_file


def export_csv(apps: List[AppInfo], output_file: str) -> str:
	"""Write a CSV report with appended security + sources sections."""
	stats = get_export_stats(apps)
	sev = count_by_severity(apps)
	vuln_apps = [a for a in apps if a.security_findings]

	with open(output_file, 'w', newline='', encoding='utf-8') as f:
		writer = csv.writer(f)
		writer.writerow(['Name', 'Source', 'Version', 'Latest', 'Status'])
		for app in apps:
			writer.writerow(
				[
					app.name,
					display_source(app.source),
					app.version,
					app.latest_version,
					app.update_status.value,
				]
			)

		if vuln_apps:
			writer.writerow([])
			writer.writerow(['Security Vulnerabilities Detected'])
			writer.writerow(['Package', 'Source', 'Version', 'CVE', 'Severity'])
			for app in vuln_apps:
				for finding in app.security_findings:
					writer.writerow(
						[
							app.name,
							display_source(app.source),
							app.version,
							finding.get('cve', 'N/A'),
							finding.get('severity', 'UNKNOWN'),
						]
					)

		if any(sev.values()):
			writer.writerow([])
			writer.writerow(['Security Summary'])
			writer.writerow(['Critical', sev['critical']])
			writer.writerow(['High', sev['high']])
			writer.writerow(['Medium', sev['medium']])
			writer.writerow(['Low', sev['low']])

		writer.writerow([])
		writer.writerow(['Sources'])
		for src, cnt in sorted(stats['source_counts'].items()):
			writer.writerow([src, cnt])

	return output_file


_HTML_STATUS_CLASS = {
	UpdateStatus.UP_TO_DATE: 'status-up-to-date',
	UpdateStatus.UPDATE_AVAILABLE: 'status-update',
	UpdateStatus.SECURITY_UPDATE_AVAILABLE: 'status-update',
	UpdateStatus.VULNERABLE: 'status-vulnerable',
	UpdateStatus.UNKNOWN: 'status-unknown',
	UpdateStatus.ERROR: 'status-error',
}


_HTML_STYLE_BLOCK = """
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
        h1 { color: #333; border-bottom: 2px solid #0066cc; padding-bottom: 10px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }
        .stat { background: white; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }
        .stat-value { font-size: 24px; font-weight: bold; }
        .stat-label { color: #666; font-size: 14px; margin-top: 5px; }
        .up-to-date { color: #28a745; }
        .update-available { color: #ffc107; }
        .vulnerable { color: #dc3545; }
        .unknown { color: #6c757d; }
        table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th { background: #0066cc; color: white; padding: 12px; text-align: left; }
        td { padding: 10px 12px; border-bottom: 1px solid #eee; }
        tr:hover { background: #f8f9fa; }
        .status { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500; }
        .status-up-to-date { background: #d4edda; color: #155724; }
        .status-update { background: #fff3cd; color: #856404; }
        .status-vulnerable { background: #f8d7da; color: #721c24; }
        .status-unknown { background: #e2e3e5; color: #383d41; }
        .status-error { background: #f8d7da; color: #721c24; }
        .footer { margin-top: 20px; color: #666; font-size: 12px; text-align: center; }
"""


def export_html(
	apps: List[AppInfo],
	output_file: str,
	branding: Optional[object] = None,
	template_path: Optional[str] = None,
) -> str:
	"""Write a styled, branded HTML report. Template + branding optional (5.3)."""
	from system_update.report_templates import ReportBranding, render_html

	resolved_branding = branding if isinstance(branding, ReportBranding) else ReportBranding()
	rendered = render_html(apps, branding=resolved_branding, template_path=template_path)
	with open(output_file, 'w', encoding='utf-8') as f:
		f.write(rendered)
	return output_file


# Legacy inline HTML generator retained as fallback / reference.
def _export_html_legacy(apps: List[AppInfo], output_file: str) -> str:
	"""Write a styled HTML report with summary cards and tables."""
	scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
	stats = get_export_stats(apps)
	sec = security_summary(apps)

	html: List[str] = [
		'<!DOCTYPE html>',
		'<html lang="en">',
		'<head>',
		'    <meta charset="UTF-8">',
		'    <meta name="viewport" content="width=device-width, initial-scale=1.0">',
		f'    <title>System Update Report - {scan_time}</title>',
		'    <style>',
		_HTML_STYLE_BLOCK,
		'    </style>',
		'</head>',
		'<body>',
		'    <h1>System Update Report</h1>',
		f'    <p><strong>Generated:</strong> {scan_time}</p>',
		'    <div class="summary">',
		f'        <div class="stat"><div class="stat-value">{stats["total"]}</div><div class="stat-label">Total Packages</div></div>',
		f'        <div class="stat"><div class="stat-value up-to-date">{stats["up_to_date"]}</div><div class="stat-label">Up to Date</div></div>',
		f'        <div class="stat"><div class="stat-value update-available">{stats["update_available"]}</div><div class="stat-label">Updates Available</div></div>',
		f'        <div class="stat"><div class="stat-value vulnerable">{stats["vulnerable"]}</div><div class="stat-label">Vulnerable</div></div>',
		f'        <div class="stat"><div class="stat-value unknown">{stats["unknown"]}</div><div class="stat-label">Unknown</div></div>',
		'    </div>',
		'    <table>',
		'        <thead>',
		'            <tr>',
		'                <th>Package</th><th>Source</th><th>Current Version</th><th>Latest Version</th><th>Status</th>',
		'            </tr>',
		'        </thead>',
		'        <tbody>',
	]

	for app in apps:
		status_class = _HTML_STATUS_CLASS.get(app.update_status, 'status-unknown')
		status_text = (
			app.status_display.split(' ')[0]
			if ' ' in app.status_display
			else app.update_status.value
		)
		html.append(
			f'            <tr>'
			f'<td><strong>{app.name}</strong></td>'
			f'<td>{display_source(app.source)}</td>'
			f'<td>{app.version or "-"}</td>'
			f'<td>{app.latest_version or "-"}</td>'
			f'<td><span class="status {status_class}">{status_text}</span></td>'
			f'</tr>'
		)

	html.extend(['        </tbody>', '    </table>'])

	vuln_apps = [app for app in apps if app.security_findings]
	if vuln_apps or stats['vulnerable'] > 0:
		html.extend(
			[
				'',
				'    <h2>🔥 Security Vulnerabilities Detected</h2>',
				'    <table>',
				'        <thead>',
				'            <tr>',
				'                <th>Package</th><th>Source</th><th>Version</th><th>CVE</th><th>Severity</th>',
				'            </tr>',
				'        </thead>',
				'        <tbody>',
			]
		)
		for app in vuln_apps:
			for finding in app.security_findings:
				html.append(
					f'            <tr>'
					f'<td><strong>{app.name}</strong></td>'
					f'<td>{display_source(app.source)}</td>'
					f'<td>{app.version}</td>'
					f'<td>{finding.get("cve", "N/A")}</td>'
					f'<td><span class="status status-vulnerable">{finding.get("severity", "UNKNOWN")}</span></td>'
					f'</tr>'
				)
		html.extend(['        </tbody>', '    </table>'])

	if sec['critical'] or sec['high'] or sec['medium'] or sec['low']:
		html.extend(
			[
				'',
				'    <h2>📈 Security Summary</h2>',
				'    <div class="summary">',
				f'        <div class="stat"><div class="stat-value">{sec["total_vulns"]}</div><div class="stat-label">Total Vulns</div></div>',
				f'        <div class="stat"><div class="stat-value">{sec["packages_affected"]}</div><div class="stat-label">Packages Affected</div></div>',
				f'        <div class="stat"><div class="stat-value">{sec["critical"]}</div><div class="stat-label">Critical</div></div>',
				f'        <div class="stat"><div class="stat-value vulnerable">{sec["high"]}</div><div class="stat-label">High</div></div>',
				f'        <div class="stat"><div class="stat-value update-available">{sec["medium"]}</div><div class="stat-label">Medium</div></div>',
				f'        <div class="stat"><div class="stat-value unknown">{sec["low"]}</div><div class="stat-label">Low</div></div>',
				'    </div>',
			]
		)

	if stats['source_counts']:
		source_parts = [f'{src}:{cnt}' for src, cnt in sorted(stats['source_counts'].items())]
		html.extend(
			[
				'',
				'    <h2>📦 Sources</h2>',
				f'    <p><strong>Sources:</strong> {", ".join(source_parts)}</p>',
			]
		)

	html.extend(
		[
			'    <div class="footer"><p>Generated by System Update CLI</p></div>',
			'</body>',
			'</html>',
		]
	)

	with open(output_file, 'w', encoding='utf-8') as f:
		f.write('\n'.join(html))
	return output_file


def export_xml(apps: List[AppInfo], output_file: str) -> str:
	"""Write an XML report with packages, vulnerabilities, and summaries."""
	scan_time = datetime.now().isoformat()
	stats = get_export_stats(apps)
	sec = security_summary(apps)

	lines: List[str] = ['<?xml version="1.0" encoding="UTF-8"?>', '<system_update>']
	lines.append(f'  <scan_time>{scan_time}</scan_time>')
	lines.append(f'  <total_packages>{len(apps)}</total_packages>')
	lines.append('  <packages>')

	for app in apps:
		lines.append('    <package>')
		lines.append(f'      <name>{_xml_escape(app.name)}</name>')
		lines.append(f'      <source>{_xml_escape(display_source(app.source))}</source>')
		lines.append(f'      <current_version>{_xml_escape(app.version or "-")}</current_version>')
		lines.append(
			f'      <latest_version>{_xml_escape(app.latest_version or "-")}</latest_version>'
		)
		lines.append(f'      <status>{app.update_status.value}</status>')
		if app.app_id:
			lines.append(f'      <app_id>{_xml_escape(app.app_id)}</app_id>')
		if app.security_findings:
			lines.append('      <vulnerabilities>')
			for finding in app.security_findings:
				lines.append('        <vulnerability>')
				lines.append(f'          <cve>{_xml_escape(finding.get("cve", "N/A"))}</cve>')
				lines.append(
					f'          <severity>{_xml_escape(finding.get("severity", "UNKNOWN"))}</severity>'
				)
				lines.append('        </vulnerability>')
			lines.append('      </vulnerabilities>')
		lines.append('    </package>')

	lines.append('  </packages>')

	vuln_apps = [app for app in apps if app.security_findings]
	if vuln_apps or stats['vulnerable'] > 0:
		lines.append('  <security_vulnerabilities>')
		for app in vuln_apps:
			for finding in app.security_findings:
				lines.append('    <vulnerability>')
				lines.append(f'      <package>{_xml_escape(app.name)}</package>')
				lines.append(f'      <source>{_xml_escape(display_source(app.source))}</source>')
				lines.append(f'      <version>{_xml_escape(app.version)}</version>')
				lines.append(f'      <cve>{_xml_escape(finding.get("cve", "N/A"))}</cve>')
				lines.append(
					f'      <severity>{_xml_escape(finding.get("severity", "UNKNOWN"))}</severity>'
				)
				lines.append('    </vulnerability>')
		lines.append('  </security_vulnerabilities>')

	if sec['critical'] or sec['high'] or sec['medium'] or sec['low']:
		lines.append('  <security_summary>')
		lines.append(f'    <total_vulns>{sec["total_vulns"]}</total_vulns>')
		lines.append(f'    <packages_affected>{sec["packages_affected"]}</packages_affected>')
		lines.append(f'    <critical>{sec["critical"]}</critical>')
		lines.append(f'    <high>{sec["high"]}</high>')
		lines.append(f'    <medium>{sec["medium"]}</medium>')
		lines.append(f'    <low>{sec["low"]}</low>')
		lines.append('  </security_summary>')

	if stats['source_counts']:
		lines.append('  <sources>')
		for src, cnt in sorted(stats['source_counts'].items()):
			lines.append(f'    <source name="{_xml_escape(src)}">{cnt}</source>')
		lines.append('  </sources>')

	lines.append('</system_update>')

	with open(output_file, 'w', encoding='utf-8') as f:
		f.write('\n'.join(lines))
	return output_file


_MD_STATUS_ICON = {
	UpdateStatus.UP_TO_DATE: '✅',
	UpdateStatus.UPDATE_AVAILABLE: '🔄',
	UpdateStatus.SECURITY_UPDATE_AVAILABLE: '🔒',
	UpdateStatus.VULNERABLE: '🔥',
	UpdateStatus.UNKNOWN: '❓',
	UpdateStatus.ERROR: '❌',
}


def export_markdown(apps: List[AppInfo], output_file: str) -> str:
	"""Write a GitHub-compatible Markdown report."""
	scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
	stats = get_export_stats(apps)
	sec = security_summary(apps)

	lines: List[str] = [
		'# System Update Report',
		'',
		f'**Generated:** {scan_time}',
		'',
		'## Summary',
		'',
		'| Total | Up to Date | Updates | Vulnerable | Unknown |',
		'|------:|----------:|-------:|----------:|--------:|',
		f'| {stats["total"]} | {stats["up_to_date"]} | {stats["update_available"]} | {stats["vulnerable"]} | {stats["unknown"]} |',
		'',
		'## Packages',
		'',
		'| Package | Source | Version | Latest | Status |',
		'|--------|--------|--------|--------|--------|',
	]

	for app in apps:
		icon = _MD_STATUS_ICON.get(app.update_status, '❓')
		lines.append(
			f'| {app.name} | {display_source(app.source)} | {app.version or "-"} | '
			f'{app.latest_version or "-"} | {icon} {app.update_status.value} |'
		)

	vuln_apps = [a for a in apps if a.security_findings]
	if vuln_apps or stats['vulnerable'] > 0:
		lines.extend(
			[
				'',
				'## 🔥 Security Vulnerabilities Detected',
				'',
				'| Package | Source | Version | CVE | Severity |',
				'|--------|--------|--------|-----|-----------|',
			]
		)
		for app in vuln_apps:
			for finding in app.security_findings:
				lines.append(
					f'| {app.name} | {display_source(app.source)} | {app.version} | '
					f'{finding.get("cve", "N/A")} | {finding.get("severity", "UNKNOWN")} |'
				)

	if sec['critical'] or sec['high'] or sec['medium'] or sec['low']:
		lines.extend(
			[
				'',
				'## 📈 Security Summary',
				'',
				'| Total Vulns | Packages Affected | Critical | High | Medium | Low |',
				'|-------------|-------------------|----------|------|--------|-----|',
				f'| {sec["total_vulns"]} | {sec["packages_affected"]} | {sec["critical"]} | '
				f'{sec["high"]} | {sec["medium"]} | {sec["low"]} |',
			]
		)

	if stats['source_counts']:
		lines.extend(['', '## 📦 Sources', ''])
		for src, cnt in sorted(stats['source_counts'].items()):
			lines.append(f'- {src}: {cnt}')

	with open(output_file, 'w', encoding='utf-8') as f:
		f.write('\n'.join(lines))
	return output_file


def export_diff(apps: List[AppInfo], output_file: str) -> str:
	"""Write a plain-text diff listing updated, vulnerable, and up-to-date packages."""
	scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
	stats = get_export_stats(apps)
	sec = security_summary(apps)

	lines: List[str] = [f'System Update Diff - {scan_time}', '=' * 50, '']

	updated = [a for a in apps if a.has_update]
	vulnerable = [a for a in apps if a.is_vulnerable]
	up_to_date = [a for a in apps if a.update_status == UpdateStatus.UP_TO_DATE]

	if updated:
		lines.append('Updated Packages:')
		lines.append('-' * 30)
		for app in updated:
			lines.append(f'{app.name} ({display_source(app.source)})')
			lines.append(f'  {app.version} -> {app.latest_version}')
			lines.append('')
		lines.append('')

	if vulnerable:
		lines.append('Vulnerable Packages:')
		lines.append('-' * 30)
		for app in vulnerable:
			lines.append(f'{app.name} ({display_source(app.source)})')
			lines.append(f'  Version: {app.version}')
			for finding in app.security_findings:
				lines.append(
					f'  ! {finding.get("severity", "UNKNOWN")}: {finding.get("cve", "N/A")}'
				)
			lines.append('')
		lines.append('')

	if up_to_date:
		lines.append('Up to Date Packages:')
		lines.append('-' * 30)
		for app in up_to_date:
			lines.append(f'  {app.name} ({display_source(app.source)}) v{app.version}')
		lines.append('')

	lines.append(
		f'Summary: {len(updated)} updates, {len(vulnerable)} vulnerable, '
		f'{len(up_to_date)} up to date'
	)

	if sec['critical'] or sec['high'] or sec['medium'] or sec['low']:
		lines.extend(['', 'Security Summary:', '=' * 30])
		lines.append(f'  Total Vulns: {sec["total_vulns"]}')
		lines.append(f'  Packages Affected: {sec["packages_affected"]}')
		lines.append(f'  Critical: {sec["critical"]}')
		lines.append(f'  High: {sec["high"]}')
		lines.append(f'  Medium: {sec["medium"]}')
		lines.append(f'  Low: {sec["low"]}')

	if stats['source_counts']:
		lines.extend(['', 'Sources:', '=' * 30])
		for src, cnt in sorted(stats['source_counts'].items()):
			lines.append(f'  {src}: {cnt}')

	with open(output_file, 'w', encoding='utf-8') as f:
		f.write('\n'.join(lines))
	return output_file


# ═══════════════════════════════════════════════════════════════════════════════
# FORMAT DISPATCHER
# ═══════════════════════════════════════════════════════════════════════════════


_EXPORTERS = {
	'json': export_json,
	'csv': export_csv,
	'html': export_html,
	'xml': export_xml,
	'markdown': export_markdown,
	'md': export_markdown,
	'diff': export_diff,
}


def export(
	apps: List[AppInfo],
	format_type: str,
	output_file: Optional[str] = None,
	branding: Optional[object] = None,
	template_path: Optional[str] = None,
) -> str:
	"""Dispatch to the correct exporter for ``format_type``.

	``branding`` and ``template_path`` are HTML-only (ignored for other formats)
	and implement enhancement section 5.3 (custom templates, logo, branding).
	Returns the written file path. Raises ``ValueError`` for unknown formats.
	"""
	exporter = _EXPORTERS.get(format_type)
	if exporter is None:
		import difflib

		valid = sorted(_EXPORTERS.keys())
		suggestion = difflib.get_close_matches(str(format_type), valid, n=1)
		hint = f' Did you mean: {suggestion[0]!r}?' if suggestion else ''
		raise ValueError(
			f'Unknown export format: {format_type!r}.{hint} '
			f'Valid formats: {", ".join(valid)}.'
		)
	path = resolve_output_file(format_type, output_file)
	if format_type == 'html':
		return export_html(apps, path, branding=branding, template_path=template_path)
	return exporter(apps, path)
