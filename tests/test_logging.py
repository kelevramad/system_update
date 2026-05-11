"""Hardening 5.1 — structured logging, secret redaction, context adapter."""

from __future__ import annotations

import logging

import pytest

from system_update.config import (
	SystemConfig,
	_ContextLoggerAdapter,
	_redact,
	_RedactionFilter,
	get_logger,
	setup_logging,
)


# ─── Redaction patterns ──────────────────────────────────────────────────


@pytest.mark.parametrize(
	'raw, expected_marker, forbidden',
	[
		('password=hunter2', 'password=***', 'hunter2'),
		('PASSWORD: s3cret-value', 'PASSWORD: ***', 's3cret-value'),
		('token=ghp_abc123', 'token=***', 'ghp_abc123'),
		('api_key = xyz-1234', 'api_key = ***', 'xyz-1234'),
		('Authorization: Bearer abc.def.ghi', 'Authorization: ***', 'abc.def.ghi'),
		("winrs -p:'topsecret' host", "-p:'***", 'topsecret'),
		('secret=value123 trailing text', 'secret=***', 'value123'),
	],
)
def test_redact_strips_known_secret_patterns(raw, expected_marker, forbidden):
	redacted = _redact(raw)
	assert forbidden not in redacted
	assert expected_marker in redacted


def test_redact_leaves_safe_text_unchanged():
	safe = 'scanned 42 packages in 1.2s'
	assert _redact(safe) == safe


def test_redaction_filter_rewrites_log_record_message():
	record = logging.LogRecord(
		name='test', level=logging.INFO, pathname=__file__, lineno=1,
		msg='password=hunter2 user=alice',
		args=None, exc_info=None,
	)
	flt = _RedactionFilter()
	assert flt.filter(record) is True
	assert 'hunter2' not in record.getMessage()
	assert 'password=***' in record.getMessage()


def test_setup_logging_attaches_redaction_filter_to_every_handler(tmp_path):
	config = SystemConfig()
	config.config_dir = tmp_path
	config.log_file = tmp_path / 'system.log'
	setup_logging(config, debug=True)

	root = logging.getLogger()
	try:
		for handler in root.handlers:
			assert any(isinstance(f, _RedactionFilter) for f in handler.filters), (
				f'Handler {handler!r} is missing the redaction filter'
			)
	finally:
		for handler in root.handlers[:]:
			root.removeHandler(handler)


def test_setup_logging_redacts_secrets_in_emitted_lines(tmp_path):
	config = SystemConfig()
	config.config_dir = tmp_path
	config.log_file = tmp_path / 'system.log'
	setup_logging(config, debug=True)

	logger = logging.getLogger('system_update.test_redaction')
	try:
		logger.info('sending password=hunter2 to api')
	finally:
		for handler in logging.getLogger().handlers[:]:
			handler.flush()
			logging.getLogger().removeHandler(handler)

	text = (tmp_path / 'system.log').read_text(encoding='utf-8')
	assert 'hunter2' not in text
	assert 'password=***' in text


# ─── Context LoggerAdapter ───────────────────────────────────────────────


def test_get_logger_without_context_returns_plain_logger():
	log = get_logger('test_no_context')
	assert isinstance(log, logging.Logger)


def test_get_logger_with_context_returns_adapter():
	log = get_logger('test_with_context', host='alpha', source='winget')
	assert isinstance(log, _ContextLoggerAdapter)


def test_context_logger_adapter_prepends_fields(caplog):
	log = get_logger('system_update.adapter_test', host='alpha', source='winget')
	with caplog.at_level(logging.INFO, logger='system_update.adapter_test'):
		log.info('scan complete')

	rendered = caplog.records[-1].getMessage()
	assert '[host=alpha source=winget]' in rendered
	assert 'scan complete' in rendered
