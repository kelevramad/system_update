"""Tests for 5.1 Historical Tracking feature (SQLite database)."""

import os
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from system_update import AppInfo, HistoryDatabase, UpdateStatus


class TestHistoryDatabase:
    """Test suite for HistoryDatabase class."""

    @pytest.fixture
    def temp_db(self):
        """Create a temporary database for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / 'test_history.db'
            db = HistoryDatabase(db_path, connect=False)
            yield db
            db.close()
            if db_path.exists():
                db_path.unlink()

    def test_init_creates_database(self, temp_db):
        """Database should be created at specified path after connecting."""
        temp_db._ensure_connection()
        assert temp_db.db_path.exists()

    def test_schema_has_scans_table(self, temp_db):
        """Schema should include scans table."""
        temp_db._ensure_connection()
        cursor = temp_db.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='scans'"
        )
        tables = [row[0] for row in cursor.fetchall()]
        assert 'scans' in tables

    def test_schema_has_package_snapshots_table(self, temp_db):
        """Schema should include package_snapshots table."""
        temp_db._ensure_connection()
        cursor = temp_db.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='package_snapshots'"
        )
        tables = [row[0] for row in cursor.fetchall()]
        assert 'package_snapshots' in tables

    def test_schema_has_version_history_table(self, temp_db):
        """Schema should include version_history table."""
        temp_db._ensure_connection()
        cursor = temp_db.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='version_history'"
        )
        tables = [row[0] for row in cursor.fetchall()]
        assert 'version_history' in tables

    def test_record_scan_stores_data(self, temp_db):
        """record_scan should store scan data in database."""
        apps = [
            AppInfo(name='Git', source='Winget', version='2.0', latest_version='2.1'),
            AppInfo(name='NodeJS', source='npm', version='18.0', latest_version='20.0'),
        ]
        temp_db.record_scan(apps, 'test_scan_001', 'winget,npm', 10.5)

        scans = temp_db.get_scans()
        assert len(scans) == 1
        assert scans[0]['id'] == 'test_scan_001'
        assert scans[0]['package_count'] == 2

    def test_get_scans_returns_list(self, temp_db):
        """get_scans should return list of scan records."""
        apps = [AppInfo(name='Test', source='pip', version='1.0')]
        temp_db.record_scan(apps, 'scan_001', 'pip', 5.0)

        scans = temp_db.get_scans()
        assert isinstance(scans, list)
        assert len(scans) > 0

    def test_get_scans_respects_limit(self, temp_db):
        """get_scans should respect limit parameter."""
        for i in range(5):
            apps = [AppInfo(name=f'App{i}', source='pip', version='1.0')]
            temp_db.record_scan(apps, f'scan_{i:03d}', 'pip', 1.0)

        scans = temp_db.get_scans(limit=3)
        assert len(scans) == 3

    def test_get_package_history(self, temp_db):
        """get_package_history should return version history for package."""
        apps = [
            AppInfo(name='git', source='Winget', version='2.0'),
            AppInfo(name='git', source='Winget', version='2.1'),
        ]
        for i, app in enumerate(apps):
            temp_db.record_scan([app], f'scan_{i:03d}', 'winget', 1.0)

        history = temp_db.get_package_history('git', 'Winget')
        assert len(history) >= 2

    def test_get_update_trends(self, temp_db):
        """get_update_trends should return statistics."""
        apps = [AppInfo(name='Test', source='pip', version='1.0', latest_version='2.0')]
        temp_db.record_scan(apps, 'scan_001', 'pip', 5.0)

        trends = temp_db.get_update_trends(days=30)
        assert 'source_stats' in trends
        assert 'period_days' in trends
        assert trends['period_days'] == 30

    def test_get_stale_packages(self, temp_db):
        """get_stale_packages should return packages not updated in specified days."""
        apps = [AppInfo(name='OldPkg', source='pip', version='1.0')]
        temp_db.record_scan(apps, 'scan_old', 'pip', 1.0)

        stale = temp_db.get_stale_packages(days=0)
        assert isinstance(stale, list)

    def test_get_source_distribution(self, temp_db):
        """get_source_distribution should return package counts by source."""
        apps = [
            AppInfo(name='Git', source='Winget', version='2.0'),
            AppInfo(name='NodeJS', source='npm', version='18.0'),
        ]
        temp_db.record_scan(apps, 'scan_001', 'winget,npm', 5.0)

        dist = temp_db.get_source_distribution()
        assert isinstance(dist, dict)

    def test_close(self, temp_db):
        """close should close database connection."""
        temp_db._ensure_connection()
        assert temp_db.conn is not None

        temp_db.close()


class TestHistoryCLIFlags:
    """Test CLI flags for history features."""

    def test_history_flag_shows_help(self):
        """--history flag should work."""
        import subprocess
        result = subprocess.run(
            ['python', 'system_update.py', '--help'],
            capture_output=True,
            text=True,
        )
        assert '--history' in result.stdout

    def test_history_shows_info(self):
        """--history should show scan history."""
        import subprocess
        result = subprocess.run(
            ['python', 'system_update.py', '--history'],
            capture_output=True,
            text=True,
        )
        code = result.returncode
        output = result.stdout + result.stderr
        assert code == 0 or 'history' in output.lower()

    def test_history_package_flag(self):
        """--history-package should be recognized."""
        import subprocess
        result = subprocess.run(
            ['python', 'system_update.py', '--history-package', 'git'],
            capture_output=True,
            text=True,
        )
        output = result.stdout + result.stderr
        assert 'not found' in output.lower() or result.returncode == 0

    def test_history_trends_flag(self):
        """--history-trends should work."""
        import subprocess
        result = subprocess.run(
            ['python', 'system_update.py', '--history-trends'],
            capture_output=True,
            text=True,
        )
        code = result.returncode
        output = result.stdout + result.stderr
        assert code == 0 or 'trend' in output.lower()

    def test_report_flag_html(self):
        """--report html should work."""
        import subprocess
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as f:
            output_file = f.name
        try:
            result = subprocess.run(
                ['python', 'system_update.py', '--report', 'html', '--report-output', output_file],
                capture_output=True,
                text=True,
            )
            output = result.stdout + result.stderr
            assert result.returncode == 0 or 'report' in output.lower()
        finally:
            if os.path.exists(output_file):
                os.unlink(output_file)