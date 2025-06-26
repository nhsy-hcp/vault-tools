"""Unit tests for data classes (AuditStats, AuditData)."""
import time
import threading
from datetime import datetime

import pytest

from src.namespace_audit.main import AuditStats, AuditData


class TestAuditStats:
    """Test the AuditStats dataclass."""

    def test_initial_stats(self):
        """Test initial statistics values."""
        stats = AuditStats()

        assert stats.processed_count == 0
        assert stats.error_count == 0
        assert stats.start_time is None
        assert stats.end_time is None
        assert stats.duration is None

    def test_start_and_finish_timing(self):
        """Test timing functionality."""
        stats = AuditStats()

        stats.start()
        assert stats.start_time is not None
        assert isinstance(stats.start_time, datetime)

        time.sleep(0.01)  # Small delay to ensure measurable duration

        stats.finish()
        assert stats.end_time is not None
        assert stats.duration is not None
        assert stats.duration > 0

    def test_increment_counters(self):
        """Test counter increment methods."""
        stats = AuditStats()

        stats.increment_processed()
        assert stats.processed_count == 1

        stats.increment_errors()
        assert stats.error_count == 1

        # Test multiple increments
        for _ in range(5):
            stats.increment_processed()
            stats.increment_errors()

        assert stats.processed_count == 6
        assert stats.error_count == 6

    def test_concurrent_statistics_updates(self):
        """Test thread-safe statistics updates under load."""
        stats = AuditStats()
        threads = []

        def update_stats():
            for _ in range(100):
                stats.increment_processed()
                stats.increment_errors()

        # Start multiple threads updating stats
        for _ in range(10):
            thread = threading.Thread(target=update_stats)
            threads.append(thread)
            thread.start()

        # Wait for completion
        for thread in threads:
            thread.join()

        # Verify final counts
        assert stats.processed_count == 1000
        assert stats.error_count == 1000


class TestAuditData:
    """Test the AuditData dataclass."""

    def test_initial_data(self):
        """Test initial data structure."""
        data = AuditData()

        assert isinstance(data.namespaces, dict)
        assert isinstance(data.auth_methods, dict)
        assert isinstance(data.secret_engines, dict)
        assert len(data.namespaces) == 0
        assert len(data.auth_methods) == 0
        assert len(data.secret_engines) == 0

    def test_data_storage_and_retrieval(self):
        """Test storing and retrieving audit data."""
        data = AuditData()
        
        # Add sample namespace data
        data.namespaces['test/'] = {'id': '123', 'custom_metadata': {}}
        data.auth_methods['test/'] = {'userpass/': {'type': 'userpass'}}
        data.secret_engines['test/'] = {'secret/': {'type': 'kv'}}
        
        # Verify data storage
        assert 'test/' in data.namespaces
        assert 'test/' in data.auth_methods
        assert 'test/' in data.secret_engines
        assert data.namespaces['test/']['id'] == '123'
        assert data.auth_methods['test/']['userpass/']['type'] == 'userpass'
        assert data.secret_engines['test/']['secret/']['type'] == 'kv'