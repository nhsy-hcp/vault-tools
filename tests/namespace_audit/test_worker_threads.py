"""Tests for worker thread functionality."""
import queue
import threading
from unittest.mock import Mock

import pytest

from src.namespace_audit.main import NamespaceAuditor
from src.common.vault_client import VaultClient


class TestWorkerThreads:
    """Test worker thread functionality."""

    @pytest.fixture
    def auditor_with_mock_traverse(self):
        """Create auditor with mocked traverse method."""
        mock_client = Mock(spec=VaultClient)
        auditor = NamespaceAuditor(mock_client)

        # Mock the traverse method to avoid actual Vault calls
        # The method takes (namespace_path, path_queue) parameters
        auditor._traverse_namespace = Mock(return_value=None)
        
        return auditor

    def test_worker_processes_queue_items(self, auditor_with_mock_traverse):
        """Test that worker processes queue items correctly."""
        test_queue = queue.Queue()
        test_queue.put("namespace1/")
        test_queue.put("namespace2/")
        test_queue.put(None)  # Shutdown signal

        # Start worker in a separate thread
        worker_thread = threading.Thread(
            target=auditor_with_mock_traverse._worker,
            args=(test_queue,)
        )
        worker_thread.start()
        worker_thread.join(timeout=2)  # Give more time for processing

        # Verify traverse was called for each namespace
        assert auditor_with_mock_traverse._traverse_namespace.call_count == 2

    def test_worker_handles_empty_queue(self, auditor_with_mock_traverse):
        """Test worker handles empty queue gracefully."""
        test_queue = queue.Queue()
        test_queue.put(None)  # Immediate shutdown

        worker_thread = threading.Thread(
            target=auditor_with_mock_traverse._worker,
            args=(test_queue,)
        )
        worker_thread.start()
        worker_thread.join(timeout=1)

        # Should not call traverse for empty queue
        auditor_with_mock_traverse._traverse_namespace.assert_not_called()

    def test_worker_handles_timeout(self, auditor_with_mock_traverse):
        """Test worker handles queue timeout gracefully."""
        test_queue = queue.Queue()
        # Don't put anything in queue, should timeout and continue

        worker_thread = threading.Thread(
            target=auditor_with_mock_traverse._worker,
            args=(test_queue,)
        )
        worker_thread.start()
        
        # Put shutdown signal after a delay
        test_queue.put(None)
        worker_thread.join(timeout=2)

        # Should handle timeout gracefully
        assert not worker_thread.is_alive()

    def test_worker_error_handling(self, auditor_with_mock_traverse):
        """Test worker handles errors in traverse method."""
        # Make traverse method raise an exception
        auditor_with_mock_traverse._traverse_namespace.side_effect = Exception("Test error")
        
        test_queue = queue.Queue()
        test_queue.put("error-namespace/")
        test_queue.put(None)  # Shutdown signal

        worker_thread = threading.Thread(
            target=auditor_with_mock_traverse._worker,
            args=(test_queue,)
        )
        worker_thread.start()
        worker_thread.join(timeout=2)

        # Should increment error count when traverse fails
        assert auditor_with_mock_traverse.stats.error_count == 1

    def test_worker_rate_limiting_logic(self, auditor_with_mock_traverse):
        """Test worker applies rate limiting correctly."""
        # Configure rate limiting
        auditor_with_mock_traverse.rate_limit_disable = False
        auditor_with_mock_traverse.rate_limit_batch_size = 2
        auditor_with_mock_traverse.rate_limit_sleep_seconds = 0.01  # Short for testing
        
        test_queue = queue.Queue()
        test_queue.put("namespace1/")
        test_queue.put("namespace2/")  # Should trigger rate limit
        test_queue.put("namespace3/")
        test_queue.put(None)  # Shutdown signal

        worker_thread = threading.Thread(
            target=auditor_with_mock_traverse._worker,
            args=(test_queue,)
        )
        worker_thread.start()
        worker_thread.join(timeout=3)

        # Should process all namespaces despite rate limiting
        assert auditor_with_mock_traverse._traverse_namespace.call_count == 3


class TestWorkerThreadIntegration:
    """Integration tests for worker thread coordination."""

    def test_multiple_workers_coordination(self):
        """Test multiple worker threads working together."""
        mock_client = Mock(spec=VaultClient)
        auditor = NamespaceAuditor(mock_client, worker_threads=2)
        
        # Mock traverse to avoid actual API calls
        processed_namespaces = []
        
        def mock_traverse(namespace_path, path_queue):
            processed_namespaces.append(namespace_path)
            
        auditor._traverse_namespace = mock_traverse
        
        # Create test queue with multiple items
        test_queue = queue.Queue()
        namespaces = [f"namespace{i}/" for i in range(5)]
        for ns in namespaces:
            test_queue.put(ns)
        
        # Add shutdown signals for each worker
        for _ in range(2):
            test_queue.put(None)
        
        # Start multiple workers
        workers = []
        for i in range(2):
            worker = threading.Thread(
                target=auditor._worker,
                args=(test_queue,),
                name=f"Worker-{i}"
            )
            workers.append(worker)
            worker.start()
        
        # Wait for completion
        for worker in workers:
            worker.join(timeout=3)
        
        # Verify all namespaces were processed
        assert len(processed_namespaces) == 5
        assert set(processed_namespaces) == set(namespaces)

    def test_worker_queue_task_done_semantics(self):
        """Test proper queue.task_done() usage."""
        mock_client = Mock(spec=VaultClient)
        auditor = NamespaceAuditor(mock_client)
        
        # Mock traverse to avoid actual API calls
        auditor._traverse_namespace = Mock()
        
        test_queue = queue.Queue()
        test_queue.put("test-namespace/")
        test_queue.put(None)
        
        # Start worker
        worker_thread = threading.Thread(
            target=auditor._worker,
            args=(test_queue,)
        )
        worker_thread.start()
        worker_thread.join(timeout=2)
        
        # Queue should be properly managed
        assert test_queue.empty() or test_queue.qsize() == 0