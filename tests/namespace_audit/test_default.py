"""
Namespace Audit Test Suite - Compatibility Layer

This file provides backward compatibility for any CI/CD systems that reference 
'test_default.py'. The actual tests have been refactored into focused modules:

- test_data_classes.py      (6 tests)  - AuditStats and AuditData unit tests
- test_auditor_core.py      (11 tests) - Core NamespaceAuditor functionality  
- test_namespace_traversal.py (7 tests) - Namespace API interaction tests
- test_worker_threads.py    (7 tests)  - Threading and concurrency tests
- test_integration_simple.py (7 tests) - Integration tests

Total: 38 comprehensive tests with better organization and no hanging issues.

To run all namespace audit tests: pytest tests/namespace_audit/ -v
"""

import pytest

# Import all the modular test classes to maintain compatibility
from .test_data_classes import TestAuditStats, TestAuditData
from .test_auditor_core import (
    TestNamespaceAuditorInitialization,
    TestVaultConnectionHandling, 
    TestRateLimiting,
    TestAuditSummaryLogging,
    TestReportGeneration
)
from .test_namespace_traversal import (
    TestNamespaceDataFetching,
    TestNamespacePathProcessing
)
from .test_worker_threads import (
    TestWorkerThreads,
    TestWorkerThreadIntegration
)
from .test_integration_simple import (
    TestBasicIntegration,
    TestComponentInteractions
)

# Re-export the test classes for discovery
__all__ = [
    'TestAuditStats',
    'TestAuditData', 
    'TestNamespaceAuditorInitialization',
    'TestVaultConnectionHandling',
    'TestRateLimiting',
    'TestAuditSummaryLogging', 
    'TestReportGeneration',
    'TestNamespaceDataFetching',
    'TestNamespacePathProcessing',
    'TestWorkerThreads',
    'TestWorkerThreadIntegration',
    'TestBasicIntegration',
    'TestComponentInteractions'
]

def test_module_organization():
    """Test that confirms the modular test structure is working."""
    # This test verifies that all test classes are accessible
    assert TestAuditStats is not None
    assert TestAuditData is not None
    assert TestNamespaceAuditorInitialization is not None
    assert TestVaultConnectionHandling is not None
    assert TestRateLimiting is not None
    assert TestAuditSummaryLogging is not None
    assert TestReportGeneration is not None
    assert TestNamespaceDataFetching is not None
    assert TestNamespacePathProcessing is not None
    assert TestWorkerThreads is not None
    assert TestWorkerThreadIntegration is not None
    assert TestBasicIntegration is not None
    assert TestComponentInteractions is not None

def test_legacy_compatibility():
    """Test that ensures backward compatibility is maintained."""
    # This test can be run by CI/CD systems that expect test_default.py to exist
    # It confirms the modular tests are available and working
    import sys
    import importlib
    
    # Verify all modules can be imported
    modules = [
        'tests.namespace_audit.test_data_classes',
        'tests.namespace_audit.test_auditor_core',
        'tests.namespace_audit.test_namespace_traversal', 
        'tests.namespace_audit.test_worker_threads',
        'tests.namespace_audit.test_integration_simple'
    ]
    
    for module_name in modules:
        try:
            importlib.import_module(module_name)
        except ImportError as e:
            pytest.fail(f"Failed to import {module_name}: {e}")

if __name__ == "__main__":
    # If someone runs this file directly, provide helpful information
    print(__doc__)
    print("\nTo run the new modular test suite:")
    print("  pytest tests/namespace_audit/ -v")
    print("\nTo run specific test modules:")
    print("  pytest tests/namespace_audit/test_data_classes.py -v")
    print("  pytest tests/namespace_audit/test_auditor_core.py -v")
    print("  pytest tests/namespace_audit/test_namespace_traversal.py -v")
    print("  pytest tests/namespace_audit/test_worker_threads.py -v") 
    print("  pytest tests/namespace_audit/test_integration_simple.py -v")