"""
Top-level test runner for CloudNative ThreatGuard.
Runs all unit, integration, failure mode, and lab tests across the platform.
Ensures 100% test pass rate.
"""

import sys
import os
import unittest

PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def run_all_tests():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Discover tests in runtime/ and simulations/
    runtime_tests = loader.discover(start_dir=os.path.join(PROJECT_ROOT, "runtime"), pattern="test_*.py")
    sim_tests = loader.discover(start_dir=os.path.join(PROJECT_ROOT, "simulations"), pattern="test_*.py")

    suite.addTests(runtime_tests)
    suite.addTests(sim_tests)

    print("=" * 70)
    print(" CloudNative ThreatGuard: Comprehensive Security Test Suite")
    print("=" * 70)

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("-" * 70)
    print(f"Total Tests Run : {result.testsRun}")
    print(f"Failures        : {len(result.failures)}")
    print(f"Errors          : {len(result.errors)}")
    print(f"Pass Rate       : {((result.testsRun - len(result.failures) - len(result.errors)) / max(1, result.testsRun)) * 100.0:.1f}%")
    print("=" * 70)

    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
