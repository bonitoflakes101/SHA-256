"""
ESHA-256 Thesis Test Suite
===========================

Test scripts for Chapter 4: Implementation & Testing

Tests included:
1. test_length_extension.py - Length-extension attack resistance
2. test_avalanche.py - Avalanche effect analysis
3. test_sasca.py - SASCA resistance simulation
4. test_performance.py - Performance benchmarking
5. test_rsa_integration.py - RSA-PSS integration test

Usage:
    cd tests
    python test_length_extension.py
    python test_avalanche.py
    python test_sasca.py
    python test_performance.py
    python test_rsa_integration.py

Or run all tests:
    python -m pytest tests/

Author: ESHA-256 Thesis Project
Date: December 2025
"""

__all__ = [
    'test_length_extension',
    'test_avalanche',
    'test_sasca',
    'test_performance',
    'test_rsa_integration'
]

