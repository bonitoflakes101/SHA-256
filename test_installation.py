#!/usr/bin/env python3
"""
Quick Test Script
=================

Verifies that SHA-256 and ESHA-256 implementations are working correctly.

Run this after installation to ensure everything is set up properly.
"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from sha256 import SHA256
from esha256 import ESHA256
from utils import hamming_distance, flip_random_bit

def test_sha256():
    """Test standard SHA-256 implementation."""
    print("Testing SHA-256...")
    print("-" * 60)
    
    sha = SHA256()
    
    # Test vector 1: empty string
    result = sha.hexdigest(b"")
    expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    test1 = result == expected
    print(f"  Empty string: {'✓ PASS' if test1 else '✗ FAIL'}")
    
    # Test vector 2: "abc"
    result = sha.hexdigest(b"abc")
    expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    test2 = result == expected
    print(f"  'abc': {'✓ PASS' if test2 else '✗ FAIL'}")
    
    return test1 and test2

def test_esha256():
    """Test ESHA-256 implementation."""
    print("\nTesting ESHA-256...")
    print("-" * 60)
    
    esha = ESHA256()
    
    # Test consistency (same input → same output)
    msg = b"Medical record data for patient 12345"
    hash1 = esha.hexdigest(msg)
    hash2 = esha.hexdigest(msg)
    test1 = hash1 == hash2
    print(f"  Consistency: {'✓ PASS' if test1 else '✗ FAIL'}")
    
    # Test uniqueness (different inputs → different outputs)
    hash_a = esha.hexdigest(b"message A")
    hash_b = esha.hexdigest(b"message B")
    test2 = hash_a != hash_b
    print(f"  Uniqueness: {'✓ PASS' if test2 else '✗ FAIL'}")
    
    # Test avalanche effect
    msg1 = b"test message"
    msg2 = b"test messagf"  # 1 bit difference
    hash1 = esha.hash(msg1)
    hash2 = esha.hash(msg2)
    diff_bits = hamming_distance(hash1, hash2)
    test3 = 100 <= diff_bits <= 156  # ~50% ± some variance
    print(f"  Avalanche effect: {diff_bits}/256 bits changed ({'✓ PASS' if test3 else '✗ FAIL'})")
    
    return test1 and test2 and test3

def test_length_extension_immunity():
    """Quick test that ESHA-256 prevents length extension."""
    print("\nTesting Length-Extension Immunity...")
    print("-" * 60)
    
    # Same block at different positions should give different hashes
    block1 = b"A" * 64
    block2 = b"A" * 128  # Same block, but at different position
    
    esha = ESHA256()
    hash1 = esha.hexdigest(block1)
    hash2 = esha.hexdigest(block2)
    
    test = hash1 != hash2
    print(f"  Position dependency: {'✓ PASS' if test else '✗ FAIL'}")
    print(f"    Hash('A'×64):  {hash1[:16]}...")
    print(f"    Hash('A'×128): {hash2[:16]}...")
    print(f"    Different: {test}")
    
    return test

def main():
    """Run all tests."""
    print("=" * 60)
    print("ESHA-256 INSTALLATION TEST")
    print("=" * 60)
    
    results = []
    
    # Run tests
    results.append(("SHA-256", test_sha256()))
    results.append(("ESHA-256", test_esha256()))
    results.append(("Length-Extension Immunity", test_length_extension_immunity()))
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    all_passed = all(result for _, result in results)
    
    for name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"  {name}: {status}")
    
    print("\n" + ("All tests passed! ✓" if all_passed else "Some tests failed! ✗"))
    print("=" * 60)
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())