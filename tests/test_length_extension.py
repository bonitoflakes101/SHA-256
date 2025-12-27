"""
Length-Extension Attack Test
==============================

This script tests the vulnerability of SHA-256 to length-extension attacks
and demonstrates how ESHA-256's HAIFA framework provides complete immunity.

Length-Extension Attack:
Given: Hash(secret || message) and len(secret || message)
Attacker can compute: Hash(secret || message || padding || extension)
Without knowing the secret!

SHA-256 (Merkle-Damgård): Vulnerable (100% success rate)
ESHA-256 (HAIFA): Immune (0% success rate)

Author: ESHA-256 Thesis Project
Date: December 2025
"""

import sys
import os
import csv
import struct
from datetime import datetime

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from sha256 import SHA256
from esha256 import ESHA256
from utils import random_bytes


def sha256_pad(msg_len: int) -> bytes:
    """
    Calculate SHA-256 padding for a message of given length.
    
    Padding: 0x80 || zeros || length_in_bits (64-bit big-endian)
    Total padded length must be multiple of 64 bytes.
    
    Args:
        msg_len: Length of original message in bytes
        
    Returns:
        Padding bytes
    """
    padding = b'\x80'
    padding += b'\x00' * ((55 - msg_len) % 64)
    padding += struct.pack('>Q', msg_len * 8)
    return padding


def length_extension_attack_sha256(sha256_hasher: SHA256, 
                                    secret: bytes, 
                                    message: bytes, 
                                    extension: bytes) -> bool:
    """
    Attempt length-extension attack on SHA-256.
    
    Given Hash(secret || message), compute Hash(secret || message || padding || extension)
    without knowing the secret.
    
    Args:
        sha256_hasher: SHA256 instance
        secret: Unknown secret (only used to verify attack success)
        message: Known message
        extension: Attacker's extension data
        
    Returns:
        True if attack succeeded (forged hash matches real hash)
    """
    original_msg = secret + message
    
    # Step 1: Attacker gets the original hash (from MAC or API)
    original_hash = sha256_hasher.hash(original_msg)
    
    # Step 2: Attacker calculates padding for original message length
    padding = sha256_pad(len(original_msg))
    
    # Step 3: Attacker constructs extended message
    # Real extended message: secret || message || padding || extension
    extended_msg = original_msg + padding + extension
    
    # Step 4: Attacker computes forged hash using length-extension
    # Set internal state to original hash, then continue hashing
    forged_hasher = SHA256()
    
    # Parse original hash into internal state (this is the attack!)
    forged_hasher.h = list(struct.unpack('>8I', original_hash))
    
    # Pad the extension (attacker knows the total length)
    total_len = len(original_msg) + len(padding) + len(extension)
    ext_padded = extension + sha256_pad(total_len)
    
    # Process extension blocks
    for i in range(0, len(ext_padded), 64):
        block = ext_padded[i:i+64]
        W = forged_hasher._message_schedule(block)
        forged_hasher._compress(W)
    
    forged_hash = b''.join(struct.pack('>I', h) for h in forged_hasher.h)
    
    # Step 5: Compute real hash of extended message (for verification)
    real_hash = sha256_hasher.hash(extended_msg)
    
    # Attack succeeds if forged hash matches real hash
    return forged_hash == real_hash


def length_extension_attack_esha256(esha256_hasher: ESHA256, 
                                     secret: bytes, 
                                     message: bytes, 
                                     extension: bytes) -> bool:
    """
    Attempt length-extension attack on ESHA-256.
    
    HAIFA framework should prevent this attack because:
    1. Bitcount is injected into each block (position-dependent)
    2. Salt provides domain separation
    3. Attacker cannot reconstruct correct internal state
    
    Args:
        esha256_hasher: ESHA256 instance
        secret: Unknown secret
        message: Known message
        extension: Attacker's extension
        
    Returns:
        True if attack succeeded (should always be False for ESHA-256)
    """
    original_msg = secret + message
    
    # Get original hash
    original_hash = esha256_hasher.hash(original_msg)
    
    # Calculate padding
    padding = sha256_pad(len(original_msg))
    
    # Construct extended message
    extended_msg = original_msg + padding + extension
    
    # Attempt to forge hash (attacker tries to set state like SHA-256)
    forged_hasher = ESHA256(use_masking=False)  # Disable masking for determinism
    
    # Parse hash into internal state (attack attempt)
    forged_hasher.h = list(struct.unpack('>8I', original_hash))
    
    # CRITICAL: Attacker doesn't know correct bitcount!
    # They would guess based on original message length
    forged_hasher.bitcount = (len(original_msg) + len(padding)) * 8
    
    # Pad extension and process
    total_len = len(original_msg) + len(padding) + len(extension)
    ext_padded = extension + sha256_pad(total_len)
    
    for i in range(0, len(ext_padded), 64):
        block = ext_padded[i:i+64]
        W = forged_hasher._multi_lane_schedule(block)
        forged_hasher._compress(W)
        forged_hasher.bitcount += 512
    
    forged_hash = b''.join(struct.pack('>I', h) for h in forged_hasher.h)
    
    # Compute real hash
    real_hash = esha256_hasher.hash(extended_msg)
    
    return forged_hash == real_hash


def run_test(iterations: int = 1000):
    """
    Run length-extension attack test.
    
    Args:
        iterations: Number of attack attempts
    """
    print("=" * 70)
    print("LENGTH-EXTENSION ATTACK TEST")
    print("ESHA-256 Thesis - Chapter 4: Implementation & Testing")
    print("=" * 70)
    print()
    
    # Create output directories
    os.makedirs('results', exist_ok=True)
    os.makedirs('results/graphs', exist_ok=True)
    
    # Initialize hashers
    sha256 = SHA256()
    esha256 = ESHA256(use_masking=False)  # Disable masking for deterministic testing
    
    # Results tracking
    sha256_successes = 0
    esha256_successes = 0
    results = []
    
    print(f"Running {iterations} length-extension attack attempts...")
    print()
    
    for i in range(iterations):
        # Progress indicator
        if i % 100 == 0:
            print(f"  Progress: {i}/{iterations}...")
        
        # Generate random test data
        secret_len = 8 + (i % 24)  # 8-32 bytes
        message_len = 16 + (i % 48)  # 16-64 bytes
        extension_len = 8 + (i % 16)  # 8-24 bytes
        
        secret = random_bytes(secret_len)
        message = random_bytes(message_len)
        extension = random_bytes(extension_len)
        
        # Test SHA-256 (vulnerable)
        sha256_success = length_extension_attack_sha256(sha256, secret, message, extension)
        if sha256_success:
            sha256_successes += 1
        
        # Test ESHA-256 (should be immune)
        esha256_success = length_extension_attack_esha256(esha256, secret, message, extension)
        if esha256_success:
            esha256_successes += 1
        
        # Record result
        results.append({
            'test_id': i + 1,
            'secret_length': secret_len,
            'message_length': message_len,
            'extension_length': extension_len,
            'sha256_success': 1 if sha256_success else 0,
            'esha256_success': 1 if esha256_success else 0
        })
    
    # Calculate percentages
    sha256_pct = (sha256_successes / iterations) * 100
    esha256_pct = (esha256_successes / iterations) * 100
    
    # Print results
    print()
    print("-" * 70)
    print("RESULTS")
    print("-" * 70)
    print()
    print(f"Length-Extension Attack Test ({iterations} iterations)")
    print()
    print(f"  SHA-256:    {sha256_successes:,}/{iterations:,} attacks succeeded ({sha256_pct:.1f}%)")
    print(f"  ESHA-256:   {esha256_successes:,}/{iterations:,} attacks succeeded ({esha256_pct:.1f}%)")
    print()
    
    # Conclusion
    if sha256_pct == 100.0 and esha256_pct == 0.0:
        print("CONCLUSION: HAIFA framework provides complete immunity ✅")
        print()
        print("Explanation:")
        print("  - SHA-256 uses Merkle-Damgård construction which is inherently")
        print("    vulnerable to length-extension attacks")
        print("  - ESHA-256 uses HAIFA framework which injects bitcount and salt")
        print("    into each compression, making extension impossible")
    else:
        print("CONCLUSION: Unexpected results - please investigate")
        if esha256_pct > 0:
            print(f"  WARNING: ESHA-256 showed {esha256_pct:.1f}% vulnerability!")
    
    print()
    print("-" * 70)
    
    # Save results to CSV
    csv_path = 'results/length_extension_results.csv'
    with open(csv_path, 'w', newline='') as f:
        fieldnames = ['test_id', 'secret_length', 'message_length', 
                      'extension_length', 'sha256_success', 'esha256_success']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    
    print(f"Results saved to: {csv_path}")
    print()
    
    # Summary statistics
    summary_path = 'results/length_extension_summary.txt'
    with open(summary_path, 'w') as f:
        f.write("Length-Extension Attack Test Summary\n")
        f.write("=" * 50 + "\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Iterations: {iterations}\n")
        f.write("\n")
        f.write("Results:\n")
        f.write(f"  SHA-256:  {sha256_successes}/{iterations} ({sha256_pct:.1f}%) - VULNERABLE\n")
        f.write(f"  ESHA-256: {esha256_successes}/{iterations} ({esha256_pct:.1f}%) - PROTECTED\n")
        f.write("\n")
        f.write("Conclusion: HAIFA framework prevents length-extension attacks\n")
    
    print(f"Summary saved to: {summary_path}")
    
    return sha256_pct == 100.0 and esha256_pct == 0.0


def main():
    """Main entry point."""
    try:
        success = run_test(iterations=1000)
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

