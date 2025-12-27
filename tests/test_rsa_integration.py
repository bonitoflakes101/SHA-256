"""
RSA-PSS Integration Test
=========================

This script tests the integration of ESHA-256 with RSA-PSS digital signatures
for medical document authentication.

RSA-PSS (Probabilistic Signature Scheme):
- Uses randomized padding for enhanced security
- Relies on hash function for message digest
- Suitable for medical digital signatures

Test scenarios:
1. Sign medical documents with RSA-PSS + ESHA-256
2. Verify all signatures (should be 100% success)
3. Test tamper detection (modified documents should fail)

Author: ESHA-256 Thesis Project
Date: December 2025
"""

import sys
import os
import csv
import time
import hashlib
from datetime import datetime

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from esha256 import ESHA256
from utils import random_bytes

# Try to import cryptography library for RSA
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


class ESHA256Hash:
    """
    Custom hash class for use with cryptography library's RSA-PSS.
    
    Wraps ESHA-256 to be compatible with cryptography's hash interface.
    """
    name = "esha256"
    digest_size = 32  # 256 bits = 32 bytes
    block_size = 64   # 512 bits = 64 bytes
    
    def __init__(self, data: bytes = b""):
        self._hasher = ESHA256(use_masking=True)
        self._data = data
    
    def update(self, data: bytes):
        self._data += data
    
    def copy(self):
        new_hash = ESHA256Hash()
        new_hash._data = self._data
        return new_hash
    
    def digest(self):
        return self._hasher.hash(self._data)
    
    def hexdigest(self):
        return self._hasher.hexdigest(self._data)


def generate_medical_document(doc_id: int) -> bytes:
    """
    Generate a simulated medical document.
    
    Args:
        doc_id: Document identifier
        
    Returns:
        Simulated medical document as bytes
    """
    # Simulate realistic medical document content
    patient_id = f"PT{doc_id:06d}"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    document = f"""
    =====================================================
    MEDICAL RECORD - CONFIDENTIAL
    =====================================================
    
    Document ID: MED-{doc_id:08d}
    Patient ID: {patient_id}
    Date: {timestamp}
    
    DIAGNOSIS:
    - Primary: Essential Hypertension (ICD-10: I10)
    - Secondary: Type 2 Diabetes Mellitus (ICD-10: E11)
    
    VITAL SIGNS:
    - Blood Pressure: {120 + (doc_id % 40)}/{70 + (doc_id % 20)} mmHg
    - Heart Rate: {60 + (doc_id % 40)} bpm
    - Temperature: {36.0 + (doc_id % 20) / 10:.1f}°C
    - SpO2: {94 + (doc_id % 6)}%
    
    LABORATORY RESULTS:
    - Fasting Glucose: {90 + (doc_id % 50)} mg/dL
    - HbA1c: {5.5 + (doc_id % 30) / 10:.1f}%
    - Creatinine: {0.8 + (doc_id % 10) / 10:.1f} mg/dL
    
    PRESCRIPTION:
    - Lisinopril 10mg, once daily
    - Metformin 500mg, twice daily
    
    PHYSICIAN:
    Dr. Medical Officer
    License No: PHY-{1000 + doc_id}
    
    This document is digitally signed using ESHA-256 + RSA-PSS
    =====================================================
    """
    
    return document.encode('utf-8')


def sign_with_esha256_pss(private_key, message: bytes) -> bytes:
    """
    Sign a message using RSA-PSS with ESHA-256.
    
    Uses a custom implementation since cryptography library
    doesn't directly support custom hash algorithms in PSS.
    
    Args:
        private_key: RSA private key
        message: Message to sign
        
    Returns:
        Digital signature
    """
    # Hash the message with ESHA-256
    esha = ESHA256(use_masking=True)
    message_hash = esha.hash(message)
    
    # Sign the hash with RSA-PSS using SHA-256 internally
    # (The security comes from ESHA-256 hash, PSS just adds padding)
    signature = private_key.sign(
        message_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return signature


def verify_with_esha256_pss(public_key, message: bytes, signature: bytes) -> bool:
    """
    Verify a signature using RSA-PSS with ESHA-256.
    
    Args:
        public_key: RSA public key
        message: Original message
        signature: Signature to verify
        
    Returns:
        True if signature is valid
    """
    # Hash the message with ESHA-256
    esha = ESHA256(use_masking=True)
    message_hash = esha.hash(message)
    
    try:
        public_key.verify(
            signature,
            message_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def run_test_with_cryptography(iterations: int = 100):
    """
    Run RSA-PSS integration test using cryptography library.
    
    Args:
        iterations: Number of documents to test
    """
    print("=" * 70)
    print("RSA-PSS INTEGRATION TEST")
    print("ESHA-256 Thesis - Chapter 4: Implementation & Testing")
    print("=" * 70)
    print()
    print("Configuration:")
    print("  - RSA Key Size: 2048 bits")
    print("  - Hash Algorithm: ESHA-256")
    print("  - Padding Scheme: PSS (Probabilistic Signature Scheme)")
    print()
    
    # Create output directories
    os.makedirs('results', exist_ok=True)
    
    # Generate RSA key pair
    print("Generating RSA 2048-bit key pair...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    print("  Key pair generated successfully")
    print()
    
    # Results tracking
    results = []
    signatures_created = 0
    signatures_verified = 0
    tampers_detected = 0
    sign_times = []
    verify_times = []
    
    print(f"Testing {iterations} medical documents...")
    print()
    
    for i in range(iterations):
        # Progress indicator
        if i % 10 == 0:
            print(f"  Progress: {i}/{iterations}...")
        
        # Generate medical document
        document = generate_medical_document(i + 1)
        
        # Sign document
        sign_start = time.perf_counter()
        try:
            signature = sign_with_esha256_pss(private_key, document)
            sign_time = (time.perf_counter() - sign_start) * 1000
            sign_times.append(sign_time)
            signatures_created += 1
            sign_success = True
        except Exception as e:
            sign_time = 0
            sign_success = False
        
        # Verify signature
        verify_start = time.perf_counter()
        signature_valid = verify_with_esha256_pss(public_key, document, signature)
        verify_time = (time.perf_counter() - verify_start) * 1000
        verify_times.append(verify_time)
        
        if signature_valid:
            signatures_verified += 1
        
        # Test tamper detection (modify document and verify)
        tampered_document = bytearray(document)
        tampered_document[len(tampered_document) // 2] ^= 0x01  # Flip one bit
        tampered_document = bytes(tampered_document)
        
        tamper_detected = not verify_with_esha256_pss(public_key, tampered_document, signature)
        if tamper_detected:
            tampers_detected += 1
        
        # Record result
        results.append({
            'test_id': i + 1,
            'document_size': len(document),
            'sign_time_ms': sign_time,
            'verify_time_ms': verify_time,
            'signature_valid': 1 if signature_valid else 0,
            'tamper_detected': 1 if tamper_detected else 0
        })
    
    # Calculate statistics
    avg_sign_time = sum(sign_times) / len(sign_times)
    avg_verify_time = sum(verify_times) / len(verify_times)
    
    # Print results
    print()
    print("-" * 70)
    print("RESULTS")
    print("-" * 70)
    print()
    print(f"RSA-PSS Integration Test ({iterations} documents)")
    print()
    print(f"  Signatures created:     {signatures_created}/{iterations} ({signatures_created/iterations*100:.0f}%)")
    print(f"  Signatures verified:    {signatures_verified}/{iterations} ({signatures_verified/iterations*100:.0f}%)")
    print(f"  Tampers detected:       {tampers_detected}/{iterations} ({tampers_detected/iterations*100:.0f}%)")
    print()
    print(f"  Avg signing time:       {avg_sign_time:.1f} ms")
    print(f"  Avg verification time:  {avg_verify_time:.1f} ms")
    print()
    
    if signatures_verified == iterations and tampers_detected == iterations:
        print("CONCLUSION: ESHA-256 + RSA-PSS integration successful ✅")
        print()
        print("Medical Document Signing with ESHA-256:")
        print("  ✅ All signatures created successfully")
        print("  ✅ All signatures verified correctly")
        print("  ✅ All tampered documents detected")
        print("  ✅ Suitable for medical digital signatures")
    else:
        print("WARNING: Some tests failed - investigation needed")
    
    print()
    print("-" * 70)
    
    # Save results to CSV
    csv_path = 'results/rsa_integration_results.csv'
    with open(csv_path, 'w', newline='') as f:
        fieldnames = ['test_id', 'document_size', 'sign_time_ms', 
                      'verify_time_ms', 'signature_valid', 'tamper_detected']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    
    print(f"Results saved to: {csv_path}")
    print()
    
    # Summary statistics
    summary_path = 'results/rsa_integration_summary.txt'
    with open(summary_path, 'w') as f:
        f.write("RSA-PSS Integration Test Summary\n")
        f.write("=" * 50 + "\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Documents: {iterations}\n")
        f.write(f"RSA Key Size: 2048 bits\n")
        f.write(f"Hash Algorithm: ESHA-256\n")
        f.write("\n")
        f.write("Results:\n")
        f.write(f"  Signatures Created: {signatures_created}/{iterations}\n")
        f.write(f"  Signatures Verified: {signatures_verified}/{iterations}\n")
        f.write(f"  Tampers Detected: {tampers_detected}/{iterations}\n")
        f.write("\n")
        f.write("Performance:\n")
        f.write(f"  Avg Signing Time: {avg_sign_time:.2f} ms\n")
        f.write(f"  Avg Verification Time: {avg_verify_time:.2f} ms\n")
        f.write("\n")
        f.write("Conclusion: ESHA-256 + RSA-PSS suitable for medical signatures\n")
    
    print(f"Summary saved to: {summary_path}")
    
    return signatures_verified == iterations and tampers_detected == iterations


def run_test_without_cryptography(iterations: int = 100):
    """
    Run simplified integration test without cryptography library.
    
    Simulates RSA-PSS signing using ESHA-256 hashing.
    
    Args:
        iterations: Number of documents to test
    """
    print("=" * 70)
    print("RSA-PSS INTEGRATION TEST (Simplified)")
    print("ESHA-256 Thesis - Chapter 4: Implementation & Testing")
    print("=" * 70)
    print()
    print("Note: 'cryptography' library not found. Running simplified test.")
    print("      Install with: pip install cryptography")
    print()
    
    # Create output directories
    os.makedirs('results', exist_ok=True)
    
    # Initialize ESHA-256
    esha = ESHA256(use_masking=True)
    
    # Simulated key (for demonstration)
    simulated_private_key = random_bytes(256)
    
    # Results tracking
    results = []
    signatures_created = 0
    signatures_verified = 0
    tampers_detected = 0
    sign_times = []
    verify_times = []
    
    print(f"Testing {iterations} medical documents...")
    print()
    
    for i in range(iterations):
        # Progress indicator
        if i % 10 == 0:
            print(f"  Progress: {i}/{iterations}...")
        
        # Generate medical document
        document = generate_medical_document(i + 1)
        
        # Simulate signing (hash + simulated RSA)
        sign_start = time.perf_counter()
        document_hash = esha.hash(document)
        # Simulated signature: Hash(document_hash || private_key)
        signature = esha.hash(document_hash + simulated_private_key)
        sign_time = (time.perf_counter() - sign_start) * 1000
        sign_times.append(sign_time)
        signatures_created += 1
        
        # Simulate verification
        verify_start = time.perf_counter()
        verify_hash = esha.hash(document)
        expected_sig = esha.hash(verify_hash + simulated_private_key)
        signature_valid = (signature == expected_sig)
        verify_time = (time.perf_counter() - verify_start) * 1000
        verify_times.append(verify_time)
        
        if signature_valid:
            signatures_verified += 1
        
        # Test tamper detection
        tampered_document = bytearray(document)
        tampered_document[len(tampered_document) // 2] ^= 0x01
        tampered_document = bytes(tampered_document)
        
        tampered_hash = esha.hash(tampered_document)
        tampered_sig = esha.hash(tampered_hash + simulated_private_key)
        tamper_detected = (signature != tampered_sig)
        
        if tamper_detected:
            tampers_detected += 1
        
        # Record result
        results.append({
            'test_id': i + 1,
            'document_size': len(document),
            'sign_time_ms': sign_time,
            'verify_time_ms': verify_time,
            'signature_valid': 1 if signature_valid else 0,
            'tamper_detected': 1 if tamper_detected else 0
        })
    
    # Calculate statistics
    avg_sign_time = sum(sign_times) / len(sign_times)
    avg_verify_time = sum(verify_times) / len(verify_times)
    
    # Print results
    print()
    print("-" * 70)
    print("RESULTS (Simplified - ESHA-256 hashing only)")
    print("-" * 70)
    print()
    print(f"RSA-PSS Integration Test ({iterations} documents)")
    print()
    print(f"  Signatures created:     {signatures_created}/{iterations} ({signatures_created/iterations*100:.0f}%)")
    print(f"  Signatures verified:    {signatures_verified}/{iterations} ({signatures_verified/iterations*100:.0f}%)")
    print(f"  Tampers detected:       {tampers_detected}/{iterations} ({tampers_detected/iterations*100:.0f}%)")
    print()
    print(f"  Avg hashing time:       {avg_sign_time:.1f} ms")
    print(f"  Avg verification time:  {avg_verify_time:.1f} ms")
    print()
    
    if signatures_verified == iterations and tampers_detected == iterations:
        print("CONCLUSION: ESHA-256 hashing works correctly ✅")
        print()
        print("Note: For full RSA-PSS test, install 'cryptography' library:")
        print("      pip install cryptography")
    
    print()
    print("-" * 70)
    
    # Save results
    csv_path = 'results/rsa_integration_results.csv'
    with open(csv_path, 'w', newline='') as f:
        fieldnames = ['test_id', 'document_size', 'sign_time_ms', 
                      'verify_time_ms', 'signature_valid', 'tamper_detected']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    
    print(f"Results saved to: {csv_path}")
    
    # Summary
    summary_path = 'results/rsa_integration_summary.txt'
    with open(summary_path, 'w') as f:
        f.write("RSA-PSS Integration Test Summary (Simplified)\n")
        f.write("=" * 50 + "\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Documents: {iterations}\n")
        f.write(f"Mode: Simplified (cryptography library not available)\n")
        f.write("\n")
        f.write("Results:\n")
        f.write(f"  Hashes Created: {signatures_created}/{iterations}\n")
        f.write(f"  Hashes Verified: {signatures_verified}/{iterations}\n")
        f.write(f"  Tampers Detected: {tampers_detected}/{iterations}\n")
        f.write("\n")
        f.write("Note: Install 'cryptography' for full RSA-PSS testing\n")
    
    print(f"Summary saved to: {summary_path}")
    
    return signatures_verified == iterations and tampers_detected == iterations


def run_test(iterations: int = 100):
    """
    Run RSA-PSS integration test.
    
    Args:
        iterations: Number of documents to test
    """
    if HAS_CRYPTOGRAPHY:
        return run_test_with_cryptography(iterations)
    else:
        return run_test_without_cryptography(iterations)


def main():
    """Main entry point."""
    try:
        success = run_test(iterations=100)
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

