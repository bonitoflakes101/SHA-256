"""
Utility Functions for ESHA-256 Thesis
======================================

Helper functions for cryptographic operations, testing, and analysis.

Author: ESHA-256 Thesis Project
Date: December 2025
"""

import secrets
from typing import List


def hamming_distance(bytes1: bytes, bytes2: bytes) -> int:
    """
    Calculate Hamming distance between two byte sequences.
    
    Returns the number of differing bits.
    
    Args:
        bytes1: First byte sequence
        bytes2: Second byte sequence
        
    Returns:
        Number of differing bits
    """
    if len(bytes1) != len(bytes2):
        raise ValueError("Byte sequences must be same length")
    
    distance = 0
    for b1, b2 in zip(bytes1, bytes2):
        xor = b1 ^ b2
        distance += bin(xor).count('1')
    
    return distance


def flip_random_bit(data: bytes) -> bytes:
    """
    Flip a random bit in the byte sequence.
    
    Args:
        data: Input bytes
        
    Returns:
        Bytes with one random bit flipped
    """
    data_list = bytearray(data)
    
    # Choose random byte and bit position
    byte_pos = secrets.randbelow(len(data_list))
    bit_pos = secrets.randbelow(8)
    
    # Flip the bit
    data_list[byte_pos] ^= (1 << bit_pos)
    
    return bytes(data_list)


def random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes.
    
    Args:
        length: Number of bytes to generate
        
    Returns:
        Random bytes
    """
    return secrets.token_bytes(length)


def format_hex(data: bytes, bytes_per_line: int = 16) -> str:
    """
    Format bytes as hex dump (for display).
    
    Args:
        data: Bytes to format
        bytes_per_line: Number of bytes per line
        
    Returns:
        Formatted hex string
    """
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i+bytes_per_line]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        lines.append(f'{i:04x}: {hex_part}')
    return '\n'.join(lines)


def hamming_weight(value: int) -> int:
    """
    Calculate Hamming weight (number of 1 bits) of an integer.
    
    Used for power consumption simulation.
    
    Args:
        value: Integer value
        
    Returns:
        Number of 1 bits
    """
    return bin(value).count('1')


def simulate_power_consumption(value: int, mask: int = None, noise_stddev: float = 2.0) -> float:
    """
    Simulate power consumption using Hamming weight model.
    
    Power consumption is proportional to the number of bits set to '1'.
    This is the standard model used in side-channel analysis research.
    
    Args:
        value: The data value being processed
        mask: Optional mask for boolean masking (if None, no masking)
        noise_stddev: Standard deviation of Gaussian noise
        
    Returns:
        Simulated power consumption (arbitrary units)
    """
    import random
    
    if mask is not None:
        value = value ^ mask  # Apply mask
    
    # Power proportional to Hamming weight
    power = hamming_weight(value)
    
    # Add Gaussian noise to simulate measurement noise
    noise = random.gauss(0, noise_stddev)
    
    return power + noise


def pearson_correlation(x: List[float], y: List[float]) -> float:
    """
    Calculate Pearson correlation coefficient between two variables.
    
    Used for SASCA analysis: correlation between power traces and data.
    
    Args:
        x: First variable (e.g., power traces)
        y: Second variable (e.g., data values)
        
    Returns:
        Correlation coefficient (-1 to 1)
    """
    if len(x) != len(y):
        raise ValueError("Lists must have same length")
    
    n = len(x)
    
    # Calculate means
    mean_x = sum(x) / n
    mean_y = sum(y) / n
    
    # Calculate covariance and standard deviations
    covariance = sum((x[i] - mean_x) * (y[i] - mean_y) for i in range(n))
    std_x = (sum((x[i] - mean_x) ** 2 for i in range(n))) ** 0.5
    std_y = (sum((y[i] - mean_y) ** 2 for i in range(n))) ** 0.5
    
    if std_x == 0 or std_y == 0:
        return 0.0
    
    return covariance / (std_x * std_y)


def chi_square_test(observed: List[int], expected_mean: float) -> float:
    """
    Chi-square goodness of fit test.
    
    Used to test if observed distribution matches expected (e.g., uniform).
    
    Args:
        observed: Observed frequency counts
        expected_mean: Expected mean for each category
        
    Returns:
        Chi-square statistic
    """
    chi_square = sum(((obs - expected_mean) ** 2) / expected_mean 
                     for obs in observed)
    return chi_square


def xor_bytes(bytes1: bytes, bytes2: bytes) -> bytes:
    """
    XOR two byte sequences.
    
    Args:
        bytes1: First byte sequence
        bytes2: Second byte sequence
        
    Returns:
        XOR result
    """
    if len(bytes1) != len(bytes2):
        raise ValueError("Byte sequences must be same length")
    
    return bytes(b1 ^ b2 for b1, b2 in zip(bytes1, bytes2))


def int_to_bytes(value: int, length: int = 4, byteorder: str = 'big') -> bytes:
    """
    Convert integer to bytes.
    
    Args:
        value: Integer value
        length: Number of bytes
        byteorder: 'big' or 'little'
        
    Returns:
        Byte representation
    """
    return value.to_bytes(length, byteorder=byteorder)


def bytes_to_int(data: bytes, byteorder: str = 'big') -> int:
    """
    Convert bytes to integer.
    
    Args:
        data: Byte sequence
        byteorder: 'big' or 'little'
        
    Returns:
        Integer value
    """
    return int.from_bytes(data, byteorder=byteorder)


# Quick test
if __name__ == "__main__":
    print("Utility Functions Test")
    print("=" * 60)
    
    # Test 1: Hamming distance
    b1 = b'\x00\x00\x00\x00'
    b2 = b'\xff\xff\xff\xff'
    dist = hamming_distance(b1, b2)
    print(f"Hamming distance test: {dist} bits (expected: 32)")
    print(f"  Result: {'PASS' if dist == 32 else 'FAIL'}")
    
    # Test 2: Flip random bit
    original = b'\x00' * 8
    flipped = flip_random_bit(original)
    dist = hamming_distance(original, flipped)
    print(f"\nFlip random bit test: {dist} bit(s) changed (expected: 1)")
    print(f"  Result: {'PASS' if dist == 1 else 'FAIL'}")
    
    # Test 3: Power simulation (unmasked vs masked)
    value = 0xAAAAAAAA  # Alternating bits (16 ones)
    power_unmasked = simulate_power_consumption(value, mask=None, noise_stddev=0)
    mask = 0xFFFFFFFF
    power_masked = simulate_power_consumption(value, mask=mask, noise_stddev=0)
    
    print(f"\nPower simulation test:")
    print(f"  Value: 0x{value:08x} (Hamming weight: {hamming_weight(value)})")
    print(f"  Power (unmasked): {power_unmasked:.1f}")
    print(f"  Value XOR mask: 0x{value^mask:08x} (Hamming weight: {hamming_weight(value^mask)})")
    print(f"  Power (masked): {power_masked:.1f}")
    print(f"  Different: {'PASS' if power_unmasked != power_masked else 'FAIL'}")
    
    # Test 4: Pearson correlation
    x = [1, 2, 3, 4, 5]
    y = [2, 4, 6, 8, 10]  # Perfect positive correlation
    corr = pearson_correlation(x, y)
    print(f"\nPearson correlation test:")
    print(f"  Correlation: {corr:.3f} (expected: ~1.0 for perfect correlation)")
    print(f"  Result: {'PASS' if abs(corr - 1.0) < 0.01 else 'FAIL'}")
    
    print("\nAll utility functions tested!")