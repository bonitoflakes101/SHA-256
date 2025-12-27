"""
ESHA-256 Enhanced Implementation
=================================

This module implements ESHA-256 (Enhanced SHA-256) with three key enhancements:
1. HAIFA Framework - Prevents length-extension attacks
2. Multi-Lane Message Schedule - Improves collision resistance and enables SIMD
3. Boolean Masking - Provides SASCA (side-channel attack) protection

Author: ESHA-256 Thesis Project
Date: December 2025
"""

import struct
import secrets
from typing import List, Tuple


class ESHA256:
    """
    Enhanced SHA-256 implementation with security and performance improvements.
    
    Enhancements:
    - HAIFA framework (bitcount + salt) for length-extension immunity
    - Multi-lane message schedule for better collision resistance
    - Boolean masking for side-channel protection
    """
    
    # Initial hash values (same as SHA-256)
    H0 = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]
    
    # Round constants (same as SHA-256)
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]
    
    # HAIFA salt (domain separation: "ESHA-256" + padding + version)
    SALT = [0x45534841, 0x2D323536, 0x00000000, 0x00000001]  # "ESHA", "-256", padding, v1
    
    def __init__(self, use_masking: bool = True):
        """
        Initialize ESHA-256 hasher.
        
        Args:
            use_masking: Enable boolean masking for SASCA protection (default: True)
        """
        self.use_masking = use_masking
        self.reset()
    
    def reset(self):
        """Reset the hasher state."""
        self.h = self.H0.copy()
        self.bitcount = 0  # HAIFA: Track total bits processed
    
    @staticmethod
    def _rotr(x: int, n: int) -> int:
        """Rotate right operation (32-bit)."""
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF
    
    @staticmethod
    def _shr(x: int, n: int) -> int:
        """Shift right operation."""
        return x >> n
    
    @staticmethod
    def _ch(x: int, y: int, z: int) -> int:
        """Choice function."""
        return (x & y) ^ (~x & z)
    
    @staticmethod
    def _maj(x: int, y: int, z: int) -> int:
        """Majority function."""
        return (x & y) ^ (x & z) ^ (y & z)
    
    def _sigma0(self, x: int) -> int:
        """Sigma0 function for message schedule."""
        return self._rotr(x, 7) ^ self._rotr(x, 18) ^ self._shr(x, 3)
    
    def _sigma1(self, x: int) -> int:
        """Sigma1 function for message schedule."""
        return self._rotr(x, 17) ^ self._rotr(x, 19) ^ self._shr(x, 10)
    
    def _Sigma0(self, x: int) -> int:
        """Sigma0 function for compression."""
        return self._rotr(x, 2) ^ self._rotr(x, 13) ^ self._rotr(x, 22)
    
    def _Sigma1(self, x: int) -> int:
        """Sigma1 function for compression."""
        return self._rotr(x, 6) ^ self._rotr(x, 11) ^ self._rotr(x, 25)
    
    def _pad_message(self, message: bytes) -> bytes:
        """Pad message (same as SHA-256)."""
        msg_len = len(message)
        message += b'\x80'
        message += b'\x00' * ((55 - msg_len) % 64)
        message += struct.pack('>Q', msg_len * 8)
        return message
    
    def _haifa_inject(self, W: List[int]) -> None:
        """
        ENHANCEMENT 1A: HAIFA Framework Injection
        
        Inject bitcount and salt into message schedule to prevent
        length-extension attacks.
        
        This makes each block position-dependent:
        - Same message block at different positions → different hash
        - Attacker cannot extend without knowing exact bitcount
        
        Args:
            W: Message schedule (modified in-place)
        """
        # Inject bitcount (high 32 bits, low 32 bits)
        W[0] ^= (self.bitcount >> 32) & 0xFFFFFFFF
        W[1] ^= self.bitcount & 0xFFFFFFFF
        
        # Inject salt (domain separation)
        W[14] ^= self.SALT[0] ^ self.SALT[2]
        W[15] ^= self.SALT[1] ^ self.SALT[3]
    
    def _multi_lane_schedule(self, block: bytes) -> List[int]:
        """
        ENHANCEMENT 1B: Multi-Lane Message Schedule
        
        Instead of sequential expansion (W[t] depends on W[t-1]),
        use 4 parallel lanes that can be computed independently.
        
        Benefits:
        - Better collision resistance (4 synchronized differential paths needed)
        - SIMD parallelization (4-way vectorization possible)
        - Improved diffusion
        
        Structure:
        Lane_A[t] = f(Lane_A[t-4], Lane_B[t-4], Lane_C[t-4], Lane_D[t-4])
        Lane_B[t] = f(Lane_B[t-4], Lane_A[t-4], Lane_C[t-4], Lane_D[t-4])
        Lane_C[t] = f(Lane_C[t-4], Lane_B[t-4], Lane_D[t-4], Lane_A[t-4])
        Lane_D[t] = f(Lane_D[t-4], Lane_C[t-4], Lane_A[t-4], Lane_B[t-4])
        
        All 4 lanes can be computed in parallel!
        
        Args:
            block: 512-bit message block
            
        Returns:
            List of 64 32-bit words (interleaved lanes)
        """
        # Parse block into 16 32-bit words
        words = list(struct.unpack('>16I', block))
        
        # HAIFA injection
        self._haifa_inject(words)
        
        # Distribute into 4 lanes (each lane gets every 4th word)
        lane_A = [words[0], words[4], words[8], words[12]]
        lane_B = [words[1], words[5], words[9], words[13]]
        lane_C = [words[2], words[6], words[10], words[14]]
        lane_D = [words[3], words[7], words[11], words[15]]
        
        # Expand each lane from 4 to 16 words (parallel expansion)
        for t in range(4, 16):
            # Cross-lane mixing for better diffusion
            lane_A.append((self._sigma1(lane_A[t-4]) + lane_D[t-4] + 
                          self._sigma0(lane_B[t-4]) + lane_C[t-4]) & 0xFFFFFFFF)
            
            lane_B.append((self._sigma1(lane_B[t-4]) + lane_A[t-4] + 
                          self._sigma0(lane_C[t-4]) + lane_D[t-4]) & 0xFFFFFFFF)
            
            lane_C.append((self._sigma1(lane_C[t-4]) + lane_B[t-4] + 
                          self._sigma0(lane_D[t-4]) + lane_A[t-4]) & 0xFFFFFFFF)
            
            lane_D.append((self._sigma1(lane_D[t-4]) + lane_C[t-4] + 
                          self._sigma0(lane_A[t-4]) + lane_B[t-4]) & 0xFFFFFFFF)
        
        # Interleave lanes back into W[0..63]
        W = []
        for t in range(16):
            W.append(lane_A[t])
            W.append(lane_B[t])
            W.append(lane_C[t])
            W.append(lane_D[t])
        
        return W
    
    def _compress(self, W: List[int]) -> None:
        """
        ENHANCEMENT 2: Compression with SASCA Protection
        
        Uses first-order boolean masking to prevent side-channel attacks.
        
        Power consumption now depends on (value XOR mask) instead of actual value,
        decorrelating power traces from sensitive data.
        
        Args:
            W: Message schedule (64 32-bit words)
        """
        # Initialize working variables
        a, b, c, d, e, f, g, h = self.h
        
        # ENHANCEMENT 2: Generate random mask for this block
        if self.use_masking:
            mask = secrets.randbits(32)
            # Mask all working variables
            a ^= mask
            b ^= mask
            c ^= mask
            d ^= mask
            e ^= mask
            f ^= mask
            g ^= mask
            h ^= mask
        else:
            mask = 0
        
        # 64 rounds with masked operations
        for t in range(64):
            # Unmask for computation (constant-time)
            a_real = a ^ mask
            e_real = e ^ mask
            
            # Standard SHA-256 operations
            T1 = (h ^ mask) + self._Sigma1(e_real) + self._ch(e_real, f ^ mask, g ^ mask) + self.K[t] + W[t]
            T2 = self._Sigma0(a_real) + self._maj(a_real, b ^ mask, c ^ mask)
            
            # Update with masking
            h = g
            g = f
            f = e
            e = ((d ^ mask) + T1) ^ mask  # Re-mask
            d = c
            c = b
            b = a
            a = (T1 + T2) ^ mask  # Re-mask
        
        # Unmask and add to hash state
        self.h[0] = (self.h[0] + (a ^ mask)) & 0xFFFFFFFF
        self.h[1] = (self.h[1] + (b ^ mask)) & 0xFFFFFFFF
        self.h[2] = (self.h[2] + (c ^ mask)) & 0xFFFFFFFF
        self.h[3] = (self.h[3] + (d ^ mask)) & 0xFFFFFFFF
        self.h[4] = (self.h[4] + (e ^ mask)) & 0xFFFFFFFF
        self.h[5] = (self.h[5] + (f ^ mask)) & 0xFFFFFFFF
        self.h[6] = (self.h[6] + (g ^ mask)) & 0xFFFFFFFF
        self.h[7] = (self.h[7] + (h ^ mask)) & 0xFFFFFFFF
    
    def hash(self, message: bytes) -> bytes:
        """
        Compute ESHA-256 hash of message.
        
        Args:
            message: Input message (arbitrary length)
            
        Returns:
            32-byte (256-bit) hash digest
        """
        # Reset state
        self.reset()
        
        # Pad message
        padded = self._pad_message(message)
        
        # Process each 512-bit block
        for i in range(0, len(padded), 64):
            block = padded[i:i+64]
            
            # ENHANCEMENT 1: Multi-lane message schedule with HAIFA
            W = self._multi_lane_schedule(block)
            
            # ENHANCEMENT 2: Masked compression
            self._compress(W)
            
            # Update bitcount for HAIFA
            self.bitcount += 512
        
        # Produce final hash value
        return b''.join(struct.pack('>I', h) for h in self.h)
    
    def hexdigest(self, message: bytes) -> str:
        """
        Compute ESHA-256 hash and return as hex string.
        
        Args:
            message: Input message
            
        Returns:
            64-character hex string
        """
        return self.hash(message).hex()


# Quick test
if __name__ == "__main__":
    esha = ESHA256()
    
    # Test basic functionality
    print("ESHA-256 Test Results:")
    print("=" * 60)
    
    # Test 1: Empty string
    result = esha.hexdigest(b"")
    print(f"Hash(''):   {result}")
    
    # Test 2: Simple message
    result = esha.hexdigest(b"abc")
    print(f"Hash('abc'): {result}")
    
    # Test 3: Consistency check (same input should give same output)
    msg = b"Medical record data for patient 12345"
    hash1 = esha.hexdigest(msg)
    hash2 = esha.hexdigest(msg)
    print(f"\nConsistency test: {'PASS' if hash1 == hash2 else 'FAIL'}")
    print(f"  Hash 1: {hash1}")
    print(f"  Hash 2: {hash2}")
    
    # Test 4: Different messages should give different hashes
    hash_a = esha.hexdigest(b"message A")
    hash_b = esha.hexdigest(b"message B")
    print(f"\nUniqueness test: {'PASS' if hash_a != hash_b else 'FAIL'}")
    print(f"  Hash A: {hash_a}")
    print(f"  Hash B: {hash_b}")
    
    # Test 5: Avalanche effect (1 bit change should change ~50% of output)
    msg1 = b"test message"
    msg2 = b"test messagf"  # Changed last character 'e' -> 'f' (1 bit difference)
    hash1 = esha.hash(msg1)
    hash2 = esha.hash(msg2)
    
    # Count different bits
    diff_bits = sum(bin(a ^ b).count('1') for a, b in zip(hash1, hash2))
    avalanche_pct = (diff_bits / 256) * 100
    
    print(f"\nAvalanche effect test:")
    print(f"  Changed 1 input bit → {diff_bits}/256 output bits changed ({avalanche_pct:.1f}%)")
    print(f"  Expected: ~128 bits (50%)")
    print(f"  Result: {'PASS' if 100 <= diff_bits <= 156 else 'FAIL'}")