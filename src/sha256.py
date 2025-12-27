"""
SHA-256 Standard Implementation
================================

This module implements the standard SHA-256 cryptographic hash function
as specified in FIPS 180-4. This serves as the baseline for comparison
with the enhanced ESHA-256 implementation.

"""

import struct
from typing import List


class SHA256:
    """
    Standard SHA-256 implementation following FIPS 180-4 specification.
    
    This is the baseline implementation with no enhancements.
    Used for comparison against ESHA-256.
    """
    
    # Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
    H0 = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]
    
    # Round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
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
    
    def __init__(self):
        """Initialize SHA-256 hasher."""
        self.reset()
    
    def reset(self):
        """Reset the hasher state."""
        self.h = self.H0.copy()
    
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
        """Choice function: (x AND y) XOR (NOT x AND z)."""
        return (x & y) ^ (~x & z)
    
    @staticmethod
    def _maj(x: int, y: int, z: int) -> int:
        """Majority function: (x AND y) XOR (x AND z) XOR (y AND z)."""
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
        """
        Pad message according to SHA-256 specification.
        
        Padding: message || 1 || 0...0 || length (64 bits)
        Result length must be multiple of 512 bits (64 bytes).
        """
        msg_len = len(message)
        message += b'\x80'  # Append bit '1' (and 7 zero bits as one byte)
        
        # Append zero bytes until length ≡ 448 (mod 512) bits = 56 (mod 64) bytes
        message += b'\x00' * ((55 - msg_len) % 64)
        
        # Append original message length as 64-bit big-endian integer
        message += struct.pack('>Q', msg_len * 8)
        
        return message
    
    def _message_schedule(self, block: bytes) -> List[int]:
        """
        Prepare message schedule W[0..63] from 512-bit block.
        
        This is the STANDARD sequential message schedule.
        W[16] depends on W[15], W[14], W[9], W[0]
        W[17] depends on W[16], W[15], W[10], W[1]  <- Sequential dependency!
        
        Args:
            block: 512-bit (64-byte) message block
            
        Returns:
            List of 64 32-bit words
        """
        # Parse block into 16 32-bit big-endian words
        W = list(struct.unpack('>16I', block))
        
        # Extend to 64 words (sequential expansion)
        for t in range(16, 64):
            W.append((self._sigma1(W[t-2]) + W[t-7] + 
                     self._sigma0(W[t-15]) + W[t-16]) & 0xFFFFFFFF)
        
        return W
    
    def _compress(self, W: List[int]) -> None:
        """
        Compression function (64 rounds).
        
        This is the STANDARD compression with no side-channel protection.
        
        Args:
            W: Message schedule (64 32-bit words)
        """
        # Initialize working variables
        a, b, c, d, e, f, g, h = self.h
        
        # 64 rounds
        for t in range(64):
            T1 = (h + self._Sigma1(e) + self._ch(e, f, g) + 
                  self.K[t] + W[t]) & 0xFFFFFFFF
            T2 = (self._Sigma0(a) + self._maj(a, b, c)) & 0xFFFFFFFF
            
            h = g
            g = f
            f = e
            e = (d + T1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (T1 + T2) & 0xFFFFFFFF
        
        # Add compressed chunk to current hash value (Merkle-Damgård construction)
        self.h[0] = (self.h[0] + a) & 0xFFFFFFFF
        self.h[1] = (self.h[1] + b) & 0xFFFFFFFF
        self.h[2] = (self.h[2] + c) & 0xFFFFFFFF
        self.h[3] = (self.h[3] + d) & 0xFFFFFFFF
        self.h[4] = (self.h[4] + e) & 0xFFFFFFFF
        self.h[5] = (self.h[5] + f) & 0xFFFFFFFF
        self.h[6] = (self.h[6] + g) & 0xFFFFFFFF
        self.h[7] = (self.h[7] + h) & 0xFFFFFFFF
    
    def hash(self, message: bytes) -> bytes:
        """
        Compute SHA-256 hash of message.
        
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
            W = self._message_schedule(block)
            self._compress(W)
        
        # Produce final hash value (big-endian)
        return b''.join(struct.pack('>I', h) for h in self.h)
    
    def hexdigest(self, message: bytes) -> str:
        """
        Compute SHA-256 hash and return as hex string.
        
        Args:
            message: Input message
            
        Returns:
            64-character hex string
        """
        return self.hash(message).hex()


# Quick test
if __name__ == "__main__":
    sha = SHA256()
    
    # Test vector 1: empty string
    result = sha.hexdigest(b"")
    expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    print(f"Test 1 (empty): {'PASS' if result == expected else 'FAIL'}")
    print(f"  Got:      {result}")
    print(f"  Expected: {expected}")
    
    # Test vector 2: "abc"
    result = sha.hexdigest(b"abc")
    expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    print(f"\nTest 2 ('abc'): {'PASS' if result == expected else 'FAIL'}")
    print(f"  Got:      {result}")
    print(f"  Expected: {expected}")
    
    # Test vector 3: longer message
    result = sha.hexdigest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    expected = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    print(f"\nTest 3 (long): {'PASS' if result == expected else 'FAIL'}")
    print(f"  Got:      {result}")
    print(f"  Expected: {expected}")