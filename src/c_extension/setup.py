"""
ESHA-256 SIMD Extension Build Configuration
============================================

Build the SIMD-optimized C extension for ESHA-256.

Usage:
    python setup.py build_ext --inplace

Or use the build.sh script in the project root.

Author: ESHA-256 Thesis Project
Date: January 2026
"""

import platform
import sys
import os
from setuptools import setup, Extension

# Detect platform and architecture
system = platform.system()
machine = platform.machine()

# Determine if we're on ARM (Apple Silicon, ARM64 Linux) or x86
is_arm = machine in ['aarch64', 'arm64', 'ARM64']
is_x86 = machine in ['x86_64', 'AMD64', 'i386', 'i686']
is_macos = system == 'Darwin'
is_linux = system == 'Linux'
is_windows = system == 'Windows'

print(f"Building for: {system} {machine}")
print(f"  ARM: {is_arm}, x86: {is_x86}")

# Base compiler flags
extra_compile_args = ['-O3', '-Wall']
extra_link_args = []

if is_macos:
    # macOS: Handle universal builds (ARM64 + x86_64)
    # Don't use architecture-specific flags since Xcode builds for both
    # NEON is automatically available on Apple Silicon
    # AVX2 is automatically available on modern Intel Macs
    print("  SIMD: Auto-detect (universal build)")
    extra_compile_args.extend([
        '-DNDEBUG',
        # Let the compiler auto-detect SIMD capabilities
        # The C code uses preprocessor checks for __ARM_NEON and __AVX2__
    ])
    
elif is_linux:
    if is_arm:
        # ARM64 Linux (Raspberry Pi 4, AWS Graviton, etc.)
        print("  SIMD: ARM NEON")
        extra_compile_args.extend([
            '-march=armv8-a',
            '-DNDEBUG',
        ])
    elif is_x86:
        # Intel/AMD x86_64 Linux
        print("  SIMD: Intel AVX2/SSE4.2")
        extra_compile_args.extend([
            '-mavx2',
            '-msse4.2',
            '-DNDEBUG',
        ])
    else:
        print(f"  SIMD: Scalar fallback (unknown architecture: {machine})")
        extra_compile_args.append('-DNDEBUG')
        
elif is_windows:
    # Windows with MSVC
    print("  SIMD: Intel AVX2 (MSVC)")
    extra_compile_args = ['/O2', '/arch:AVX2']
    
else:
    print(f"  SIMD: Scalar fallback (unknown platform: {system})")
    extra_compile_args.append('-DNDEBUG')

# Define the extension module
esha256_simd = Extension(
    'esha256_simd',
    sources=['esha256_simd.c'],
    include_dirs=['.'],
    extra_compile_args=extra_compile_args,
    extra_link_args=extra_link_args,
    language='c',
)

# Setup configuration
setup(
    name='esha256_simd',
    version='1.0.0',
    description='SIMD-optimized message schedule for ESHA-256',
    long_description='''
SIMD-accelerated multi-lane message schedule expansion for ESHA-256.

Supports:
- ARM NEON (Apple Silicon M1/M2/M3, ARM64 Linux)
- Intel AVX2 (Haswell and newer)
- Intel SSE4.2 (older Intel/AMD fallback)
- Scalar (portable fallback)

The multi-lane design naturally maps to 128-bit SIMD registers,
allowing all 4 lanes to be computed in parallel.
''',
    author='ESHA-256 Thesis Project',
    author_email='thesis@example.com',
    ext_modules=[esha256_simd],
    python_requires='>=3.8',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: C',
        'Programming Language :: Python :: 3',
        'Topic :: Security :: Cryptography',
    ],
)
