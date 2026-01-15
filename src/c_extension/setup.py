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

# Define the extension modules
esha256_simd = Extension(
    'esha256_simd',
    sources=['esha256_simd.c'],
    include_dirs=['.'],
    extra_compile_args=extra_compile_args,
    extra_link_args=extra_link_args,
    language='c',
)

# SHA-256 baseline in C for fair comparison
sha256_baseline = Extension(
    'sha256_baseline',
    sources=['sha256_baseline.c'],
    include_dirs=['.'],
    extra_compile_args=extra_compile_args,  # Same optimization level!
    extra_link_args=extra_link_args,
    language='c',
)

# ESHA-256 FULL C implementation (for fair comparison)
esha256_full = Extension(
    'esha256_full',
    sources=['esha256_full.c'],
    include_dirs=['.'],
    extra_compile_args=extra_compile_args,  # Same optimization level!
    extra_link_args=extra_link_args,
    language='c',
)

# ESHA-256 PARALLEL - hash 4 messages at once!
esha256_parallel = Extension(
    'esha256_parallel',
    sources=['esha256_parallel.c'],
    include_dirs=['.'],
    extra_compile_args=extra_compile_args,
    extra_link_args=extra_link_args,
    language='c',
)

# Setup configuration
setup(
    name='esha256_extensions',
    version='1.0.0',
    description='C extensions for ESHA-256 thesis: SIMD optimization and SHA-256 baseline',
    long_description='''
C extensions for fair performance comparison:

1. esha256_simd: SIMD-accelerated multi-lane message schedule for ESHA-256
   - ARM NEON (Apple Silicon M1/M2/M3, ARM64 Linux)
   - Intel AVX2 (Haswell and newer)
   - Intel SSE4.2 (older Intel/AMD fallback)

2. sha256_baseline: Standard SHA-256 in optimized C
   - Same optimization level (-O3)
   - CANNOT use SIMD for message schedule (sequential dependencies)
   - Provides fair baseline for comparison

This demonstrates that ESHA-256's multi-lane design enables SIMD
parallelization that standard SHA-256's sequential design cannot achieve.
''',
    author='ESHA-256 Thesis Project',
    author_email='thesis@example.com',
    ext_modules=[esha256_simd, sha256_baseline, esha256_full, esha256_parallel],
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
