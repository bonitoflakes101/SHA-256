"""
ESHA-256 Thesis Package
========================

Enhanced SHA-256 for Medical Digital Signatures

This package provides implementations of:
- Standard SHA-256 (baseline)
- ESHA-256 (enhanced with HAIFA, multi-lane, and SASCA protection)
- Utility functions for testing and analysis
"""

from .sha256 import SHA256
from .esha256 import ESHA256
from .utils import (
    hamming_distance,
    flip_random_bit,
    random_bytes,
    simulate_power_consumption,
    pearson_correlation
)

__version__ = "1.0.0"
__author__ = "ESHA-256 Thesis Project"
__all__ = [
    "SHA256",
    "ESHA256",
    "hamming_distance",
    "flip_random_bit",
    "random_bytes",
    "simulate_power_consumption",
    "pearson_correlation"
]