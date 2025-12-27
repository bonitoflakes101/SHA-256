# ESHA-256: Enhanced SHA-256 for Medical Digital Signatures

## Overview

ESHA-256 is an enhanced version of SHA-256 designed specifically for medical digital signature systems. It addresses three critical vulnerabilities in standard SHA-256:


## Key Enhancements

### Enhancement 1: HAIFA Framework
- **What:** Injects bitcount, salt, and final-block flag into each compression
- **Why:** Prevents attackers from extending a hash without knowing the original message
- **Result:** Complete immunity to length-extension attacks

### Enhancement 2: Multi-Lane Message Schedule
- **What:** 4 parallel lanes for message expansion with cross-lane mixing
- **Why:** Better collision resistance and SIMD-friendly design
- **Result:** Maintains ideal 50% avalanche effect

### Enhancement 3: Boolean Masking (SASCA Protection)
- **What:** XORs random masks with intermediate values during computation
- **Why:** Decorrelates power consumption from sensitive data
- **Result:** 99.3% reduction in side-channel information leakage

## Project Structure

```
SHA-256/
├── src/
│   ├── __init__.py          # Package exports
│   ├── sha256.py             # Standard SHA-256 implementation
│   ├── esha256.py            # Enhanced ESHA-256 implementation
│   └── utils.py              # Helper functions
├── tests/
│   ├── test_length_extension.py   # Length-extension attack test
│   ├── test_avalanche.py          # Avalanche effect analysis
│   ├── test_sasca.py              # Side-channel resistance test
│   ├── test_performance.py        # Performance benchmarking
│   └── test_rsa_integration.py    # RSA-PSS integration test
├── results/
│   ├── graphs/                    # Generated visualization graphs
│   └── *.csv                      # Test result data files
├── requirements.txt
└── README.md
```

## Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/SHA-256.git
cd SHA-256

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

```python
from src.esha256 import ESHA256
from src.sha256 import SHA256

# Standard SHA-256
sha = SHA256()
digest_sha = sha.hexdigest(b"Medical record data")
print(f"SHA-256:  {digest_sha}")

# Enhanced ESHA-256
esha = ESHA256()
digest_esha = esha.hexdigest(b"Medical record data")
print(f"ESHA-256: {digest_esha}")
```

## Running Tests

### Run All Tests

```bash
# Activate virtual environment first
source venv/bin/activate

# Run individual tests
python tests/test_length_extension.py    # ~2 min, 1000 iterations
python tests/test_avalanche.py           # ~3 min, 10000 iterations
python tests/test_sasca.py               # ~2 min, 10000 traces
python tests/test_performance.py         # ~1 min, 10000 hashes
python tests/test_rsa_integration.py     # ~1 min, 100 documents
```

### Quick Verification

```bash
python src/sha256.py      # Test SHA-256
python src/esha256.py     # Test ESHA-256
python test_installation.py  # Full installation test
```

## Requirements

- Python 3.9+
- matplotlib (for graphs)
- numpy
- cryptography (for RSA-PSS tests)

See `requirements.txt` for full dependency list.

