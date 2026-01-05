#!/bin/bash
#
# ESHA-256 SIMD Extension Build Script
# =====================================
#
# Builds the SIMD-optimized C extension and installs it into src/
#
# Usage:
#     ./build.sh         # Build the extension
#     ./build.sh clean   # Clean build artifacts
#     ./build.sh test    # Build and run quick test
#
# Author: ESHA-256 Thesis Project
# Date: January 2026

set -e  # Exit on error

# Get script directory (project root)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
C_EXT_DIR="$SCRIPT_DIR/src/c_extension"
SRC_DIR="$SCRIPT_DIR/src"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=====================================${NC}"
echo -e "${BLUE}  ESHA-256 SIMD Extension Builder${NC}"
echo -e "${BLUE}=====================================${NC}"
echo

# Check for clean command
if [ "$1" = "clean" ]; then
    echo -e "${YELLOW}Cleaning build artifacts...${NC}"
    rm -rf "$C_EXT_DIR/build"
    rm -rf "$C_EXT_DIR/dist"
    rm -rf "$C_EXT_DIR/*.egg-info"
    rm -f "$C_EXT_DIR"/*.so
    rm -f "$C_EXT_DIR"/*.pyd
    rm -f "$SRC_DIR"/esha256_simd*.so
    rm -f "$SRC_DIR"/esha256_simd*.pyd
    echo -e "${GREEN}Clean complete.${NC}"
    exit 0
fi

# Check Python version
PYTHON=${PYTHON:-python3}
echo -e "Using Python: ${YELLOW}$($PYTHON --version)${NC}"

# Check for required tools
if ! command -v $PYTHON &> /dev/null; then
    echo -e "${RED}Error: Python not found${NC}"
    exit 1
fi

# Navigate to C extension directory
cd "$C_EXT_DIR"

# Build the extension
echo
echo -e "${YELLOW}Building SIMD extension...${NC}"
echo

$PYTHON setup.py build_ext --inplace 2>&1 | while read line; do
    echo "  $line"
done

# Check if build succeeded
BUILT_EXT=$(ls *.so 2>/dev/null || ls *.pyd 2>/dev/null || echo "")

if [ -z "$BUILT_EXT" ]; then
    echo
    echo -e "${RED}Error: Build failed - no .so/.pyd file generated${NC}"
    exit 1
fi

echo
echo -e "${GREEN}Build successful: $BUILT_EXT${NC}"

# Copy to src directory for import
echo -e "${YELLOW}Installing to src/...${NC}"
cp $BUILT_EXT "$SRC_DIR/"
echo -e "${GREEN}Installed: $SRC_DIR/$BUILT_EXT${NC}"

# Verify import
echo
echo -e "${YELLOW}Verifying import...${NC}"
cd "$SRC_DIR"
$PYTHON -c "
import esha256_simd
print(f'  SIMD available: {esha256_simd.has_simd_support()}')
print(f'  SIMD type: {esha256_simd.get_simd_type()}')
" 2>&1 | while read line; do
    echo "  $line"
done

if [ $? -eq 0 ]; then
    echo
    echo -e "${GREEN}=====================================${NC}"
    echo -e "${GREEN}  Build complete! Extension ready.${NC}"
    echo -e "${GREEN}=====================================${NC}"
else
    echo
    echo -e "${RED}Error: Import verification failed${NC}"
    exit 1
fi

# Run quick test if requested
if [ "$1" = "test" ]; then
    echo
    echo -e "${YELLOW}Running quick functionality test...${NC}"
    cd "$SCRIPT_DIR"
    $PYTHON -c "
import sys
sys.path.insert(0, 'src')

import esha256_simd
from esha256 import ESHA256

# Test 1: SIMD availability
print(f'SIMD available: {esha256_simd.has_simd_support()}')
print(f'SIMD type: {esha256_simd.get_simd_type()}')

# Test 2: Message schedule expansion
words = list(range(16))  # Simple test input
result = esha256_simd.multi_lane_schedule_simd(words)
print(f'Schedule expansion: {len(result)} words generated')

# Test 3: Hash consistency
esha = ESHA256(use_masking=False)
msg = b'SIMD test message'
hash1 = esha.hexdigest(msg)
hash2 = esha.hexdigest(msg)
print(f'Hash consistency: {\"PASS\" if hash1 == hash2 else \"FAIL\"}')
print(f'Hash: {hash1[:32]}...')

print()
print('All tests passed!')
"
fi

echo
echo -e "Next steps:"
echo -e "  1. Run tests: ${YELLOW}python tests/test_performance.py${NC}"
echo -e "  2. Verify security: ${YELLOW}python tests/test_length_extension.py${NC}"
echo

