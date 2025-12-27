"""
Avalanche Effect Analysis
==========================

This script measures the avalanche effect of SHA-256 and ESHA-256.

Avalanche Effect:
When a single input bit is changed, approximately 50% of output bits should change.
This is a critical property for cryptographic hash functions.

Ideal: 128 bits changed (50% of 256 bits)
Good range: 120-136 bits (47%-53%)

Author: ESHA-256 Thesis Project
Date: December 2025
"""

import sys
import os
import csv
import math
from datetime import datetime

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from sha256 import SHA256
from esha256 import ESHA256
from utils import hamming_distance, flip_random_bit, random_bytes


def calculate_statistics(values: list) -> dict:
    """
    Calculate mean, standard deviation, min, max.
    
    Args:
        values: List of numeric values
        
    Returns:
        Dict with mean, std, min, max
    """
    n = len(values)
    mean = sum(values) / n
    variance = sum((x - mean) ** 2 for x in values) / n
    std = math.sqrt(variance)
    
    return {
        'mean': mean,
        'std': std,
        'min': min(values),
        'max': max(values)
    }


def run_test(iterations: int = 10000):
    """
    Run avalanche effect analysis.
    
    Args:
        iterations: Number of test iterations
    """
    print("=" * 70)
    print("AVALANCHE EFFECT ANALYSIS")
    print("ESHA-256 Thesis - Chapter 4: Implementation & Testing")
    print("=" * 70)
    print()
    
    # Create output directories
    os.makedirs('results', exist_ok=True)
    os.makedirs('results/graphs', exist_ok=True)
    
    # Initialize hashers
    sha256 = SHA256()
    esha256 = ESHA256(use_masking=False)  # Disable masking for consistency
    
    # Results tracking
    sha256_bits_changed = []
    esha256_bits_changed = []
    results = []
    
    print(f"Running {iterations} avalanche tests...")
    print()
    
    for i in range(iterations):
        # Progress indicator
        if i % 1000 == 0:
            print(f"  Progress: {i}/{iterations}...")
        
        # Generate random message (varying lengths for comprehensive testing)
        msg_len = 16 + (i % 112)  # 16-128 bytes
        original_msg = random_bytes(msg_len)
        
        # Flip exactly 1 random bit
        modified_msg = flip_random_bit(original_msg)
        
        # Hash both versions with SHA-256
        sha256_hash_orig = sha256.hash(original_msg)
        sha256_hash_mod = sha256.hash(modified_msg)
        sha256_diff = hamming_distance(sha256_hash_orig, sha256_hash_mod)
        sha256_bits_changed.append(sha256_diff)
        
        # Hash both versions with ESHA-256
        esha256_hash_orig = esha256.hash(original_msg)
        esha256_hash_mod = esha256.hash(modified_msg)
        esha256_diff = hamming_distance(esha256_hash_orig, esha256_hash_mod)
        esha256_bits_changed.append(esha256_diff)
        
        # Record result
        results.append({
            'test_id': i + 1,
            'message_length': msg_len,
            'sha256_bits_changed': sha256_diff,
            'esha256_bits_changed': esha256_diff
        })
    
    # Calculate statistics
    sha256_stats = calculate_statistics(sha256_bits_changed)
    esha256_stats = calculate_statistics(esha256_bits_changed)
    
    sha256_pct = (sha256_stats['mean'] / 256) * 100
    esha256_pct = (esha256_stats['mean'] / 256) * 100
    improvement = esha256_pct - sha256_pct
    
    # Print results
    print()
    print("-" * 70)
    print("RESULTS")
    print("-" * 70)
    print()
    print(f"Avalanche Effect Analysis ({iterations:,} iterations)")
    print()
    print(f"  SHA-256:")
    print(f"    Mean: {sha256_stats['mean']:.1f} bits, Std: {sha256_stats['std']:.1f}")
    print(f"    Range: {sha256_stats['min']}-{sha256_stats['max']} bits")
    print(f"    Percentage: {sha256_pct:.1f}%")
    print()
    print(f"  ESHA-256:")
    print(f"    Mean: {esha256_stats['mean']:.1f} bits, Std: {esha256_stats['std']:.1f}")
    print(f"    Range: {esha256_stats['min']}-{esha256_stats['max']} bits")
    print(f"    Percentage: {esha256_pct:.1f}%")
    print()
    
    if improvement > 0:
        print(f"IMPROVEMENT: +{improvement:.1f}% better diffusion ✅")
    else:
        print(f"DIFFERENCE: {improvement:.1f}% (both near optimal)")
    
    print()
    print("Ideal avalanche effect: 128 bits (50.0%)")
    print()
    print("-" * 70)
    
    # Save results to CSV
    csv_path = 'results/avalanche_results.csv'
    with open(csv_path, 'w', newline='') as f:
        fieldnames = ['test_id', 'message_length', 'sha256_bits_changed', 'esha256_bits_changed']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    
    print(f"Results saved to: {csv_path}")
    
    # Generate histogram
    try:
        generate_histogram(sha256_bits_changed, esha256_bits_changed)
        print(f"Histogram saved to: results/graphs/avalanche_histogram.png")
    except ImportError:
        print("Note: matplotlib not available, skipping histogram generation")
    
    print()
    
    # Summary statistics
    summary_path = 'results/avalanche_summary.txt'
    with open(summary_path, 'w') as f:
        f.write("Avalanche Effect Analysis Summary\n")
        f.write("=" * 50 + "\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Iterations: {iterations}\n")
        f.write("\n")
        f.write("SHA-256:\n")
        f.write(f"  Mean: {sha256_stats['mean']:.2f} bits ({sha256_pct:.2f}%)\n")
        f.write(f"  Std Dev: {sha256_stats['std']:.2f}\n")
        f.write(f"  Range: {sha256_stats['min']}-{sha256_stats['max']}\n")
        f.write("\n")
        f.write("ESHA-256:\n")
        f.write(f"  Mean: {esha256_stats['mean']:.2f} bits ({esha256_pct:.2f}%)\n")
        f.write(f"  Std Dev: {esha256_stats['std']:.2f}\n")
        f.write(f"  Range: {esha256_stats['min']}-{esha256_stats['max']}\n")
        f.write("\n")
        f.write(f"Improvement: {improvement:+.2f}%\n")
    
    print(f"Summary saved to: {summary_path}")
    
    return True


def generate_histogram(sha256_data: list, esha256_data: list):
    """
    Generate histogram comparing avalanche effect distributions.
    
    Args:
        sha256_data: List of bit changes for SHA-256
        esha256_data: List of bit changes for ESHA-256
    """
    import matplotlib.pyplot as plt
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend
    
    fig, ax = plt.subplots(figsize=(12, 6))
    
    # Create histograms
    bins = range(80, 180, 2)
    
    ax.hist(sha256_data, bins=bins, alpha=0.6, label='SHA-256', 
            color='#3498db', edgecolor='white')
    ax.hist(esha256_data, bins=bins, alpha=0.6, label='ESHA-256', 
            color='#e74c3c', edgecolor='white')
    
    # Add vertical line for ideal (128 bits)
    ax.axvline(x=128, color='#2ecc71', linestyle='--', linewidth=2, 
               label='Ideal (128 bits)')
    
    # Labels and title
    ax.set_xlabel('Bits Changed (out of 256)', fontsize=12)
    ax.set_ylabel('Frequency', fontsize=12)
    ax.set_title('Avalanche Effect Distribution\n(1 bit input change → output bit changes)', 
                 fontsize=14, fontweight='bold')
    ax.legend(loc='upper right', fontsize=10)
    
    # Add statistics text
    sha256_mean = sum(sha256_data) / len(sha256_data)
    esha256_mean = sum(esha256_data) / len(esha256_data)
    
    stats_text = (f'SHA-256 Mean: {sha256_mean:.1f} bits ({sha256_mean/256*100:.1f}%)\n'
                  f'ESHA-256 Mean: {esha256_mean:.1f} bits ({esha256_mean/256*100:.1f}%)')
    ax.text(0.02, 0.98, stats_text, transform=ax.transAxes, 
            verticalalignment='top', fontsize=10,
            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
    
    ax.grid(True, alpha=0.3)
    ax.set_xlim(80, 180)
    
    plt.tight_layout()
    plt.savefig('results/graphs/avalanche_histogram.png', dpi=150, 
                bbox_inches='tight', facecolor='white')
    plt.close()


def main():
    """Main entry point."""
    try:
        success = run_test(iterations=10000)
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

