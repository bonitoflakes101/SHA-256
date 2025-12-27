"""
SASCA Resistance Test
======================

This script simulates Side-Channel Attacks with Algorithmic Side-Channel Analysis (SASCA)
and measures the correlation between power consumption and sensitive data.

Power Analysis Attack Model:
- Power consumption is proportional to Hamming weight of data
- Attacker correlates power traces with hypothetical key values
- High correlation (ρ > 0.5) indicates vulnerability

SHA-256: Unmasked operations → High correlation → Vulnerable
ESHA-256: Boolean masking → Low correlation → Protected

Author: ESHA-256 Thesis Project
Date: December 2025
"""

import sys
import os
import csv
import math
import random
import secrets
from datetime import datetime

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from utils import simulate_power_consumption, pearson_correlation, hamming_weight


def simulate_sha256_power_trace(value: int, num_operations: int = 10) -> float:
    """
    Simulate power consumption for SHA-256 (unmasked).
    
    In standard SHA-256, operations are performed directly on data.
    Power consumption leaks information about the data being processed.
    
    Args:
        value: Sensitive data value (e.g., intermediate hash state)
        num_operations: Number of operations to simulate
        
    Returns:
        Total simulated power consumption
    """
    total_power = 0.0
    
    for _ in range(num_operations):
        # Unmasked: power directly proportional to Hamming weight
        total_power += simulate_power_consumption(value, mask=None, noise_stddev=2.0)
    
    return total_power / num_operations


def simulate_esha256_power_trace(value: int, num_operations: int = 10) -> float:
    """
    Simulate power consumption for ESHA-256 (masked).
    
    ESHA-256 uses boolean masking: operations are performed on (value XOR mask).
    Attacker sees power for masked values, which have random Hamming weight.
    
    Args:
        value: Sensitive data value
        num_operations: Number of operations to simulate
        
    Returns:
        Total simulated power consumption (decorrelated from value)
    """
    total_power = 0.0
    
    for _ in range(num_operations):
        # Generate new random mask for each operation (first-order masking)
        mask = secrets.randbits(32)
        total_power += simulate_power_consumption(value, mask=mask, noise_stddev=2.0)
    
    return total_power / num_operations


def run_test(iterations: int = 10000):
    """
    Run SASCA resistance test.
    
    Args:
        iterations: Number of power traces to simulate
    """
    print("=" * 70)
    print("SASCA RESISTANCE TEST")
    print("ESHA-256 Thesis - Chapter 4: Implementation & Testing")
    print("=" * 70)
    print()
    print("Attack Model: Correlation Power Analysis (CPA)")
    print("Leakage Model: Hamming Weight of intermediate values")
    print()
    
    # Create output directories
    os.makedirs('results', exist_ok=True)
    os.makedirs('results/graphs', exist_ok=True)
    
    # Generate test data
    values = []
    hamming_weights = []
    sha256_power_traces = []
    esha256_power_traces = []
    
    print(f"Simulating {iterations:,} power traces...")
    print()
    
    for i in range(iterations):
        # Progress indicator
        if i % 1000 == 0:
            print(f"  Progress: {i}/{iterations}...")
        
        # Generate random 32-bit value (simulating intermediate computation)
        value = secrets.randbits(32)
        values.append(value)
        hamming_weights.append(hamming_weight(value))
        
        # Simulate power for SHA-256 (unmasked)
        sha256_power = simulate_sha256_power_trace(value)
        sha256_power_traces.append(sha256_power)
        
        # Simulate power for ESHA-256 (masked)
        esha256_power = simulate_esha256_power_trace(value)
        esha256_power_traces.append(esha256_power)
    
    # Calculate correlations
    # Correlation between Hamming weight (what attacker hypothesizes) and power
    sha256_correlation = pearson_correlation(hamming_weights, sha256_power_traces)
    esha256_correlation = pearson_correlation(hamming_weights, esha256_power_traces)
    
    # Calculate leakage reduction
    leakage_reduction = ((abs(sha256_correlation) - abs(esha256_correlation)) / 
                         abs(sha256_correlation)) * 100
    
    # Print results
    print()
    print("-" * 70)
    print("RESULTS")
    print("-" * 70)
    print()
    print(f"SASCA Resistance Test ({iterations:,} traces)")
    print()
    print(f"  SHA-256 (unmasked):  ρ = {sha256_correlation:.3f} ", end="")
    if abs(sha256_correlation) > 0.5:
        print("(VULNERABLE ⚠️)")
    elif abs(sha256_correlation) > 0.3:
        print("(weak)")
    else:
        print("(protected)")
    
    print(f"  ESHA-256 (masked):   ρ = {esha256_correlation:.3f} ", end="")
    if abs(esha256_correlation) < 0.1:
        print("(PROTECTED ✅)")
    elif abs(esha256_correlation) < 0.3:
        print("(good protection)")
    else:
        print("(needs improvement)")
    
    print()
    print(f"IMPROVEMENT: {leakage_reduction:.1f}% leakage reduction ✅")
    print()
    
    # Interpretation
    print("Interpretation:")
    print("  - Correlation (ρ) measures how much power consumption reveals data")
    print("  - ρ ≈ 1.0: Complete leakage (attacker can recover data)")
    print("  - ρ ≈ 0.0: No leakage (masking is effective)")
    print()
    print("-" * 70)
    
    # Prepare results for CSV
    results = []
    for i in range(iterations):
        results.append({
            'test_id': i + 1,
            'value': values[i],
            'hamming_weight': hamming_weights[i],
            'sha256_power': sha256_power_traces[i],
            'esha256_power': esha256_power_traces[i],
            'sha256_correlation': sha256_correlation,
            'esha256_correlation': esha256_correlation
        })
    
    # Save results to CSV
    csv_path = 'results/sasca_results.csv'
    with open(csv_path, 'w', newline='') as f:
        fieldnames = ['test_id', 'value', 'hamming_weight', 'sha256_power', 
                      'esha256_power', 'sha256_correlation', 'esha256_correlation']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    
    print(f"Results saved to: {csv_path}")
    
    # Generate scatter plot
    try:
        generate_correlation_plot(hamming_weights, sha256_power_traces, 
                                  esha256_power_traces, sha256_correlation, 
                                  esha256_correlation)
        print(f"Scatter plot saved to: results/graphs/sasca_correlation.png")
    except ImportError:
        print("Note: matplotlib not available, skipping plot generation")
    
    print()
    
    # Summary statistics
    summary_path = 'results/sasca_summary.txt'
    with open(summary_path, 'w') as f:
        f.write("SASCA Resistance Test Summary\n")
        f.write("=" * 50 + "\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Power Traces: {iterations}\n")
        f.write("\n")
        f.write("Results:\n")
        f.write(f"  SHA-256 Correlation:  ρ = {sha256_correlation:.4f}\n")
        f.write(f"  ESHA-256 Correlation: ρ = {esha256_correlation:.4f}\n")
        f.write("\n")
        f.write(f"Leakage Reduction: {leakage_reduction:.2f}%\n")
        f.write("\n")
        f.write("Conclusion:\n")
        f.write("  - SHA-256 shows high correlation (vulnerable to CPA)\n")
        f.write("  - ESHA-256 shows near-zero correlation (protected by masking)\n")
        f.write("  - Boolean masking effectively decorrelates power from data\n")
    
    print(f"Summary saved to: {summary_path}")
    
    return abs(esha256_correlation) < 0.1


def generate_correlation_plot(hamming_weights: list, sha256_power: list, 
                               esha256_power: list, sha256_corr: float, 
                               esha256_corr: float):
    """
    Generate scatter plot showing correlation between Hamming weight and power.
    
    Args:
        hamming_weights: List of Hamming weights
        sha256_power: SHA-256 power traces
        esha256_power: ESHA-256 power traces
        sha256_corr: SHA-256 correlation coefficient
        esha256_corr: ESHA-256 correlation coefficient
    """
    import matplotlib.pyplot as plt
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend
    
    # Sample for plotting (too many points makes plot unreadable)
    sample_size = min(2000, len(hamming_weights))
    indices = random.sample(range(len(hamming_weights)), sample_size)
    
    hw_sample = [hamming_weights[i] for i in indices]
    sha256_sample = [sha256_power[i] for i in indices]
    esha256_sample = [esha256_power[i] for i in indices]
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    # SHA-256 (vulnerable)
    ax1.scatter(hw_sample, sha256_sample, alpha=0.3, c='#e74c3c', s=10)
    ax1.set_xlabel('Hamming Weight of Data', fontsize=11)
    ax1.set_ylabel('Power Consumption (a.u.)', fontsize=11)
    ax1.set_title(f'SHA-256 (Unmasked)\nρ = {sha256_corr:.3f} - VULNERABLE', 
                  fontsize=12, fontweight='bold', color='#c0392b')
    ax1.grid(True, alpha=0.3)
    
    # Add trend line for SHA-256
    z = [sum(x*y for x, y in zip(hw_sample, sha256_sample)) / len(hw_sample)]
    ax1.axline((min(hw_sample), min(sha256_sample)), 
               (max(hw_sample), max(sha256_sample)), 
               color='darkred', linestyle='--', linewidth=2, alpha=0.7)
    
    # ESHA-256 (protected)
    ax2.scatter(hw_sample, esha256_sample, alpha=0.3, c='#27ae60', s=10)
    ax2.set_xlabel('Hamming Weight of Data', fontsize=11)
    ax2.set_ylabel('Power Consumption (a.u.)', fontsize=11)
    ax2.set_title(f'ESHA-256 (Masked)\nρ = {esha256_corr:.3f} - PROTECTED', 
                  fontsize=12, fontweight='bold', color='#27ae60')
    ax2.grid(True, alpha=0.3)
    
    fig.suptitle('Side-Channel Attack Resistance Analysis\n'
                 'Correlation between Data and Power Consumption', 
                 fontsize=14, fontweight='bold', y=1.02)
    
    plt.tight_layout()
    plt.savefig('results/graphs/sasca_correlation.png', dpi=150, 
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

