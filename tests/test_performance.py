"""
Performance Benchmarking
=========================

This script benchmarks the performance of SHA-256 and ESHA-256.

Metrics measured:
1. Throughput (operations per second)
2. Latency (milliseconds per hash)
3. Memory usage (bytes)

Expected trade-off:
- ESHA-256 is ~5-10% slower due to HAIFA, multi-lane, and masking
- This is acceptable for security-critical applications

Author: ESHA-256 Thesis Project
Date: December 2025
"""

import sys
import os
import csv
import time
import gc
from datetime import datetime

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from sha256 import SHA256
from esha256 import ESHA256
from utils import random_bytes


def measure_memory_usage(obj) -> int:
    """
    Estimate memory usage of an object.
    
    Args:
        obj: Object to measure
        
    Returns:
        Estimated memory in bytes
    """
    import sys as sys_module
    
    # Base size of object
    size = sys_module.getsizeof(obj)
    
    # Add size of instance attributes
    if hasattr(obj, '__dict__'):
        for key, value in obj.__dict__.items():
            size += sys_module.getsizeof(key)
            size += sys_module.getsizeof(value)
            if isinstance(value, list):
                size += sum(sys_module.getsizeof(item) for item in value)
    
    return size


def benchmark_sha256(hasher: SHA256, messages: list, warmup: int = 100) -> dict:
    """
    Benchmark SHA-256 performance.
    
    Args:
        hasher: SHA256 instance
        messages: List of messages to hash
        warmup: Number of warmup iterations
        
    Returns:
        Dict with throughput, latency, memory
    """
    # Warmup (allow JIT optimizations, cache warming)
    for msg in messages[:warmup]:
        hasher.hash(msg)
    
    # Force garbage collection
    gc.collect()
    
    # Measure time
    start_time = time.perf_counter()
    
    for msg in messages:
        hasher.hash(msg)
    
    end_time = time.perf_counter()
    
    # Calculate metrics
    total_time = end_time - start_time
    num_hashes = len(messages)
    
    throughput = num_hashes / total_time  # ops/sec
    latency = (total_time / num_hashes) * 1000  # ms/hash
    memory = measure_memory_usage(hasher)
    
    return {
        'throughput': throughput,
        'latency': latency,
        'memory': memory,
        'total_time': total_time
    }


def benchmark_esha256(hasher: ESHA256, messages: list, warmup: int = 100) -> dict:
    """
    Benchmark ESHA-256 performance.
    
    Args:
        hasher: ESHA256 instance
        messages: List of messages to hash
        warmup: Number of warmup iterations
        
    Returns:
        Dict with throughput, latency, memory
    """
    # Warmup
    for msg in messages[:warmup]:
        hasher.hash(msg)
    
    # Force garbage collection
    gc.collect()
    
    # Measure time
    start_time = time.perf_counter()
    
    for msg in messages:
        hasher.hash(msg)
    
    end_time = time.perf_counter()
    
    # Calculate metrics
    total_time = end_time - start_time
    num_hashes = len(messages)
    
    throughput = num_hashes / total_time
    latency = (total_time / num_hashes) * 1000
    memory = measure_memory_usage(hasher)
    
    return {
        'throughput': throughput,
        'latency': latency,
        'memory': memory,
        'total_time': total_time
    }


def run_test(iterations: int = 10000, message_size: int = 1024):
    """
    Run performance benchmarking.
    
    Args:
        iterations: Number of hash operations
        message_size: Size of each message in bytes
    """
    print("=" * 70)
    print("PERFORMANCE BENCHMARKING")
    print("ESHA-256 Thesis - Chapter 4: Implementation & Testing")
    print("=" * 70)
    print()
    
    # Create output directories
    os.makedirs('results', exist_ok=True)
    os.makedirs('results/graphs', exist_ok=True)
    
    # Generate test messages
    print(f"Generating {iterations:,} random messages ({message_size} bytes each)...")
    messages = [random_bytes(message_size) for _ in range(iterations)]
    total_data_mb = (iterations * message_size) / (1024 * 1024)
    print(f"Total data: {total_data_mb:.1f} MB")
    print()
    
    # Initialize hashers
    sha256 = SHA256()
    esha256_masked = ESHA256(use_masking=True)
    esha256_unmasked = ESHA256(use_masking=False)
    
    # Benchmark SHA-256
    print("Benchmarking SHA-256...")
    sha256_results = benchmark_sha256(sha256, messages)
    print(f"  Completed in {sha256_results['total_time']:.2f}s")
    
    # Benchmark ESHA-256 (masked)
    print("Benchmarking ESHA-256 (with masking)...")
    esha256_masked_results = benchmark_esha256(esha256_masked, messages)
    print(f"  Completed in {esha256_masked_results['total_time']:.2f}s")
    
    # Benchmark ESHA-256 (unmasked) - for comparison
    print("Benchmarking ESHA-256 (without masking)...")
    esha256_unmasked_results = benchmark_esha256(esha256_unmasked, messages)
    print(f"  Completed in {esha256_unmasked_results['total_time']:.2f}s")
    
    # Calculate differences
    throughput_diff = ((esha256_masked_results['throughput'] - sha256_results['throughput']) / 
                       sha256_results['throughput']) * 100
    memory_diff = ((esha256_masked_results['memory'] - sha256_results['memory']) / 
                   sha256_results['memory']) * 100
    
    # Print results
    print()
    print("-" * 70)
    print("RESULTS")
    print("-" * 70)
    print()
    print(f"Performance Benchmarking ({iterations:,} hashes, {message_size} bytes each)")
    print()
    print(f"  SHA-256:")
    print(f"    Throughput: {sha256_results['throughput']:.0f} ops/sec")
    print(f"    Latency:    {sha256_results['latency']:.2f} ms/hash")
    print(f"    Memory:     {sha256_results['memory']} bytes")
    print()
    print(f"  ESHA-256 (masked):")
    print(f"    Throughput: {esha256_masked_results['throughput']:.0f} ops/sec")
    print(f"    Latency:    {esha256_masked_results['latency']:.2f} ms/hash")
    print(f"    Memory:     {esha256_masked_results['memory']} bytes")
    print()
    print(f"  ESHA-256 (unmasked):")
    print(f"    Throughput: {esha256_unmasked_results['throughput']:.0f} ops/sec")
    print(f"    Latency:    {esha256_unmasked_results['latency']:.2f} ms/hash")
    print(f"    Memory:     {esha256_unmasked_results['memory']} bytes")
    print()
    print(f"DIFFERENCE (SHA-256 vs ESHA-256 masked):")
    print(f"    Throughput: {throughput_diff:+.1f}%")
    print(f"    Memory:     {memory_diff:+.1f}%")
    print()
    
    if throughput_diff > -15:
        print("CONCLUSION: Acceptable performance trade-off for enhanced security ✅")
    else:
        print("NOTE: Performance overhead may be significant for high-throughput applications")
    
    print()
    print("-" * 70)
    
    # Save results to CSV
    csv_path = 'results/performance_results.csv'
    with open(csv_path, 'w', newline='') as f:
        fieldnames = ['algorithm', 'throughput_ops_sec', 'latency_ms', 
                      'memory_bytes', 'total_time_sec']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        writer.writerow({
            'algorithm': 'SHA-256',
            'throughput_ops_sec': sha256_results['throughput'],
            'latency_ms': sha256_results['latency'],
            'memory_bytes': sha256_results['memory'],
            'total_time_sec': sha256_results['total_time']
        })
        
        writer.writerow({
            'algorithm': 'ESHA-256 (masked)',
            'throughput_ops_sec': esha256_masked_results['throughput'],
            'latency_ms': esha256_masked_results['latency'],
            'memory_bytes': esha256_masked_results['memory'],
            'total_time_sec': esha256_masked_results['total_time']
        })
        
        writer.writerow({
            'algorithm': 'ESHA-256 (unmasked)',
            'throughput_ops_sec': esha256_unmasked_results['throughput'],
            'latency_ms': esha256_unmasked_results['latency'],
            'memory_bytes': esha256_unmasked_results['memory'],
            'total_time_sec': esha256_unmasked_results['total_time']
        })
    
    print(f"Results saved to: {csv_path}")
    
    # Generate bar chart
    try:
        generate_performance_chart(sha256_results, esha256_masked_results, 
                                   esha256_unmasked_results)
        print(f"Chart saved to: results/graphs/performance_comparison.png")
    except ImportError:
        print("Note: matplotlib not available, skipping chart generation")
    
    print()
    
    # Summary statistics
    summary_path = 'results/performance_summary.txt'
    with open(summary_path, 'w') as f:
        f.write("Performance Benchmarking Summary\n")
        f.write("=" * 50 + "\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Iterations: {iterations}\n")
        f.write(f"Message Size: {message_size} bytes\n")
        f.write("\n")
        f.write("SHA-256:\n")
        f.write(f"  Throughput: {sha256_results['throughput']:.2f} ops/sec\n")
        f.write(f"  Latency: {sha256_results['latency']:.4f} ms\n")
        f.write(f"  Memory: {sha256_results['memory']} bytes\n")
        f.write("\n")
        f.write("ESHA-256 (masked):\n")
        f.write(f"  Throughput: {esha256_masked_results['throughput']:.2f} ops/sec\n")
        f.write(f"  Latency: {esha256_masked_results['latency']:.4f} ms\n")
        f.write(f"  Memory: {esha256_masked_results['memory']} bytes\n")
        f.write("\n")
        f.write(f"Throughput Difference: {throughput_diff:+.2f}%\n")
        f.write(f"Memory Difference: {memory_diff:+.2f}%\n")
    
    print(f"Summary saved to: {summary_path}")
    
    return True


def generate_performance_chart(sha256_results: dict, esha256_masked: dict, 
                                esha256_unmasked: dict):
    """
    Generate bar chart comparing performance.
    
    Args:
        sha256_results: SHA-256 benchmark results
        esha256_masked: ESHA-256 (masked) benchmark results
        esha256_unmasked: ESHA-256 (unmasked) benchmark results
    """
    import matplotlib.pyplot as plt
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend
    
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))
    
    algorithms = ['SHA-256', 'ESHA-256\n(masked)', 'ESHA-256\n(unmasked)']
    colors = ['#3498db', '#e74c3c', '#f39c12']
    
    # Throughput chart
    throughputs = [sha256_results['throughput'], esha256_masked['throughput'], 
                   esha256_unmasked['throughput']]
    axes[0].bar(algorithms, throughputs, color=colors, edgecolor='white', linewidth=1.5)
    axes[0].set_ylabel('Operations per Second', fontsize=11)
    axes[0].set_title('Throughput Comparison', fontsize=12, fontweight='bold')
    axes[0].grid(True, axis='y', alpha=0.3)
    
    # Add value labels
    for i, v in enumerate(throughputs):
        axes[0].text(i, v + max(throughputs) * 0.02, f'{v:.0f}', 
                     ha='center', fontsize=10, fontweight='bold')
    
    # Latency chart
    latencies = [sha256_results['latency'], esha256_masked['latency'], 
                 esha256_unmasked['latency']]
    axes[1].bar(algorithms, latencies, color=colors, edgecolor='white', linewidth=1.5)
    axes[1].set_ylabel('Milliseconds per Hash', fontsize=11)
    axes[1].set_title('Latency Comparison', fontsize=12, fontweight='bold')
    axes[1].grid(True, axis='y', alpha=0.3)
    
    for i, v in enumerate(latencies):
        axes[1].text(i, v + max(latencies) * 0.02, f'{v:.2f}', 
                     ha='center', fontsize=10, fontweight='bold')
    
    # Memory chart
    memories = [sha256_results['memory'], esha256_masked['memory'], 
                esha256_unmasked['memory']]
    axes[2].bar(algorithms, memories, color=colors, edgecolor='white', linewidth=1.5)
    axes[2].set_ylabel('Memory (bytes)', fontsize=11)
    axes[2].set_title('Memory Usage Comparison', fontsize=12, fontweight='bold')
    axes[2].grid(True, axis='y', alpha=0.3)
    
    for i, v in enumerate(memories):
        axes[2].text(i, v + max(memories) * 0.02, f'{v}', 
                     ha='center', fontsize=10, fontweight='bold')
    
    fig.suptitle('SHA-256 vs ESHA-256 Performance Comparison', 
                 fontsize=14, fontweight='bold', y=1.02)
    
    plt.tight_layout()
    plt.savefig('results/graphs/performance_comparison.png', dpi=150, 
                bbox_inches='tight', facecolor='white')
    plt.close()


def main():
    """Main entry point."""
    try:
        success = run_test(iterations=10000, message_size=1024)
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

