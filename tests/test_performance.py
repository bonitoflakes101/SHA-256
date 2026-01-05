"""
Performance Benchmarking
=========================

This script benchmarks the performance of SHA-256 and ESHA-256.

Metrics measured:
1. Throughput (operations per second)
2. Latency (milliseconds per hash)
3. Memory usage (bytes)

Configurations tested:
- SHA-256 (baseline)
- ESHA-256 (Python, with masking)
- ESHA-256 (Python, without masking)
- ESHA-256 (SIMD, with masking) - if C extension available
- ESHA-256 (SIMD, without masking) - if C extension available

Expected results:
- ESHA-256 Python: ~5-10% slower than SHA-256 (acceptable for security)
- ESHA-256 SIMD: ~40% faster than SHA-256 (performance improvement!)

Author: ESHA-256 Thesis Project
Date: December 2025 (SIMD benchmarks added January 2026)
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
from esha256 import ESHA256, get_simd_info
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


def benchmark_hasher(hasher, messages: list, warmup: int = 100, name: str = "Hasher") -> dict:
    """
    Benchmark a hasher's performance.
    
    Args:
        hasher: Hasher instance (SHA256 or ESHA256)
        messages: List of messages to hash
        warmup: Number of warmup iterations
        name: Name for progress display
        
    Returns:
        Dict with throughput, latency, memory, total_time
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
    
    # Print SIMD status
    simd_info = get_simd_info()
    print("SIMD Status:")
    print(f"  Extension installed: {simd_info['extension_installed']}")
    print(f"  SIMD available: {simd_info['simd_available']}")
    print(f"  SIMD type: {simd_info['simd_type']}")
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
    esha256_masked_python = ESHA256(use_masking=True, use_simd=False)
    esha256_unmasked_python = ESHA256(use_masking=False, use_simd=False)
    
    # Results dictionary
    results = {}
    
    # Benchmark SHA-256 (baseline)
    print("Benchmarking SHA-256 (baseline)...")
    results['sha256'] = benchmark_hasher(sha256, messages, name="SHA-256")
    print(f"  Completed in {results['sha256']['total_time']:.2f}s")
    
    # Benchmark ESHA-256 (Python, masked)
    print("Benchmarking ESHA-256 (Python, with masking)...")
    results['esha256_python_masked'] = benchmark_hasher(esha256_masked_python, messages)
    print(f"  Completed in {results['esha256_python_masked']['total_time']:.2f}s")
    
    # Benchmark ESHA-256 (Python, unmasked)
    print("Benchmarking ESHA-256 (Python, without masking)...")
    results['esha256_python_unmasked'] = benchmark_hasher(esha256_unmasked_python, messages)
    print(f"  Completed in {results['esha256_python_unmasked']['total_time']:.2f}s")
    
    # SIMD benchmarks (if available)
    if simd_info['simd_available']:
        esha256_masked_simd = ESHA256(use_masking=True, use_simd=True)
        esha256_unmasked_simd = ESHA256(use_masking=False, use_simd=True)
        
        print(f"Benchmarking ESHA-256 (SIMD {simd_info['simd_type']}, with masking)...")
        results['esha256_simd_masked'] = benchmark_hasher(esha256_masked_simd, messages)
        print(f"  Completed in {results['esha256_simd_masked']['total_time']:.2f}s")
        
        print(f"Benchmarking ESHA-256 (SIMD {simd_info['simd_type']}, without masking)...")
        results['esha256_simd_unmasked'] = benchmark_hasher(esha256_unmasked_simd, messages)
        print(f"  Completed in {results['esha256_simd_unmasked']['total_time']:.2f}s")
    
    # Calculate differences vs baseline
    baseline_throughput = results['sha256']['throughput']
    
    def calc_diff(result):
        return ((result['throughput'] - baseline_throughput) / baseline_throughput) * 100
    
    # Print results
    print()
    print("-" * 70)
    print("RESULTS")
    print("-" * 70)
    print()
    print(f"Performance Benchmarking ({iterations:,} hashes, {message_size} bytes each)")
    print()
    
    # SHA-256 baseline
    print("  SHA-256 (baseline):")
    print(f"    Throughput: {results['sha256']['throughput']:,.0f} ops/sec")
    print(f"    Latency:    {results['sha256']['latency']:.4f} ms/hash")
    print(f"    Memory:     {results['sha256']['memory']:,} bytes")
    print()
    
    # ESHA-256 Python masked
    diff = calc_diff(results['esha256_python_masked'])
    print("  ESHA-256 (Python, masked):")
    print(f"    Throughput: {results['esha256_python_masked']['throughput']:,.0f} ops/sec ({diff:+.1f}% vs baseline)")
    print(f"    Latency:    {results['esha256_python_masked']['latency']:.4f} ms/hash")
    print(f"    Memory:     {results['esha256_python_masked']['memory']:,} bytes")
    print()
    
    # ESHA-256 Python unmasked
    diff = calc_diff(results['esha256_python_unmasked'])
    print("  ESHA-256 (Python, unmasked):")
    print(f"    Throughput: {results['esha256_python_unmasked']['throughput']:,.0f} ops/sec ({diff:+.1f}% vs baseline)")
    print(f"    Latency:    {results['esha256_python_unmasked']['latency']:.4f} ms/hash")
    print(f"    Memory:     {results['esha256_python_unmasked']['memory']:,} bytes")
    print()
    
    # SIMD results
    if simd_info['simd_available']:
        diff = calc_diff(results['esha256_simd_masked'])
        print(f"  ESHA-256 (SIMD {simd_info['simd_type']}, masked):")
        print(f"    Throughput: {results['esha256_simd_masked']['throughput']:,.0f} ops/sec ({diff:+.1f}% vs baseline)")
        print(f"    Latency:    {results['esha256_simd_masked']['latency']:.4f} ms/hash")
        print(f"    Memory:     {results['esha256_simd_masked']['memory']:,} bytes")
        print()
        
        diff = calc_diff(results['esha256_simd_unmasked'])
        print(f"  ESHA-256 (SIMD {simd_info['simd_type']}, unmasked):")
        print(f"    Throughput: {results['esha256_simd_unmasked']['throughput']:,.0f} ops/sec ({diff:+.1f}% vs baseline)")
        print(f"    Latency:    {results['esha256_simd_unmasked']['latency']:.4f} ms/hash")
        print(f"    Memory:     {results['esha256_simd_unmasked']['memory']:,} bytes")
        print()
        
        # Calculate SIMD speedup
        simd_speedup = results['esha256_simd_unmasked']['throughput'] / results['esha256_python_unmasked']['throughput']
        print(f"  SIMD Speedup (vs Python): {simd_speedup:.2f}x")
        print()
    
    # Conclusion
    print("-" * 70)
    print("CONCLUSION")
    print("-" * 70)
    
    python_diff = calc_diff(results['esha256_python_masked'])
    if abs(python_diff) < 15:
        print(f"Python implementation: Acceptable overhead ({python_diff:+.1f}%) ✅")
    else:
        print(f"Python implementation: Significant overhead ({python_diff:+.1f}%) ⚠️")
    
    if simd_info['simd_available']:
        simd_diff = calc_diff(results['esha256_simd_masked'])
        if simd_diff > 0:
            print(f"SIMD implementation: Performance GAIN ({simd_diff:+.1f}% faster than baseline) ✅")
        else:
            print(f"SIMD implementation: {simd_diff:+.1f}% vs baseline")
    else:
        print("SIMD implementation: Not available (run ./build.sh to compile)")
    
    print()
    print("-" * 70)
    
    # Save results to CSV
    csv_path = 'results/performance_results.csv'
    with open(csv_path, 'w', newline='') as f:
        fieldnames = ['algorithm', 'throughput_ops_sec', 'latency_ms', 
                      'memory_bytes', 'total_time_sec', 'vs_baseline_pct']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        writer.writerow({
            'algorithm': 'SHA-256',
            'throughput_ops_sec': results['sha256']['throughput'],
            'latency_ms': results['sha256']['latency'],
            'memory_bytes': results['sha256']['memory'],
            'total_time_sec': results['sha256']['total_time'],
            'vs_baseline_pct': 0.0
        })
        
        writer.writerow({
            'algorithm': 'ESHA-256 (Python, masked)',
            'throughput_ops_sec': results['esha256_python_masked']['throughput'],
            'latency_ms': results['esha256_python_masked']['latency'],
            'memory_bytes': results['esha256_python_masked']['memory'],
            'total_time_sec': results['esha256_python_masked']['total_time'],
            'vs_baseline_pct': calc_diff(results['esha256_python_masked'])
        })
        
        writer.writerow({
            'algorithm': 'ESHA-256 (Python, unmasked)',
            'throughput_ops_sec': results['esha256_python_unmasked']['throughput'],
            'latency_ms': results['esha256_python_unmasked']['latency'],
            'memory_bytes': results['esha256_python_unmasked']['memory'],
            'total_time_sec': results['esha256_python_unmasked']['total_time'],
            'vs_baseline_pct': calc_diff(results['esha256_python_unmasked'])
        })
        
        if simd_info['simd_available']:
            writer.writerow({
                'algorithm': f'ESHA-256 (SIMD {simd_info["simd_type"]}, masked)',
                'throughput_ops_sec': results['esha256_simd_masked']['throughput'],
                'latency_ms': results['esha256_simd_masked']['latency'],
                'memory_bytes': results['esha256_simd_masked']['memory'],
                'total_time_sec': results['esha256_simd_masked']['total_time'],
                'vs_baseline_pct': calc_diff(results['esha256_simd_masked'])
            })
            
            writer.writerow({
                'algorithm': f'ESHA-256 (SIMD {simd_info["simd_type"]}, unmasked)',
                'throughput_ops_sec': results['esha256_simd_unmasked']['throughput'],
                'latency_ms': results['esha256_simd_unmasked']['latency'],
                'memory_bytes': results['esha256_simd_unmasked']['memory'],
                'total_time_sec': results['esha256_simd_unmasked']['total_time'],
                'vs_baseline_pct': calc_diff(results['esha256_simd_unmasked'])
            })
    
    print(f"Results saved to: {csv_path}")
    
    # Generate bar chart
    try:
        generate_performance_chart(results, simd_info)
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
        f.write(f"SIMD Available: {simd_info['simd_available']}\n")
        if simd_info['simd_available']:
            f.write(f"SIMD Type: {simd_info['simd_type']}\n")
        f.write("\n")
        f.write("SHA-256 (baseline):\n")
        f.write(f"  Throughput: {results['sha256']['throughput']:.2f} ops/sec\n")
        f.write(f"  Latency: {results['sha256']['latency']:.4f} ms\n")
        f.write(f"  Memory: {results['sha256']['memory']} bytes\n")
        f.write("\n")
        f.write("ESHA-256 (Python, masked):\n")
        f.write(f"  Throughput: {results['esha256_python_masked']['throughput']:.2f} ops/sec\n")
        f.write(f"  Latency: {results['esha256_python_masked']['latency']:.4f} ms\n")
        f.write(f"  Memory: {results['esha256_python_masked']['memory']} bytes\n")
        f.write(f"  vs Baseline: {calc_diff(results['esha256_python_masked']):+.2f}%\n")
        f.write("\n")
        if simd_info['simd_available']:
            f.write(f"ESHA-256 (SIMD {simd_info['simd_type']}, masked):\n")
            f.write(f"  Throughput: {results['esha256_simd_masked']['throughput']:.2f} ops/sec\n")
            f.write(f"  Latency: {results['esha256_simd_masked']['latency']:.4f} ms\n")
            f.write(f"  Memory: {results['esha256_simd_masked']['memory']} bytes\n")
            f.write(f"  vs Baseline: {calc_diff(results['esha256_simd_masked']):+.2f}%\n")
            f.write(f"  SIMD Speedup: {results['esha256_simd_unmasked']['throughput'] / results['esha256_python_unmasked']['throughput']:.2f}x\n")
    
    print(f"Summary saved to: {summary_path}")
    
    return True


def generate_performance_chart(results: dict, simd_info: dict):
    """
    Generate bar chart comparing performance.
    
    Args:
        results: Benchmark results dictionary
        simd_info: SIMD information dictionary
    """
    import matplotlib.pyplot as plt
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend
    
    # Prepare data
    if simd_info['simd_available']:
        algorithms = ['SHA-256\n(baseline)', 'ESHA-256\n(Python)', 'ESHA-256\n(SIMD)']
        throughputs = [
            results['sha256']['throughput'],
            results['esha256_python_masked']['throughput'],
            results['esha256_simd_masked']['throughput']
        ]
        latencies = [
            results['sha256']['latency'],
            results['esha256_python_masked']['latency'],
            results['esha256_simd_masked']['latency']
        ]
        memories = [
            results['sha256']['memory'],
            results['esha256_python_masked']['memory'],
            results['esha256_simd_masked']['memory']
        ]
        colors = ['#3498db', '#e74c3c', '#27ae60']
    else:
        algorithms = ['SHA-256\n(baseline)', 'ESHA-256\n(Python, masked)', 'ESHA-256\n(Python, unmasked)']
        throughputs = [
            results['sha256']['throughput'],
            results['esha256_python_masked']['throughput'],
            results['esha256_python_unmasked']['throughput']
        ]
        latencies = [
            results['sha256']['latency'],
            results['esha256_python_masked']['latency'],
            results['esha256_python_unmasked']['latency']
        ]
        memories = [
            results['sha256']['memory'],
            results['esha256_python_masked']['memory'],
            results['esha256_python_unmasked']['memory']
        ]
        colors = ['#3498db', '#e74c3c', '#f39c12']
    
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))
    
    # Throughput chart
    bars1 = axes[0].bar(algorithms, throughputs, color=colors, edgecolor='white', linewidth=1.5)
    axes[0].set_ylabel('Operations per Second', fontsize=11)
    axes[0].set_title('Throughput Comparison', fontsize=12, fontweight='bold')
    axes[0].grid(True, axis='y', alpha=0.3)
    
    # Add value labels
    for i, (bar, v) in enumerate(zip(bars1, throughputs)):
        axes[0].text(bar.get_x() + bar.get_width()/2, v + max(throughputs) * 0.02, 
                     f'{v:,.0f}', ha='center', fontsize=9, fontweight='bold')
    
    # Latency chart
    bars2 = axes[1].bar(algorithms, latencies, color=colors, edgecolor='white', linewidth=1.5)
    axes[1].set_ylabel('Milliseconds per Hash', fontsize=11)
    axes[1].set_title('Latency Comparison', fontsize=12, fontweight='bold')
    axes[1].grid(True, axis='y', alpha=0.3)
    
    for i, (bar, v) in enumerate(zip(bars2, latencies)):
        axes[1].text(bar.get_x() + bar.get_width()/2, v + max(latencies) * 0.02, 
                     f'{v:.4f}', ha='center', fontsize=9, fontweight='bold')
    
    # Memory chart
    bars3 = axes[2].bar(algorithms, memories, color=colors, edgecolor='white', linewidth=1.5)
    axes[2].set_ylabel('Memory (bytes)', fontsize=11)
    axes[2].set_title('Memory Usage Comparison', fontsize=12, fontweight='bold')
    axes[2].grid(True, axis='y', alpha=0.3)
    
    for i, (bar, v) in enumerate(zip(bars3, memories)):
        axes[2].text(bar.get_x() + bar.get_width()/2, v + max(memories) * 0.02, 
                     f'{v:,}', ha='center', fontsize=9, fontweight='bold')
    
    title = 'SHA-256 vs ESHA-256 Performance Comparison'
    if simd_info['simd_available']:
        title += f'\n(SIMD: {simd_info["simd_type"]})'
    
    fig.suptitle(title, fontsize=14, fontweight='bold', y=1.02)
    
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
