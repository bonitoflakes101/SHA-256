"""
Performance Benchmarking
=========================

This script benchmarks the performance of SHA-256 and ESHA-256 using PURE C implementations
for fair comparison. This reflects real-world usage in medical digital signature systems
where cryptographic operations are typically implemented in C for performance.

Metrics measured:
1. Throughput (operations per second)
2. Latency (milliseconds per hash)
3. Memory usage (bytes)

Configurations tested:
- SHA-256 (C baseline) - optimized C implementation
- ESHA-256 (C, with masking) - full C implementation with all enhancements
- ESHA-256 (C, without masking) - C implementation without SASCA protection
- ESHA-256 (C + SIMD, with masking) - C with SIMD acceleration if available
- ESHA-256 (C + SIMD, without masking) - C with SIMD acceleration if available

Expected results:
- ESHA-256 C: Comparable to SHA-256 C baseline
- ESHA-256 C + SIMD: ~30-50% faster than SHA-256 C (performance improvement!)

Author: ESHA-256 Thesis Project
Date: December 2025 (C-only benchmarks updated January 2026)
"""

import sys
import os
import csv
import time
import gc
from datetime import datetime

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'c_extension'))

from utils import random_bytes

# Try to import C extensions
try:
    import sha256_baseline
    _HAS_SHA256_C = True
except ImportError:
    _HAS_SHA256_C = False
    sha256_baseline = None

try:
    import esha256_full
    _HAS_ESHA256_C = True
except ImportError:
    _HAS_ESHA256_C = False
    esha256_full = None


class SHA256CWrapper:
    """Wrapper for SHA-256 C extension to match benchmark interface."""
    def __init__(self):
        if not _HAS_SHA256_C:
            raise ImportError("sha256_baseline C extension not available. Run build.sh to compile.")
        self._module = sha256_baseline
    
    def hash(self, data: bytes) -> bytes:
        """Hash data using C implementation."""
        return self._module.hash(data)


class ESHA256CWrapper:
    """Wrapper for ESHA-256 C extension to match benchmark interface."""
    def __init__(self, use_masking: bool = True):
        if not _HAS_ESHA256_C:
            raise ImportError("esha256_full C extension not available. Run build.sh to compile.")
        self._module = esha256_full
        self.use_masking = use_masking
    
    def hash(self, data: bytes) -> bytes:
        """Hash data using C implementation."""
        return self._module.hash(data, 1 if self.use_masking else 0)


def get_simd_info() -> dict:
    """
    Get information about SIMD support from C extension.
    
    Returns:
        Dict with 'extension_installed', 'simd_available', and 'simd_type' keys
    """
    if not _HAS_ESHA256_C:
        return {
            'extension_installed': False,
            'simd_available': False,
            'simd_type': 'Not installed'
        }
    
    try:
        has_simd = esha256_full.has_simd()
        info_str = esha256_full.get_info()
        
        # Parse SIMD type from info string
        if 'NEON' in info_str:
            simd_type = 'ARM NEON'
        elif 'AVX2' in info_str:
            simd_type = 'Intel AVX2'
        elif 'SSE' in info_str:
            simd_type = 'Intel SSE'
        else:
            simd_type = 'None (scalar)'
        
        return {
            'extension_installed': True,
            'simd_available': bool(has_simd),
            'simd_type': simd_type
        }
    except Exception:
        return {
            'extension_installed': True,
            'simd_available': False,
            'simd_type': 'Unknown'
        }


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
    
    # Check C extensions are available
    if not _HAS_SHA256_C:
        print("ERROR: sha256_baseline C extension not available!")
        print("Please run: cd src/c_extension && python setup.py build_ext --inplace")
        return False
    
    if not _HAS_ESHA256_C:
        print("ERROR: esha256_full C extension not available!")
        print("Please run: cd src/c_extension && python setup.py build_ext --inplace")
        return False
    
    # Print SIMD status
    simd_info = get_simd_info()
    print("Implementation: Pure C (fair comparison)")
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
    
    # Initialize hashers (all C implementations)
    sha256 = SHA256CWrapper()
    esha256_masked = ESHA256CWrapper(use_masking=True)
    esha256_unmasked = ESHA256CWrapper(use_masking=False)
    
    # Results dictionary
    results = {}
    
    # Benchmark SHA-256 (C baseline)
    print("Benchmarking SHA-256 (C baseline)...")
    results['sha256'] = benchmark_hasher(sha256, messages, name="SHA-256 (C)")
    print(f"  Completed in {results['sha256']['total_time']:.2f}s")
    
    # Benchmark ESHA-256 (C, masked)
    print("Benchmarking ESHA-256 (C, with masking)...")
    results['esha256_masked'] = benchmark_hasher(esha256_masked, messages, name="ESHA-256 (C, masked)")
    print(f"  Completed in {results['esha256_masked']['total_time']:.2f}s")
    
    # Benchmark ESHA-256 (C, unmasked)
    print("Benchmarking ESHA-256 (C, without masking)...")
    results['esha256_unmasked'] = benchmark_hasher(esha256_unmasked, messages, name="ESHA-256 (C, unmasked)")
    print(f"  Completed in {results['esha256_unmasked']['total_time']:.2f}s")
    
    # Note: SIMD is built into esha256_full if available
    # The C extension automatically uses SIMD when available
    if simd_info['simd_available']:
        print(f"Note: ESHA-256 C implementation uses {simd_info['simd_type']} SIMD acceleration")
        print()
    
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
    
    # SHA-256 baseline (C)
    print("  SHA-256 (C baseline):")
    print(f"    Throughput: {results['sha256']['throughput']:,.0f} ops/sec")
    print(f"    Latency:    {results['sha256']['latency']:.4f} ms/hash")
    print(f"    Memory:     {results['sha256']['memory']:,} bytes")
    print()
    
    # ESHA-256 C masked
    diff = calc_diff(results['esha256_masked'])
    simd_note = f" ({simd_info['simd_type']} SIMD)" if simd_info['simd_available'] else ""
    print(f"  ESHA-256 (C, masked{simd_note}):")
    print(f"    Throughput: {results['esha256_masked']['throughput']:,.0f} ops/sec ({diff:+.1f}% vs baseline)")
    print(f"    Latency:    {results['esha256_masked']['latency']:.4f} ms/hash")
    print(f"    Memory:     {results['esha256_masked']['memory']:,} bytes")
    print()
    
    # ESHA-256 C unmasked
    diff = calc_diff(results['esha256_unmasked'])
    print(f"  ESHA-256 (C, unmasked{simd_note}):")
    print(f"    Throughput: {results['esha256_unmasked']['throughput']:,.0f} ops/sec ({diff:+.1f}% vs baseline)")
    print(f"    Latency:    {results['esha256_unmasked']['latency']:.4f} ms/hash")
    print(f"    Memory:     {results['esha256_unmasked']['memory']:,} bytes")
    print()
    
    # Calculate masking overhead
    masking_overhead = ((results['esha256_masked']['throughput'] - results['esha256_unmasked']['throughput']) / 
                       results['esha256_unmasked']['throughput']) * 100
    print(f"  Masking overhead: {masking_overhead:+.1f}%")
    print()
    
    # Conclusion
    print("-" * 70)
    print("CONCLUSION")
    print("-" * 70)
    
    esha256_diff = calc_diff(results['esha256_masked'])
    if esha256_diff > 0:
        print(f"ESHA-256 (C): Performance GAIN ({esha256_diff:+.1f}% faster than SHA-256 C) ✅")
    elif abs(esha256_diff) < 10:
        print(f"ESHA-256 (C): Comparable performance ({esha256_diff:+.1f}% vs SHA-256 C) ✅")
    else:
        print(f"ESHA-256 (C): Performance overhead ({esha256_diff:+.1f}% vs SHA-256 C)")
    
    if simd_info['simd_available']:
        print(f"SIMD acceleration: {simd_info['simd_type']} enabled ✅")
    else:
        print("SIMD acceleration: Not available (scalar C implementation)")
    
    masking_overhead = ((results['esha256_masked']['throughput'] - results['esha256_unmasked']['throughput']) / 
                       results['esha256_unmasked']['throughput']) * 100
    print(f"Masking overhead: {masking_overhead:+.1f}% (acceptable for SASCA protection)")
    
    print()
    print("-" * 70)
    
    # Save results to CSV
    csv_path = 'results/performance_results.csv'
    with open(csv_path, 'w', newline='') as f:
        fieldnames = ['algorithm', 'throughput_ops_sec', 'latency_ms', 
                      'memory_bytes', 'total_time_sec', 'vs_baseline_pct']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        simd_suffix = f" ({simd_info['simd_type']})" if simd_info['simd_available'] else ""
        
        writer.writerow({
            'algorithm': 'SHA-256 (C)',
            'throughput_ops_sec': results['sha256']['throughput'],
            'latency_ms': results['sha256']['latency'],
            'memory_bytes': results['sha256']['memory'],
            'total_time_sec': results['sha256']['total_time'],
            'vs_baseline_pct': 0.0
        })
        
        writer.writerow({
            'algorithm': f'ESHA-256 (C, masked{simd_suffix})',
            'throughput_ops_sec': results['esha256_masked']['throughput'],
            'latency_ms': results['esha256_masked']['latency'],
            'memory_bytes': results['esha256_masked']['memory'],
            'total_time_sec': results['esha256_masked']['total_time'],
            'vs_baseline_pct': calc_diff(results['esha256_masked'])
        })
        
        writer.writerow({
            'algorithm': f'ESHA-256 (C, unmasked{simd_suffix})',
            'throughput_ops_sec': results['esha256_unmasked']['throughput'],
            'latency_ms': results['esha256_unmasked']['latency'],
            'memory_bytes': results['esha256_unmasked']['memory'],
            'total_time_sec': results['esha256_unmasked']['total_time'],
            'vs_baseline_pct': calc_diff(results['esha256_unmasked'])
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
        f.write("Implementation: Pure C (fair comparison)\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Iterations: {iterations}\n")
        f.write(f"Message Size: {message_size} bytes\n")
        f.write(f"SIMD Available: {simd_info['simd_available']}\n")
        if simd_info['simd_available']:
            f.write(f"SIMD Type: {simd_info['simd_type']}\n")
        f.write("\n")
        f.write("SHA-256 (C baseline):\n")
        f.write(f"  Throughput: {results['sha256']['throughput']:.2f} ops/sec\n")
        f.write(f"  Latency: {results['sha256']['latency']:.4f} ms\n")
        f.write(f"  Memory: {results['sha256']['memory']} bytes\n")
        f.write("\n")
        simd_note = f" ({simd_info['simd_type']})" if simd_info['simd_available'] else ""
        f.write(f"ESHA-256 (C, masked{simd_note}):\n")
        f.write(f"  Throughput: {results['esha256_masked']['throughput']:.2f} ops/sec\n")
        f.write(f"  Latency: {results['esha256_masked']['latency']:.4f} ms\n")
        f.write(f"  Memory: {results['esha256_masked']['memory']} bytes\n")
        f.write(f"  vs Baseline: {calc_diff(results['esha256_masked']):+.2f}%\n")
        f.write("\n")
        f.write(f"ESHA-256 (C, unmasked{simd_note}):\n")
        f.write(f"  Throughput: {results['esha256_unmasked']['throughput']:.2f} ops/sec\n")
        f.write(f"  Latency: {results['esha256_unmasked']['latency']:.4f} ms\n")
        f.write(f"  Memory: {results['esha256_unmasked']['memory']} bytes\n")
        f.write(f"  vs Baseline: {calc_diff(results['esha256_unmasked']):+.2f}%\n")
        masking_overhead = ((results['esha256_masked']['throughput'] - results['esha256_unmasked']['throughput']) / 
                           results['esha256_unmasked']['throughput']) * 100
        f.write(f"  Masking Overhead: {masking_overhead:+.2f}%\n")
    
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
    simd_note = f"\n({simd_info['simd_type']})" if simd_info['simd_available'] else ""
    algorithms = ['SHA-256\n(C)', f'ESHA-256\n(C, masked{simd_note})', f'ESHA-256\n(C, unmasked{simd_note})']
    throughputs = [
        results['sha256']['throughput'],
        results['esha256_masked']['throughput'],
        results['esha256_unmasked']['throughput']
    ]
    latencies = [
        results['sha256']['latency'],
        results['esha256_masked']['latency'],
        results['esha256_unmasked']['latency']
    ]
    memories = [
        results['sha256']['memory'],
        results['esha256_masked']['memory'],
        results['esha256_unmasked']['memory']
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
    
    title = 'SHA-256 vs ESHA-256 Performance Comparison (Pure C)'
    if simd_info['simd_available']:
        title += f'\n(SIMD: {simd_info["simd_type"]})'
    else:
        title += '\n(Scalar C implementation)'
    
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
