/**
 * ESHA-256 SIMD Header
 * ====================
 * 
 * SIMD-optimized multi-lane message schedule expansion for ESHA-256.
 * Supports ARM NEON (Apple Silicon, ARM64) and Intel AVX2/SSE4.2.
 * 
 * Author: ESHA-256 Thesis Project
 * Date: January 2026
 */

#ifndef ESHA256_SIMD_H
#define ESHA256_SIMD_H

#include <stdint.h>
#include <stdbool.h>

/**
 * SIMD-optimized multi-lane message schedule expansion.
 * 
 * Takes 16 pre-processed words (after HAIFA injection) and expands them
 * to 64 words using the multi-lane algorithm with SIMD acceleration.
 * 
 * Lane distribution:
 *   Lane A: words[0], words[4], words[8], words[12]
 *   Lane B: words[1], words[5], words[9], words[13]
 *   Lane C: words[2], words[6], words[10], words[14]
 *   Lane D: words[3], words[7], words[11], words[15]
 * 
 * Cross-lane expansion:
 *   lane_A[t] = σ₁(lane_A[t-4]) + lane_D[t-4] + σ₀(lane_B[t-4]) + lane_C[t-4]
 *   lane_B[t] = σ₁(lane_B[t-4]) + lane_A[t-4] + σ₀(lane_C[t-4]) + lane_D[t-4]
 *   lane_C[t] = σ₁(lane_C[t-4]) + lane_B[t-4] + σ₀(lane_D[t-4]) + lane_A[t-4]
 *   lane_D[t] = σ₁(lane_D[t-4]) + lane_C[t-4] + σ₀(lane_A[t-4]) + lane_B[t-4]
 * 
 * @param words_in  Input: 16 32-bit words (after HAIFA injection)
 * @param W_out     Output: 64 32-bit words (expanded message schedule)
 */
void multi_lane_schedule_simd(const uint32_t words_in[16], uint32_t W_out[64]);

/**
 * Check if SIMD is available on this CPU.
 * 
 * @return true if ARM NEON or Intel AVX2/SSE4.2 is available
 */
bool has_simd_support(void);

/**
 * Get SIMD implementation type string.
 * 
 * @return "ARM NEON", "Intel AVX2", "Intel SSE4.2", or "None (scalar fallback)"
 */
const char* get_simd_type(void);

#endif /* ESHA256_SIMD_H */

