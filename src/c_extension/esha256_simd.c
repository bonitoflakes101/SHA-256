/**
 * ESHA-256 SIMD Implementation
 * ============================
 * 
 * SIMD-optimized multi-lane message schedule expansion for ESHA-256.
 * 
 * Supported architectures:
 * - ARM NEON (Apple Silicon M1/M2/M3, ARM64 Linux)
 * - Intel AVX2 (Haswell and newer)
 * - Intel SSE4.2 (fallback for older Intel/AMD)
 * - Scalar (portable fallback)
 * 
 * The multi-lane design naturally maps to SIMD:
 * - 4 lanes × 32-bit words = 128-bit SIMD registers
 * - All 4 lanes computed in parallel with single instruction
 * 
 * Author: ESHA-256 Thesis Project
 * Date: January 2026
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "esha256_simd.h"
#include <string.h>

/* ============================================================================
 * Architecture Detection
 * ============================================================================ */

#if defined(__ARM_NEON) || defined(__ARM_NEON__)
    #include <arm_neon.h>
    #define SIMD_ARM_NEON 1
    #define HAS_SIMD 1
    #define SIMD_TYPE_STR "ARM NEON"
#elif defined(__AVX2__)
    #include <immintrin.h>
    #define SIMD_AVX2 1
    #define HAS_SIMD 1
    #define SIMD_TYPE_STR "Intel AVX2"
#elif defined(__SSE4_2__) || defined(__SSE4_1__)
    #include <smmintrin.h>
    #define SIMD_SSE4 1
    #define HAS_SIMD 1
    #define SIMD_TYPE_STR "Intel SSE4.2"
#else
    #define HAS_SIMD 0
    #define SIMD_TYPE_STR "None (scalar fallback)"
#endif

/* ============================================================================
 * Scalar Helper Functions (used by all implementations)
 * ============================================================================ */

/**
 * Right rotate 32-bit value
 */
static inline uint32_t rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

/**
 * σ₀(x) = ROTR⁷(x) ⊕ ROTR¹⁸(x) ⊕ SHR³(x)
 * Used in message schedule expansion
 */
static inline uint32_t sigma0(uint32_t x) {
    return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
}

/**
 * σ₁(x) = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x)
 * Used in message schedule expansion
 */
static inline uint32_t sigma1(uint32_t x) {
    return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
}

/* ============================================================================
 * ARM NEON Implementation
 * ============================================================================ */

#ifdef SIMD_ARM_NEON

/**
 * NEON σ₀: processes 4 values in parallel
 */
static inline uint32x4_t neon_sigma0(uint32x4_t x) {
    /* ROTR⁷(x) */
    uint32x4_t r7 = vorrq_u32(vshrq_n_u32(x, 7), vshlq_n_u32(x, 25));
    /* ROTR¹⁸(x) */
    uint32x4_t r18 = vorrq_u32(vshrq_n_u32(x, 18), vshlq_n_u32(x, 14));
    /* SHR³(x) */
    uint32x4_t s3 = vshrq_n_u32(x, 3);
    /* XOR all together */
    return veorq_u32(veorq_u32(r7, r18), s3);
}

/**
 * NEON σ₁: processes 4 values in parallel
 */
static inline uint32x4_t neon_sigma1(uint32x4_t x) {
    /* ROTR¹⁷(x) */
    uint32x4_t r17 = vorrq_u32(vshrq_n_u32(x, 17), vshlq_n_u32(x, 15));
    /* ROTR¹⁹(x) */
    uint32x4_t r19 = vorrq_u32(vshrq_n_u32(x, 19), vshlq_n_u32(x, 13));
    /* SHR¹⁰(x) */
    uint32x4_t s10 = vshrq_n_u32(x, 10);
    /* XOR all together */
    return veorq_u32(veorq_u32(r17, r19), s10);
}

/**
 * ARM NEON multi-lane schedule expansion
 * 
 * Key insight: Pack all 4 lanes into a single 128-bit register
 * Each lane element at position t is in the same vector position
 */
static void multi_lane_schedule_neon(const uint32_t words_in[16], uint32_t W_out[64]) {
    uint32x4_t lanes[16];
    
    /* 
     * Load initial 4 positions into lanes
     * Each vector holds one element from each of the 4 lanes:
     * lanes[0] = {lane_A[0], lane_B[0], lane_C[0], lane_D[0]}
     *          = {words[0], words[1], words[2], words[3]}
     */
    for (int i = 0; i < 4; i++) {
        /* Load 4 consecutive words from words_in[i*4 .. i*4+3] */
        /* This gives us position i from all 4 lanes */
        uint32_t temp[4];
        temp[0] = words_in[i * 4 + 0];  /* Lane A position i: words[0,4,8,12] */
        temp[1] = words_in[i * 4 + 1];  /* Lane B position i: words[1,5,9,13] */
        temp[2] = words_in[i * 4 + 2];  /* Lane C position i: words[2,6,10,14] */
        temp[3] = words_in[i * 4 + 3];  /* Lane D position i: words[3,7,11,15] */
        lanes[i] = vld1q_u32(temp);
    }
    
    /*
     * Expand from 4 to 16 positions using SIMD
     * 
     * Expansion formula (from Python):
     *   lane_A[t] = σ₁(lane_A[t-4]) + lane_D[t-4] + σ₀(lane_B[t-4]) + lane_C[t-4]
     *   lane_B[t] = σ₁(lane_B[t-4]) + lane_A[t-4] + σ₀(lane_C[t-4]) + lane_D[t-4]
     *   lane_C[t] = σ₁(lane_C[t-4]) + lane_B[t-4] + σ₀(lane_D[t-4]) + lane_A[t-4]
     *   lane_D[t] = σ₁(lane_D[t-4]) + lane_C[t-4] + σ₀(lane_A[t-4]) + lane_B[t-4]
     * 
     * In vector form with lanes[t] = {A[t], B[t], C[t], D[t]}:
     *   new[t] = σ₁(lanes[t-4]) + rotate_right(lanes[t-4], 1) + 
     *            σ₀(rotate_left(lanes[t-4], 1)) + rotate_left(lanes[t-4], 2)
     */
    for (int t = 4; t < 16; t++) {
        uint32x4_t prev = lanes[t - 4];
        
        /* Extract individual lane values for cross-lane operations */
        uint32_t a_prev = vgetq_lane_u32(prev, 0);  /* Lane A[t-4] */
        uint32_t b_prev = vgetq_lane_u32(prev, 1);  /* Lane B[t-4] */
        uint32_t c_prev = vgetq_lane_u32(prev, 2);  /* Lane C[t-4] */
        uint32_t d_prev = vgetq_lane_u32(prev, 3);  /* Lane D[t-4] */
        
        /* Compute σ₁ for each lane's own previous value */
        uint32x4_t sig1_vec = neon_sigma1(prev);
        
        /* Build σ₀ input vector: {B, C, D, A} - rotated left by 1 */
        uint32_t sig0_input[4] = {b_prev, c_prev, d_prev, a_prev};
        uint32x4_t sig0_vec = neon_sigma0(vld1q_u32(sig0_input));
        
        /* Build addition vectors for cross-lane mixing */
        /* lane_A gets D, lane_B gets A, lane_C gets B, lane_D gets C */
        uint32_t add1[4] = {d_prev, a_prev, b_prev, c_prev};  /* Rotated right by 1 */
        uint32x4_t add1_vec = vld1q_u32(add1);
        
        /* lane_A gets C, lane_B gets D, lane_C gets A, lane_D gets B */
        uint32_t add2[4] = {c_prev, d_prev, a_prev, b_prev};  /* Rotated left by 2 */
        uint32x4_t add2_vec = vld1q_u32(add2);
        
        /* Compute: σ₁(self) + cross1 + σ₀(cross2) + cross3 */
        uint32x4_t result = vaddq_u32(sig1_vec, add1_vec);
        result = vaddq_u32(result, sig0_vec);
        result = vaddq_u32(result, add2_vec);
        
        lanes[t] = result;
    }
    
    /*
     * Interleave lanes back into W_out[0..63]
     * W[t*4 + 0] = lane_A[t]
     * W[t*4 + 1] = lane_B[t]
     * W[t*4 + 2] = lane_C[t]
     * W[t*4 + 3] = lane_D[t]
     */
    for (int t = 0; t < 16; t++) {
        vst1q_u32(&W_out[t * 4], lanes[t]);
    }
}

#endif /* SIMD_ARM_NEON */

/* ============================================================================
 * Intel AVX2 Implementation
 * ============================================================================ */

#ifdef SIMD_AVX2

/**
 * AVX2/SSE σ₀: processes 4 values in parallel using 128-bit SSE
 */
static inline __m128i avx_sigma0(__m128i x) {
    /* ROTR⁷(x) */
    __m128i r7 = _mm_or_si128(_mm_srli_epi32(x, 7), _mm_slli_epi32(x, 25));
    /* ROTR¹⁸(x) */
    __m128i r18 = _mm_or_si128(_mm_srli_epi32(x, 18), _mm_slli_epi32(x, 14));
    /* SHR³(x) */
    __m128i s3 = _mm_srli_epi32(x, 3);
    /* XOR all together */
    return _mm_xor_si128(_mm_xor_si128(r7, r18), s3);
}

/**
 * AVX2/SSE σ₁: processes 4 values in parallel using 128-bit SSE
 */
static inline __m128i avx_sigma1(__m128i x) {
    /* ROTR¹⁷(x) */
    __m128i r17 = _mm_or_si128(_mm_srli_epi32(x, 17), _mm_slli_epi32(x, 15));
    /* ROTR¹⁹(x) */
    __m128i r19 = _mm_or_si128(_mm_srli_epi32(x, 19), _mm_slli_epi32(x, 13));
    /* SHR¹⁰(x) */
    __m128i s10 = _mm_srli_epi32(x, 10);
    /* XOR all together */
    return _mm_xor_si128(_mm_xor_si128(r17, r19), s10);
}

/**
 * Intel AVX2 multi-lane schedule expansion
 */
static void multi_lane_schedule_avx2(const uint32_t words_in[16], uint32_t W_out[64]) {
    __m128i lanes[16];
    
    /* Load initial 4 positions */
    for (int i = 0; i < 4; i++) {
        uint32_t temp[4];
        temp[0] = words_in[i * 4 + 0];
        temp[1] = words_in[i * 4 + 1];
        temp[2] = words_in[i * 4 + 2];
        temp[3] = words_in[i * 4 + 3];
        lanes[i] = _mm_loadu_si128((__m128i*)temp);
    }
    
    /* Expand from 4 to 16 positions */
    for (int t = 4; t < 16; t++) {
        __m128i prev = lanes[t - 4];
        
        /* Extract individual values */
        uint32_t temp[4];
        _mm_storeu_si128((__m128i*)temp, prev);
        uint32_t a_prev = temp[0];
        uint32_t b_prev = temp[1];
        uint32_t c_prev = temp[2];
        uint32_t d_prev = temp[3];
        
        /* σ₁ of own previous values */
        __m128i sig1_vec = avx_sigma1(prev);
        
        /* σ₀ of rotated values: {B, C, D, A} */
        uint32_t sig0_input[4] = {b_prev, c_prev, d_prev, a_prev};
        __m128i sig0_vec = avx_sigma0(_mm_loadu_si128((__m128i*)sig0_input));
        
        /* Cross-lane additions */
        uint32_t add1[4] = {d_prev, a_prev, b_prev, c_prev};
        __m128i add1_vec = _mm_loadu_si128((__m128i*)add1);
        
        uint32_t add2[4] = {c_prev, d_prev, a_prev, b_prev};
        __m128i add2_vec = _mm_loadu_si128((__m128i*)add2);
        
        /* Compute result */
        __m128i result = _mm_add_epi32(sig1_vec, add1_vec);
        result = _mm_add_epi32(result, sig0_vec);
        result = _mm_add_epi32(result, add2_vec);
        
        lanes[t] = result;
    }
    
    /* Store results */
    for (int t = 0; t < 16; t++) {
        _mm_storeu_si128((__m128i*)&W_out[t * 4], lanes[t]);
    }
}

#endif /* SIMD_AVX2 */

/* ============================================================================
 * Intel SSE4.2 Implementation (fallback for older Intel)
 * ============================================================================ */

#ifdef SIMD_SSE4

/**
 * SSE4 σ₀
 */
static inline __m128i sse_sigma0(__m128i x) {
    __m128i r7 = _mm_or_si128(_mm_srli_epi32(x, 7), _mm_slli_epi32(x, 25));
    __m128i r18 = _mm_or_si128(_mm_srli_epi32(x, 18), _mm_slli_epi32(x, 14));
    __m128i s3 = _mm_srli_epi32(x, 3);
    return _mm_xor_si128(_mm_xor_si128(r7, r18), s3);
}

/**
 * SSE4 σ₁
 */
static inline __m128i sse_sigma1(__m128i x) {
    __m128i r17 = _mm_or_si128(_mm_srli_epi32(x, 17), _mm_slli_epi32(x, 15));
    __m128i r19 = _mm_or_si128(_mm_srli_epi32(x, 19), _mm_slli_epi32(x, 13));
    __m128i s10 = _mm_srli_epi32(x, 10);
    return _mm_xor_si128(_mm_xor_si128(r17, r19), s10);
}

/**
 * Intel SSE4.2 multi-lane schedule expansion
 */
static void multi_lane_schedule_sse4(const uint32_t words_in[16], uint32_t W_out[64]) {
    __m128i lanes[16];
    
    for (int i = 0; i < 4; i++) {
        uint32_t temp[4];
        temp[0] = words_in[i * 4 + 0];
        temp[1] = words_in[i * 4 + 1];
        temp[2] = words_in[i * 4 + 2];
        temp[3] = words_in[i * 4 + 3];
        lanes[i] = _mm_loadu_si128((__m128i*)temp);
    }
    
    for (int t = 4; t < 16; t++) {
        __m128i prev = lanes[t - 4];
        
        uint32_t temp[4];
        _mm_storeu_si128((__m128i*)temp, prev);
        uint32_t a_prev = temp[0];
        uint32_t b_prev = temp[1];
        uint32_t c_prev = temp[2];
        uint32_t d_prev = temp[3];
        
        __m128i sig1_vec = sse_sigma1(prev);
        
        uint32_t sig0_input[4] = {b_prev, c_prev, d_prev, a_prev};
        __m128i sig0_vec = sse_sigma0(_mm_loadu_si128((__m128i*)sig0_input));
        
        uint32_t add1[4] = {d_prev, a_prev, b_prev, c_prev};
        __m128i add1_vec = _mm_loadu_si128((__m128i*)add1);
        
        uint32_t add2[4] = {c_prev, d_prev, a_prev, b_prev};
        __m128i add2_vec = _mm_loadu_si128((__m128i*)add2);
        
        __m128i result = _mm_add_epi32(sig1_vec, add1_vec);
        result = _mm_add_epi32(result, sig0_vec);
        result = _mm_add_epi32(result, add2_vec);
        
        lanes[t] = result;
    }
    
    for (int t = 0; t < 16; t++) {
        _mm_storeu_si128((__m128i*)&W_out[t * 4], lanes[t]);
    }
}

#endif /* SIMD_SSE4 */

/* ============================================================================
 * Scalar Fallback Implementation
 * ============================================================================ */

/**
 * Portable scalar multi-lane schedule expansion
 * Used when no SIMD is available
 */
static void multi_lane_schedule_scalar(const uint32_t words_in[16], uint32_t W_out[64]) {
    uint32_t lanes[4][16];
    
    /*
     * Distribute initial words into 4 lanes
     * Lane A: words[0], words[4], words[8], words[12]
     * Lane B: words[1], words[5], words[9], words[13]
     * Lane C: words[2], words[6], words[10], words[14]
     * Lane D: words[3], words[7], words[11], words[15]
     */
    for (int i = 0; i < 4; i++) {
        lanes[0][i] = words_in[i * 4 + 0];  /* Lane A */
        lanes[1][i] = words_in[i * 4 + 1];  /* Lane B */
        lanes[2][i] = words_in[i * 4 + 2];  /* Lane C */
        lanes[3][i] = words_in[i * 4 + 3];  /* Lane D */
    }
    
    /*
     * Expand each lane from 4 to 16 words with cross-lane mixing
     * Matches Python implementation exactly
     */
    for (int t = 4; t < 16; t++) {
        /* lane_A[t] = σ₁(lane_A[t-4]) + lane_D[t-4] + σ₀(lane_B[t-4]) + lane_C[t-4] */
        lanes[0][t] = sigma1(lanes[0][t-4]) + lanes[3][t-4] + 
                      sigma0(lanes[1][t-4]) + lanes[2][t-4];
        
        /* lane_B[t] = σ₁(lane_B[t-4]) + lane_A[t-4] + σ₀(lane_C[t-4]) + lane_D[t-4] */
        lanes[1][t] = sigma1(lanes[1][t-4]) + lanes[0][t-4] + 
                      sigma0(lanes[2][t-4]) + lanes[3][t-4];
        
        /* lane_C[t] = σ₁(lane_C[t-4]) + lane_B[t-4] + σ₀(lane_D[t-4]) + lane_A[t-4] */
        lanes[2][t] = sigma1(lanes[2][t-4]) + lanes[1][t-4] + 
                      sigma0(lanes[3][t-4]) + lanes[0][t-4];
        
        /* lane_D[t] = σ₁(lane_D[t-4]) + lane_C[t-4] + σ₀(lane_A[t-4]) + lane_B[t-4] */
        lanes[3][t] = sigma1(lanes[3][t-4]) + lanes[2][t-4] + 
                      sigma0(lanes[0][t-4]) + lanes[1][t-4];
    }
    
    /*
     * Interleave lanes back into W[0..63]
     * W[t*4 + 0] = lane_A[t]
     * W[t*4 + 1] = lane_B[t]
     * W[t*4 + 2] = lane_C[t]
     * W[t*4 + 3] = lane_D[t]
     */
    for (int t = 0; t < 16; t++) {
        W_out[t * 4 + 0] = lanes[0][t];
        W_out[t * 4 + 1] = lanes[1][t];
        W_out[t * 4 + 2] = lanes[2][t];
        W_out[t * 4 + 3] = lanes[3][t];
    }
}

/* ============================================================================
 * Public API
 * ============================================================================ */

void multi_lane_schedule_simd(const uint32_t words_in[16], uint32_t W_out[64]) {
#ifdef SIMD_ARM_NEON
    multi_lane_schedule_neon(words_in, W_out);
#elif defined(SIMD_AVX2)
    multi_lane_schedule_avx2(words_in, W_out);
#elif defined(SIMD_SSE4)
    multi_lane_schedule_sse4(words_in, W_out);
#else
    multi_lane_schedule_scalar(words_in, W_out);
#endif
}

bool has_simd_support(void) {
    return HAS_SIMD;
}

const char* get_simd_type(void) {
    return SIMD_TYPE_STR;
}

/* ============================================================================
 * Python C API Bindings
 * ============================================================================ */

/**
 * Python wrapper for multi_lane_schedule_simd
 * 
 * Args:
 *     words_in: List of 16 uint32 values (after HAIFA injection)
 * 
 * Returns:
 *     List of 64 uint32 values (expanded message schedule)
 */
static PyObject* py_multi_lane_schedule_simd(PyObject* self, PyObject* args) {
    PyObject* list_obj;
    
    if (!PyArg_ParseTuple(args, "O", &list_obj)) {
        return NULL;
    }
    
    if (!PyList_Check(list_obj)) {
        PyErr_SetString(PyExc_TypeError, "Expected a list");
        return NULL;
    }
    
    Py_ssize_t size = PyList_Size(list_obj);
    if (size != 16) {
        PyErr_SetString(PyExc_ValueError, "Expected list of exactly 16 uint32 values");
        return NULL;
    }
    
    /* Convert Python list to C array */
    uint32_t words_in[16];
    for (int i = 0; i < 16; i++) {
        PyObject* item = PyList_GetItem(list_obj, i);
        if (item == NULL) {
            return NULL;
        }
        if (!PyLong_Check(item)) {
            PyErr_SetString(PyExc_TypeError, "List items must be integers");
            return NULL;
        }
        unsigned long val = PyLong_AsUnsignedLong(item);
        if (val == (unsigned long)-1 && PyErr_Occurred()) {
            return NULL;
        }
        words_in[i] = (uint32_t)(val & 0xFFFFFFFF);
    }
    
    /* Perform SIMD expansion */
    uint32_t W_out[64];
    multi_lane_schedule_simd(words_in, W_out);
    
    /* Convert C array back to Python list */
    PyObject* result = PyList_New(64);
    if (result == NULL) {
        return NULL;
    }
    
    for (int i = 0; i < 64; i++) {
        PyObject* val = PyLong_FromUnsignedLong(W_out[i]);
        if (val == NULL) {
            Py_DECREF(result);
            return NULL;
        }
        PyList_SET_ITEM(result, i, val);
    }
    
    return result;
}

/**
 * Python wrapper for has_simd_support
 */
static PyObject* py_has_simd_support(PyObject* self, PyObject* args) {
    return PyBool_FromLong(has_simd_support());
}

/**
 * Python wrapper for get_simd_type
 */
static PyObject* py_get_simd_type(PyObject* self, PyObject* args) {
    return PyUnicode_FromString(get_simd_type());
}

/* Module method table */
static PyMethodDef EshaSIMDMethods[] = {
    {
        "multi_lane_schedule_simd",
        py_multi_lane_schedule_simd,
        METH_VARARGS,
        "SIMD-optimized multi-lane message schedule expansion.\n\n"
        "Args:\n"
        "    words_in: List of 16 uint32 values (after HAIFA injection)\n\n"
        "Returns:\n"
        "    List of 64 uint32 values (expanded message schedule)"
    },
    {
        "has_simd_support",
        py_has_simd_support,
        METH_NOARGS,
        "Check if SIMD is available on this CPU.\n\n"
        "Returns:\n"
        "    True if ARM NEON or Intel AVX2/SSE4 is available"
    },
    {
        "get_simd_type",
        py_get_simd_type,
        METH_NOARGS,
        "Get the SIMD implementation type.\n\n"
        "Returns:\n"
        "    String: 'ARM NEON', 'Intel AVX2', 'Intel SSE4.2', or 'None (scalar fallback)'"
    },
    {NULL, NULL, 0, NULL}  /* Sentinel */
};

/* Module definition */
static struct PyModuleDef esha256_simd_module = {
    PyModuleDef_HEAD_INIT,
    "esha256_simd",
    "SIMD-optimized functions for ESHA-256 multi-lane message schedule.\n\n"
    "This module provides hardware-accelerated message schedule expansion\n"
    "using ARM NEON (Apple Silicon) or Intel AVX2/SSE4.2 SIMD instructions.\n"
    "Falls back to optimized scalar code if no SIMD is available.",
    -1,
    EshaSIMDMethods
};

/* Module initialization */
PyMODINIT_FUNC PyInit_esha256_simd(void) {
    return PyModule_Create(&esha256_simd_module);
}

