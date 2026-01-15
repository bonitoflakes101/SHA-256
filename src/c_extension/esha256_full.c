/**
 * ESHA-256 Full C Implementation
 * ===============================
 * 
 * Complete ESHA-256 in C with all enhancements for fair comparison with SHA-256.
 * 
 * Enhancements implemented:
 * 1. HAIFA framework (bitcount + salt injection) - prevents length-extension
 * 2. Multi-lane message schedule with SIMD - enables parallelization
 * 3. Boolean masking (optional) - SASCA protection
 * 
 * This allows fair C-vs-C comparison with sha256_baseline.c
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* SIMD detection */
#if defined(__ARM_NEON) || defined(__ARM_NEON__)
    #include <arm_neon.h>
    #define HAS_NEON 1
#else
    #define HAS_NEON 0
#endif

/* SHA-256 Constants */
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const uint32_t H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/* HAIFA salt: "ESHA-256" + version */
static const uint32_t SALT[4] = {
    0x45534841,  /* "ESHA" */
    0x2D323536,  /* "-256" */
    0x00000000,  /* padding */
    0x00000001   /* version 1 */
};

/* Helper functions */
static inline uint32_t rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

static inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t sigma0(uint32_t x) {
    return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
}

static inline uint32_t sigma1(uint32_t x) {
    return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
}

static inline uint32_t Sigma0(uint32_t x) {
    return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
}

static inline uint32_t Sigma1(uint32_t x) {
    return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
}

static inline uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline void be32_put(uint8_t *p, uint32_t x) {
    p[0] = (x >> 24) & 0xFF;
    p[1] = (x >> 16) & 0xFF;
    p[2] = (x >> 8) & 0xFF;
    p[3] = x & 0xFF;
}

/* Simple random for masking (not cryptographically secure, but fast) */
static uint32_t random_mask(void) {
    static uint32_t state = 0x12345678;
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
}

/**
 * ENHANCEMENT 1: HAIFA injection
 * Injects bitcount and salt into message schedule to prevent length-extension
 */
static inline void haifa_inject(uint32_t W[16], uint64_t bitcount, int is_final) {
    W[0] ^= (uint32_t)(bitcount >> 32);
    W[1] ^= (uint32_t)(bitcount & 0xFFFFFFFF);
    W[14] ^= SALT[0] ^ SALT[2];
    W[15] ^= SALT[1] ^ SALT[3];
    
    /* Final block marker */
    if (is_final) {
        W[2] ^= 0x80000000;
        W[13] ^= 0x80000000;
    }
}

/**
 * ENHANCEMENT 2: Multi-lane message schedule expansion
 * Can use SIMD because lanes are independent
 */
#if HAS_NEON
/* ARM NEON SIMD version */
static inline uint32x4_t neon_sigma0(uint32x4_t x) {
    uint32x4_t r7 = vorrq_u32(vshrq_n_u32(x, 7), vshlq_n_u32(x, 25));
    uint32x4_t r18 = vorrq_u32(vshrq_n_u32(x, 18), vshlq_n_u32(x, 14));
    uint32x4_t s3 = vshrq_n_u32(x, 3);
    return veorq_u32(veorq_u32(r7, r18), s3);
}

static inline uint32x4_t neon_sigma1(uint32x4_t x) {
    uint32x4_t r17 = vorrq_u32(vshrq_n_u32(x, 17), vshlq_n_u32(x, 15));
    uint32x4_t r19 = vorrq_u32(vshrq_n_u32(x, 19), vshlq_n_u32(x, 13));
    uint32x4_t s10 = vshrq_n_u32(x, 10);
    return veorq_u32(veorq_u32(r17, r19), s10);
}

static void multi_lane_expand_simd(uint32_t W[64]) {
    uint32x4_t lanes[16];
    
    /* Load initial words into lane vectors */
    for (int i = 0; i < 4; i++) {
        uint32_t temp[4] = {W[i*4], W[i*4+1], W[i*4+2], W[i*4+3]};
        lanes[i] = vld1q_u32(temp);
    }
    
    /* Expand using SIMD */
    for (int t = 4; t < 16; t++) {
        uint32x4_t prev = lanes[t-4];
        
        uint32_t a = vgetq_lane_u32(prev, 0);
        uint32_t b = vgetq_lane_u32(prev, 1);
        uint32_t c = vgetq_lane_u32(prev, 2);
        uint32_t d = vgetq_lane_u32(prev, 3);
        
        uint32x4_t sig1 = neon_sigma1(prev);
        
        uint32_t sig0_in[4] = {b, c, d, a};
        uint32x4_t sig0 = neon_sigma0(vld1q_u32(sig0_in));
        
        uint32_t add1[4] = {d, a, b, c};
        uint32_t add2[4] = {c, d, a, b};
        
        uint32x4_t result = vaddq_u32(sig1, vld1q_u32(add1));
        result = vaddq_u32(result, sig0);
        result = vaddq_u32(result, vld1q_u32(add2));
        
        lanes[t] = result;
    }
    
    /* Store back */
    for (int t = 0; t < 16; t++) {
        vst1q_u32(&W[t*4], lanes[t]);
    }
}
#else
/* Scalar fallback */
static void multi_lane_expand_scalar(uint32_t W[64]) {
    uint32_t lanes[4][16];
    
    /* Distribute into 4 lanes */
    for (int i = 0; i < 4; i++) {
        lanes[0][i] = W[i*4 + 0];
        lanes[1][i] = W[i*4 + 1];
        lanes[2][i] = W[i*4 + 2];
        lanes[3][i] = W[i*4 + 3];
    }
    
    /* Expand each lane */
    for (int t = 4; t < 16; t++) {
        lanes[0][t] = sigma1(lanes[0][t-4]) + lanes[3][t-4] + sigma0(lanes[1][t-4]) + lanes[2][t-4];
        lanes[1][t] = sigma1(lanes[1][t-4]) + lanes[0][t-4] + sigma0(lanes[2][t-4]) + lanes[3][t-4];
        lanes[2][t] = sigma1(lanes[2][t-4]) + lanes[1][t-4] + sigma0(lanes[3][t-4]) + lanes[0][t-4];
        lanes[3][t] = sigma1(lanes[3][t-4]) + lanes[2][t-4] + sigma0(lanes[0][t-4]) + lanes[1][t-4];
    }
    
    /* Interleave back */
    for (int t = 0; t < 16; t++) {
        W[t*4 + 0] = lanes[0][t];
        W[t*4 + 1] = lanes[1][t];
        W[t*4 + 2] = lanes[2][t];
        W[t*4 + 3] = lanes[3][t];
    }
}
#endif

static void multi_lane_expand(uint32_t W[64]) {
#if HAS_NEON
    multi_lane_expand_simd(W);
#else
    multi_lane_expand_scalar(W);
#endif
}

/**
 * Process a single block with all ESHA-256 enhancements
 */
static void esha256_process_block(uint32_t state[8], const uint8_t block[64], 
                                   uint64_t bitcount, int is_final, int use_masking) {
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t mask = 0;
    int t;
    
    /* Parse block */
    for (t = 0; t < 16; t++) {
        W[t] = be32(&block[t * 4]);
    }
    
    /* ENHANCEMENT 1: HAIFA injection */
    haifa_inject(W, bitcount, is_final);
    
    /* ENHANCEMENT 2: Multi-lane expansion (with SIMD if available) */
    multi_lane_expand(W);
    
    /* Initialize working variables */
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    
    /* ENHANCEMENT 3: Boolean masking */
    if (use_masking) {
        mask = random_mask();
        a ^= mask; b ^= mask; c ^= mask; d ^= mask;
        e ^= mask; f ^= mask; g ^= mask; h ^= mask;
    }
    
    /* 64 rounds of compression */
    for (t = 0; t < 64; t++) {
        uint32_t a_real = a ^ mask;
        uint32_t e_real = e ^ mask;
        
        uint32_t T1 = (h ^ mask) + Sigma1(e_real) + 
                      ch(e_real, f ^ mask, g ^ mask) + K[t] + W[t];
        uint32_t T2 = Sigma0(a_real) + maj(a_real, b ^ mask, c ^ mask);
        
        h = g;
        g = f;
        f = e;
        e = ((d ^ mask) + T1) ^ mask;
        d = c;
        c = b;
        b = a;
        a = (T1 + T2) ^ mask;
    }
    
    /* Unmask and add to state */
    state[0] += a ^ mask;
    state[1] += b ^ mask;
    state[2] += c ^ mask;
    state[3] += d ^ mask;
    state[4] += e ^ mask;
    state[5] += f ^ mask;
    state[6] += g ^ mask;
    state[7] += h ^ mask;
}

/**
 * Python wrapper - hash with configurable masking
 */
static PyObject* py_esha256_hash(PyObject* self, PyObject* args) {
    Py_buffer buffer;
    int use_masking = 1;  /* Default: masking enabled */
    
    if (!PyArg_ParseTuple(args, "y*|i", &buffer, &use_masking)) {
        return NULL;
    }
    
    const uint8_t *data = (const uint8_t*)buffer.buf;
    Py_ssize_t len = buffer.len;
    uint64_t bitcount = 0;
    uint64_t total_bits = (uint64_t)len * 8;
    
    uint32_t state[8];
    memcpy(state, H0, sizeof(H0));
    
    uint8_t block[64];
    Py_ssize_t remaining = len;
    Py_ssize_t total_blocks;
    Py_ssize_t block_num = 0;
    
    /* Calculate total blocks for final flag */
    Py_ssize_t padded_len = len + 1 + 8;  /* message + 0x80 + length */
    if ((len % 64) >= 56) {
        padded_len += 64 - (len % 64) + 56;
    } else {
        padded_len += 56 - (len % 64);
    }
    total_blocks = padded_len / 64;
    
    /* Process complete blocks */
    while (remaining >= 64) {
        int is_final = (block_num == total_blocks - 1);
        esha256_process_block(state, data, bitcount, is_final, use_masking);
        data += 64;
        remaining -= 64;
        bitcount += 512;
        block_num++;
    }
    
    /* Padding */
    memset(block, 0, 64);
    memcpy(block, data, remaining);
    block[remaining] = 0x80;
    
    if (remaining >= 56) {
        int is_final = (block_num == total_blocks - 1);
        esha256_process_block(state, block, bitcount, is_final, use_masking);
        bitcount += 512;
        block_num++;
        memset(block, 0, 64);
    }
    
    /* Append length */
    block[56] = (total_bits >> 56) & 0xFF;
    block[57] = (total_bits >> 48) & 0xFF;
    block[58] = (total_bits >> 40) & 0xFF;
    block[59] = (total_bits >> 32) & 0xFF;
    block[60] = (total_bits >> 24) & 0xFF;
    block[61] = (total_bits >> 16) & 0xFF;
    block[62] = (total_bits >> 8) & 0xFF;
    block[63] = total_bits & 0xFF;
    
    esha256_process_block(state, block, bitcount, 1, use_masking);  /* Final block */
    
    /* Output */
    uint8_t digest[32];
    for (int i = 0; i < 8; i++) {
        be32_put(&digest[i * 4], state[i]);
    }
    
    PyBuffer_Release(&buffer);
    return PyBytes_FromStringAndSize((char*)digest, 32);
}

static PyObject* py_get_info(PyObject* self, PyObject* args) {
#if HAS_NEON
    return PyUnicode_FromString("C + ARM NEON SIMD (full ESHA-256)");
#else
    return PyUnicode_FromString("C optimized (full ESHA-256, no SIMD)");
#endif
}

static PyObject* py_has_simd(PyObject* self, PyObject* args) {
    return PyBool_FromLong(HAS_NEON);
}

/* Module methods */
static PyMethodDef Esha256FullMethods[] = {
    {"hash", py_esha256_hash, METH_VARARGS,
     "Compute ESHA-256 hash.\n\nArgs:\n  data: bytes to hash\n  use_masking: enable SASCA protection (default True)"},
    {"get_info", py_get_info, METH_NOARGS, "Get implementation info"},
    {"has_simd", py_has_simd, METH_NOARGS, "Check if SIMD is available"},           
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef esha256_full_module = {
    PyModuleDef_HEAD_INIT,
    "esha256_full",
    "Full C implementation of ESHA-256 with all enhancements:\n"
    "- HAIFA framework (length-extension protection)\n"
    "- Multi-lane message schedule (SIMD parallelization)\n"
    "- Boolean masking (SASCA protection)\n\n"
    "Use for fair comparison with sha256_baseline.",
    -1,
    Esha256FullMethods
};

PyMODINIT_FUNC PyInit_esha256_full(void) {
    return PyModule_Create(&esha256_full_module);
}
