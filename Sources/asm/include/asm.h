//
//  asm.h
//  CSChecksum
//
//  Created by Charles Srstka on 1/19/25.
//

#import "additional_hw_features.h"

#define ALWAYS_INLINE static __inline __attribute__((always_inline))

#if defined(__aarch64__) || defined(_M_ARM64)

#include <arm_neon.h>

ALWAYS_INLINE uint64x2_t clmul_lo(uint64x2_t a, uint64x2_t b) {
  uint64x2_t r;
  __asm("pmull %0.1q, %1.1d, %2.1d\n" : "=w"(r) : "w"(a), "w"(b));
  return r;
}

ALWAYS_INLINE uint64x2_t clmul_hi(uint64x2_t a, uint64x2_t b) {
  uint64x2_t r;
  __asm("pmull2 %0.1q, %1.2d, %2.2d\n" : "=w"(r) : "w"(a), "w"(b));
  return r;
}

ALWAYS_INLINE uint64x2_t eor3(uint64x2_t a, uint64x2_t b, uint64x2_t c) {
    uint64x2_t r;
    asm(".arch_extension sha3\n" "eor3 %0.16b, %1.16b, %2.16b, %3.16b" : "=w"(r) : "w"(a), "w"(b), "w"(c));
    return r;
}

#elif defined(__x86_64__) || defined(_M_X64)

#include <nmmintrin.h>
#include <immintrin.h>
#include <wmmintrin.h>

__attribute__((target("pclmul")))
ALWAYS_INLINE __m128i clmul_lo(__m128i a, __m128i b) {
    return _mm_clmulepi64_si128(a, b, 0x00);
}

__attribute__((target("pclmul")))
ALWAYS_INLINE __m128i clmul_hi(__m128i a, __m128i b) {
    return _mm_clmulepi64_si128(a, b, 0x11);
}

#endif
