//
//  additional_hw_features.h
//  CSChecksum
//
//  Created by Charles Srstka on 3/15/26.
//

#ifndef __APPLE__

#include <stdbool.h>

bool supports_fusion_crc32c(void);

#if defined(__aarch64__) || defined(_M_ARM64)

#include <stdint.h>
#include <arm_acle.h>
#include <arm_neon.h>

#elif defined(__x86_64__) || defined(_M_X64)

#include <nmmintrin.h>
#include <immintrin.h>
#include <wmmintrin.h>

#endif

#endif
