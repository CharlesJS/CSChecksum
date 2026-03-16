//
//  additional_hw_features.c
//  CSChecksum
//
//  Created by Charles Srstka on 1/22/25.
//

#include "additional_hw_features.h"

#ifndef __APPLE__
#if defined(__aarch64__) || defined(_M_ARM64)
#include <sys/auxv.h>

#ifndef HWCAP_PMULL
#define HWCAP_PMULL (1 << 4)
#endif
#ifndef HWCAP_CRC32
#define HWCAP_CRC32 (1 << 7)
#endif
#ifndef HWCAP_SHA3
#define HWCAP_SHA3  (1 << 17)
#endif

bool supports_fusion_crc32c(void) {
    unsigned long hwcap = getauxval(AT_HWCAP);
    return (hwcap & HWCAP_CRC32) != 0 && (hwcap & HWCAP_PMULL) != 0 && (hwcap & HWCAP_SHA3) != 0;
}

#else

#include <cpuid.h>

#define CPUID_ECX_PCLMULQDQ (1 << 1)
#define CPUID_ECX_SSE42     (1 << 20)

bool supports_fusion_crc32c(void) {
    unsigned int eax, ebx, ecx, edx;
    if (!(__get_cpuid(1, &eax, &ebx, &ecx, &edx))) {
        return false;
    }

    return (ecx & CPUID_ECX_SSE42) != 0 && (ecx & CPUID_ECX_PCLMULQDQ) != 0;
}

#endif
#endif
