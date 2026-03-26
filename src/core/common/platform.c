/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Platform detection, architecture identification, and CPU feature probing.
 */

#include "core/common/platform.h"
#include "pqc/common.h"

#include <string.h>

/* -------------------------------------------------------------------------- */
/* CPUID intrinsics for x86/x86_64                                           */
/* -------------------------------------------------------------------------- */

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#   define PQC_X86_CPUID 1
#   if defined(_MSC_VER)
#       include <intrin.h>
#       define pqc_cpuid(info, leaf)    __cpuid((int *)(info), (int)(leaf))
#       define pqc_cpuidex(info, leaf, sub) __cpuidex((int *)(info), (int)(leaf), (int)(sub))
#   elif defined(__GNUC__) || defined(__clang__)
#       include <cpuid.h>
static inline void
pqc_cpuid(uint32_t info[4], uint32_t leaf)
{
    __cpuid(leaf, info[0], info[1], info[2], info[3]);
}
static inline void
pqc_cpuidex(uint32_t info[4], uint32_t leaf, uint32_t sub)
{
    __cpuid_count(leaf, sub, info[0], info[1], info[2], info[3]);
}
#   endif

/*
 * Read the XCR0 register (XGETBV) to check OS support for AVX state.
 */
static inline uint64_t
pqc_xgetbv(uint32_t xcr)
{
#   if defined(_MSC_VER)
    return _xgetbv(xcr);
#   elif defined(__GNUC__) || defined(__clang__)
    uint32_t lo, hi;
    __asm__ __volatile__("xgetbv" : "=a"(lo), "=d"(hi) : "c"(xcr));
    return ((uint64_t)hi << 32) | lo;
#   else
    (void)xcr;
    return 0;
#   endif
}
#endif /* x86 CPUID */

/* -------------------------------------------------------------------------- */
/* ARM feature detection                                                      */
/* -------------------------------------------------------------------------- */

#if defined(__aarch64__) || defined(_M_ARM64)
#   define PQC_AARCH64 1
#   if defined(__linux__)
#       include <sys/auxv.h>
#       include <asm/hwcap.h>
#   elif defined(__APPLE__)
#       include <sys/sysctl.h>
#   endif
#elif defined(__arm__) || defined(_M_ARM)
#   define PQC_ARM32 1
#   if defined(__linux__)
#       include <sys/auxv.h>
#       include <asm/hwcap.h>
#   endif
#endif

/* -------------------------------------------------------------------------- */
/* Platform name                                                              */
/* -------------------------------------------------------------------------- */

const char *
pqc_get_platform_name(void)
{
#if defined(_WIN32)
    return "windows";
#elif defined(__linux__)
    return "linux";
#elif defined(__APPLE__) && defined(__MACH__)
    return "macos";
#elif defined(__FreeBSD__)
    return "freebsd";
#else
    return "unix";
#endif
}

/* -------------------------------------------------------------------------- */
/* Architecture name                                                          */
/* -------------------------------------------------------------------------- */

const char *
pqc_get_arch_name(void)
{
#if defined(__x86_64__) || defined(_M_X64)
    return "x86_64";
#elif defined(__aarch64__) || defined(_M_ARM64)
    return "aarch64";
#elif defined(__arm__) || defined(_M_ARM)
    return "arm";
#elif defined(__i386__) || defined(_M_IX86)
    return "x86";
#else
    return "generic";
#endif
}

/* -------------------------------------------------------------------------- */
/* CPU feature detection                                                      */
/* -------------------------------------------------------------------------- */

static pqc_cpu_features_t s_features;
static int                s_detected = 0;

static void
detect_features(void)
{
    memset(&s_features, 0, sizeof(s_features));

#if defined(PQC_X86_CPUID)
    {
        uint32_t info[4] = {0};
        uint32_t max_leaf;

        pqc_cpuid(info, 0);
        max_leaf = info[0];

        if (max_leaf >= 1) {
            pqc_cpuid(info, 1);
            /* ECX bits from leaf 1 */
            s_features.has_sse2   = (info[3] >> 26) & 1u;  /* EDX bit 26 */
            s_features.has_sse41  = (info[2] >> 19) & 1u;  /* ECX bit 19 */
            s_features.has_pclmul = (info[2] >>  1) & 1u;  /* ECX bit  1 */
            s_features.has_aesni  = (info[2] >> 25) & 1u;  /* ECX bit 25 */

            /* Check OSXSAVE (ECX bit 27) before probing AVX/AVX2/AVX-512 */
            if ((info[2] >> 27) & 1u) {
                uint64_t xcr0 = pqc_xgetbv(0);
                int os_avx = ((xcr0 & 0x06) == 0x06);  /* XMM + YMM */

                if (max_leaf >= 7) {
                    pqc_cpuidex(info, 7, 0);
                    /* EBX bits from leaf 7, sub-leaf 0 */
                    if (os_avx) {
                        s_features.has_avx2 = (info[1] >> 5) & 1u;
                        s_features.has_bmi2 = (info[1] >> 8) & 1u;
                    }
                    s_features.has_sha_ni = (info[1] >> 29) & 1u;

                    /* AVX-512: requires OS support for ZMM (xcr0 bits 5,6,7) */
                    if (os_avx && ((xcr0 >> 5) & 0x07) == 0x07) {
                        uint32_t avx512f = (info[1] >> 16) & 1u;
                        s_features.has_avx512 = avx512f;
                    }
                }
            }
        }
    }
#endif /* PQC_X86_CPUID */

#if defined(PQC_AARCH64)
    {
#   if defined(__linux__)
        unsigned long hwcap  = getauxval(AT_HWCAP);
        s_features.has_neon = 1;  /* NEON is mandatory on AArch64 */
        s_features.has_aes  = (hwcap & HWCAP_AES)    ? 1 : 0;
        s_features.has_sha2 = (hwcap & HWCAP_SHA2)   ? 1 : 0;
#       ifdef HWCAP_SHA3
        s_features.has_sha3 = (hwcap & HWCAP_SHA3)   ? 1 : 0;
#       endif
#       ifdef HWCAP_SVE
        s_features.has_sve  = (hwcap & HWCAP_SVE)    ? 1 : 0;
#       endif
#   elif defined(__APPLE__)
        /* On Apple Silicon, NEON/AES/SHA2 are always available */
        s_features.has_neon = 1;
        s_features.has_aes  = 1;
        s_features.has_sha2 = 1;
        s_features.has_sha3 = 1;
#   else
        /* Conservative: assume only NEON on AArch64 */
        s_features.has_neon = 1;
#   endif
    }
#endif /* PQC_AARCH64 */

#if defined(PQC_ARM32)
    {
#   if defined(__linux__)
        unsigned long hwcap = getauxval(AT_HWCAP);
        s_features.has_neon = (hwcap & HWCAP_NEON) ? 1 : 0;
#   endif
    }
#endif /* PQC_ARM32 */
}

const pqc_cpu_features_t *
pqc_cpu_detect(void)
{
    if (!s_detected) {
        detect_features();
        s_detected = 1;
    }
    return &s_features;
}

/* -------------------------------------------------------------------------- */
/* Convenience queries                                                        */
/* -------------------------------------------------------------------------- */

int pqc_cpu_has_avx2(void)   { return (int)pqc_cpu_detect()->has_avx2;   }
int pqc_cpu_has_avx512(void) { return (int)pqc_cpu_detect()->has_avx512; }
int pqc_cpu_has_neon(void)   { return (int)pqc_cpu_detect()->has_neon;   }
int pqc_cpu_has_sha_ni(void) { return (int)pqc_cpu_detect()->has_sha_ni; }
int pqc_cpu_has_pclmul(void) { return (int)pqc_cpu_detect()->has_pclmul; }
int pqc_cpu_has_bmi2(void)   { return (int)pqc_cpu_detect()->has_bmi2;   }
int pqc_cpu_has_sse2(void)   { return (int)pqc_cpu_detect()->has_sse2;   }
int pqc_cpu_has_sse41(void)  { return (int)pqc_cpu_detect()->has_sse41;  }
int pqc_cpu_has_aesni(void)  { return (int)pqc_cpu_detect()->has_aesni;  }
int pqc_cpu_has_sve(void)    { return (int)pqc_cpu_detect()->has_sve;    }
