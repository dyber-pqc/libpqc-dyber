/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Runtime CPU feature detection.
 */

#include "dispatch/dispatch.h"
#include "pqc/pqc_config.h"

#include <string.h>

static pqc_cpu_features_t cpu_features = {0};

#if defined(PQC_ARCH_X86_64) || defined(PQC_ARCH_X86)

#if defined(_MSC_VER)
#include <intrin.h>
static void cpuid(int info[4], int leaf) {
    __cpuid(info, leaf);
}
static void cpuidex(int info[4], int leaf, int subleaf) {
    __cpuidex(info, leaf, subleaf);
}
#elif defined(__GNUC__) || defined(__clang__)
#include <cpuid.h>
static void cpuid(int info[4], int leaf) {
    __cpuid(leaf, info[0], info[1], info[2], info[3]);
}
static void cpuidex(int info[4], int leaf, int subleaf) {
    __cpuid_count(leaf, subleaf, info[0], info[1], info[2], info[3]);
}
#endif

static void detect_x86_features(pqc_cpu_features_t *f) {
    int info[4];

    cpuid(info, 0);
    int max_leaf = info[0];

    if (max_leaf >= 1) {
        cpuid(info, 1);
        f->has_aesni = (info[2] >> 25) & 1;
        f->has_pclmul = (info[2] >> 1) & 1;
    }

    if (max_leaf >= 7) {
        cpuidex(info, 7, 0);
        f->has_avx2    = (info[1] >> 5) & 1;
        f->has_bmi2    = (info[1] >> 8) & 1;
        f->has_sha_ni  = (info[1] >> 29) & 1;
        f->has_avx512 = (info[1] >> 16) & 1;
    }
}

#elif defined(PQC_ARCH_AARCH64)

#if defined(__linux__)
#include <sys/auxv.h>
#include <asm/hwcap.h>
#endif

static void detect_arm_features(pqc_cpu_features_t *f) {
    /* NEON is always available on AArch64 */
    f->has_neon = 1;

#if defined(__linux__) && defined(HWCAP_SHA2)
    unsigned long hwcap = getauxval(AT_HWCAP);
    f->has_sha2 = (hwcap & HWCAP_SHA2) ? 1 : 0;
    f->has_aes  = (hwcap & HWCAP_AES) ? 1 : 0;
#ifdef HWCAP_SHA3
    f->has_sha3 = (hwcap & HWCAP_SHA3) ? 1 : 0;
#endif
#ifdef HWCAP_SVE
    f->has_sve = (hwcap & HWCAP_SVE) ? 1 : 0;
#endif
#elif defined(__APPLE__)
    /* Apple Silicon always has these */
    f->has_sha2 = 1;
    f->has_aes = 1;
    f->has_sha3 = 1;
#endif
}

#endif /* arch detection */

void pqc_detect_cpu_features(pqc_cpu_features_t *f) {
    memset(f, 0, sizeof(*f));

#if defined(PQC_ARCH_X86_64) || defined(PQC_ARCH_X86)
    detect_x86_features(f);
#elif defined(PQC_ARCH_AARCH64)
    detect_arm_features(f);
#endif

    f->initialized = 1;
}

const pqc_cpu_features_t *pqc_get_cpu_features(void) {
    if (!cpu_features.initialized) {
        pqc_detect_cpu_features(&cpu_features);
    }
    return &cpu_features;
}
