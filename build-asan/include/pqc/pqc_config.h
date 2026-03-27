/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Auto-generated configuration header. Do not edit.
 */

#ifndef PQC_CONFIG_H
#define PQC_CONFIG_H

#define PQC_VERSION_MAJOR 0
#define PQC_VERSION_MINOR 1
#define PQC_VERSION_PATCH 0
#define PQC_VERSION_STRING "0.1.0"

/* Platform */
/* #undef PQC_OS_WINDOWS */
#define PQC_OS_LINUX
/* #undef PQC_OS_MACOS */
/* #undef PQC_OS_FREEBSD */
/* #undef PQC_OS_UNIX */

/* Architecture */
#define PQC_ARCH_X86_64
/* #undef PQC_ARCH_AARCH64 */
/* #undef PQC_ARCH_X86 */
/* #undef PQC_ARCH_ARM */
/* #undef PQC_ARCH_GENERIC */

/* SIMD */
#define PQC_HAS_AVX2
#define PQC_HAS_AVX512
/* #undef PQC_HAS_NEON */
/* #undef PQC_HAS_SVE */
#define PQC_HAS_SHA_NI
#define PQC_HAS_PCLMUL
#define PQC_HAS_BMI2

/* KEM algorithms */
#define PQC_ENABLE_KEM_MLKEM
#define PQC_ENABLE_KEM_HQC
#define PQC_ENABLE_KEM_BIKE
#define PQC_ENABLE_KEM_MCELIECE
#define PQC_ENABLE_KEM_FRODO
#define PQC_ENABLE_KEM_NTRU
#define PQC_ENABLE_KEM_NTRUPRIME

/* Signature algorithms */
#define PQC_ENABLE_SIG_MLDSA
#define PQC_ENABLE_SIG_SLHDSA
#define PQC_ENABLE_SIG_FNDSA
#define PQC_ENABLE_SIG_SPHINCSPLUS
#define PQC_ENABLE_SIG_MAYO
#define PQC_ENABLE_SIG_UOV
#define PQC_ENABLE_SIG_SNOVA
#define PQC_ENABLE_SIG_CROSS
#define PQC_ENABLE_SIG_LMS
#define PQC_ENABLE_SIG_XMSS

/* Hybrid */
#define PQC_ENABLE_HYBRID

/* ASM */
#define PQC_ENABLE_ASM

#endif /* PQC_CONFIG_H */
