/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Secure memory management.
 *
 * - pqc_malloc / pqc_calloc prepend a size header so pqc_free can zeroize
 *   the correct number of bytes without the caller re-stating the size.
 * - pqc_memzero uses volatile stores and platform primitives to guarantee
 *   the compiler does not elide the zeroization.
 * - pqc_memcmp_ct delegates to ct_ops for constant-time comparison.
 */

#include "pqc/common.h"
#include "core/common/mem_internal.h"
#include "core/common/ct_ops.h"

#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------- */
/* Platform-specific secure-zero support                                      */
/* -------------------------------------------------------------------------- */

#if defined(_WIN32)
#   include <windows.h>         /* SecureZeroMemory */
#endif

#if defined(__STDC_LIB_EXT1__)
#   define PQC_HAVE_MEMSET_S 1
#endif

/* Some C11 implementations provide memset_s via optional Annex K. */
#if defined(__STDC_WANT_LIB_EXT1__) || defined(PQC_HAVE_MEMSET_S)
#   include <string.h>          /* memset_s (if available) */
#endif

/* Try explicit_bzero on glibc >= 2.25, musl, FreeBSD, OpenBSD */
#if defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#   include <strings.h>
#   if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#       if __GLIBC_PREREQ(2, 25)
#           define PQC_HAVE_EXPLICIT_BZERO 1
#       endif
#   elif defined(__FreeBSD__) || defined(__OpenBSD__)
#       define PQC_HAVE_EXPLICIT_BZERO 1
#   endif
#endif

/* -------------------------------------------------------------------------- */
/* pqc_memzero - guaranteed zeroization                                       */
/* -------------------------------------------------------------------------- */

void
pqc_memzero(void *ptr, size_t size)
{
    if (ptr == NULL || size == 0) {
        return;
    }

#if defined(_WIN32)
    SecureZeroMemory(ptr, size);
#elif defined(PQC_HAVE_MEMSET_S)
    memset_s(ptr, size, 0, size);
#elif defined(PQC_HAVE_EXPLICIT_BZERO)
    explicit_bzero(ptr, size);
#else
    /*
     * Portable fallback: use a volatile function pointer to prevent
     * the compiler from optimizing away the memset.  The C standard
     * guarantees that calls through volatile pointers cannot be elided.
     */
    typedef void *(*memset_fn_t)(void *, int, size_t);
    static volatile memset_fn_t volatile_memset = memset;
    volatile_memset(ptr, 0, size);

    /*
     * Additional safety: compiler barrier to prevent reordering.
     */
#   if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#   endif
#endif
}

/* -------------------------------------------------------------------------- */
/* Allocation helpers with size prefix                                        */
/* -------------------------------------------------------------------------- */

/*
 * We prepend each allocation with a size_t so pqc_free can zeroize without
 * the caller needing to remember the size.  The layout is:
 *
 *   [ size_t: allocation_size ] [ user data ... ]
 *   ^                           ^
 *   actual malloc pointer       pointer returned to caller
 *
 * Alignment: size_t is typically the platform's natural word size, so the
 * user pointer is at least sizeof(size_t)-aligned.  For stricter alignment
 * we round up to a multiple of the maximum fundamental alignment.
 */

#define PQC_ALLOC_ALIGNMENT  16u   /* >= alignof(max_align_t) on all targets */

#define PQC_HEADER_SIZE                                                       \
    (((sizeof(size_t) + PQC_ALLOC_ALIGNMENT - 1u) / PQC_ALLOC_ALIGNMENT)     \
     * PQC_ALLOC_ALIGNMENT)

void *
pqc_malloc(size_t size)
{
    uint8_t *raw;
    size_t total;

    if (size == 0) {
        return NULL;
    }

    /* Overflow check */
    total = PQC_HEADER_SIZE + size;
    if (total < size) {
        return NULL;
    }

    raw = (uint8_t *)malloc(total);
    if (raw == NULL) {
        return NULL;
    }

    /* Store the requested size in the header */
    memcpy(raw, &size, sizeof(size_t));

    return raw + PQC_HEADER_SIZE;
}

void *
pqc_calloc(size_t count, size_t size)
{
    uint8_t *raw;
    size_t total_user;
    size_t total;

    if (count == 0 || size == 0) {
        return NULL;
    }

    /* Overflow check for count * size */
    total_user = count * size;
    if (total_user / count != size) {
        return NULL;
    }

    /* Overflow check for header + payload */
    total = PQC_HEADER_SIZE + total_user;
    if (total < total_user) {
        return NULL;
    }

    raw = (uint8_t *)malloc(total);
    if (raw == NULL) {
        return NULL;
    }

    /* Zero the entire allocation (header + payload) */
    memset(raw, 0, total);

    /* Store the payload size in the header */
    memcpy(raw, &total_user, sizeof(size_t));

    return raw + PQC_HEADER_SIZE;
}

void
pqc_free(void *ptr, size_t size)
{
    uint8_t *raw;
    size_t stored_size;

    if (ptr == NULL) {
        return;
    }

    raw = (uint8_t *)ptr - PQC_HEADER_SIZE;

    /* Recover stored size for zeroization */
    memcpy(&stored_size, raw, sizeof(size_t));

    /*
     * Use the caller-provided size if nonzero; otherwise fall back to
     * the stored size.  Zeroize user data only (not the header).
     */
    if (size > 0) {
        pqc_memzero(ptr, size);
    } else {
        pqc_memzero(ptr, stored_size);
    }

    /* Also zeroize the header */
    pqc_memzero(raw, PQC_HEADER_SIZE);

    free(raw);
}

/* -------------------------------------------------------------------------- */
/* Constant-time comparison (wraps ct_ops)                                    */
/* -------------------------------------------------------------------------- */

int
pqc_memcmp_ct(const void *a, const void *b, size_t len)
{
    return pqc_ct_memcmp(a, b, len);
}
