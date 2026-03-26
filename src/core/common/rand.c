/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Cryptographically secure random number generation.
 *
 * Provides pqc_randombytes() backed by the operating system CSPRNG,
 * with support for a user-supplied callback override via pqc_set_rng().
 */

#include "pqc/common.h"
#include "pqc/rand.h"
#include "core/common/rand_internal.h"

#include <string.h>

/* -------------------------------------------------------------------------- */
/* Platform includes                                                          */
/* -------------------------------------------------------------------------- */

#if defined(_WIN32)
#   ifndef WIN32_LEAN_AND_MEAN
#       define WIN32_LEAN_AND_MEAN
#   endif
#   include <windows.h>
#   include <bcrypt.h>
    /* Link note: requires bcrypt.lib on MSVC */
#   ifndef BCRYPT_USE_SYSTEM_PREFERRED_RNG
#       define BCRYPT_USE_SYSTEM_PREFERRED_RNG 0x00000002
#   endif
#elif defined(__linux__)
#   include <sys/random.h>      /* getrandom() */
#   include <errno.h>
#elif defined(__APPLE__)
#   include <stdlib.h>          /* arc4random_buf */
#elif defined(__FreeBSD__)
#   include <stdlib.h>          /* arc4random_buf */
#else
    /* POSIX fallback: /dev/urandom */
#   include <stdio.h>
#   include <errno.h>
#endif

/* -------------------------------------------------------------------------- */
/* Custom RNG state (thread-safety: protected by simple atomics / guards)     */
/* -------------------------------------------------------------------------- */

static pqc_rng_callback_t s_custom_rng_cb  = NULL;
static void               *s_custom_rng_ctx = NULL;

/*
 * Minimal lock-free protection for the custom RNG pointers.
 * On platforms with C11 atomics we use _Atomic; otherwise we rely on the
 * fact that aligned pointer writes are atomic on all supported architectures.
 */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L &&                \
    !defined(__STDC_NO_ATOMICS__)
#   include <stdatomic.h>
    static _Atomic int s_rng_lock = 0;
#   define RNG_LOCK()   while (atomic_exchange(&s_rng_lock, 1)) { /* spin */ }
#   define RNG_UNLOCK() atomic_store(&s_rng_lock, 0)
#elif defined(_WIN32)
    static volatile long s_rng_lock = 0;
#   define RNG_LOCK()   while (InterlockedExchange(&s_rng_lock, 1)) { /* spin */ }
#   define RNG_UNLOCK() InterlockedExchange(&s_rng_lock, 0)
#elif defined(__GNUC__) || defined(__clang__)
    static volatile int s_rng_lock = 0;
#   define RNG_LOCK()   while (__sync_lock_test_and_set(&s_rng_lock, 1)) { /* spin */ }
#   define RNG_UNLOCK() __sync_lock_release(&s_rng_lock)
#else
    /* Last resort: no locking (single-threaded only) */
#   define RNG_LOCK()   ((void)0)
#   define RNG_UNLOCK() ((void)0)
#endif

/* -------------------------------------------------------------------------- */
/* pqc_set_rng                                                                */
/* -------------------------------------------------------------------------- */

pqc_status_t
pqc_set_rng(pqc_rng_callback_t callback, void *ctx)
{
    RNG_LOCK();
    s_custom_rng_cb  = callback;
    s_custom_rng_ctx = ctx;
    RNG_UNLOCK();
    return PQC_OK;
}

/* -------------------------------------------------------------------------- */
/* OS CSPRNG backends                                                         */
/* -------------------------------------------------------------------------- */

#if defined(_WIN32)

pqc_status_t
pqc_os_randombytes(uint8_t *buf, size_t len)
{
    NTSTATUS status;

    if (buf == NULL && len > 0) {
        return PQC_ERROR_INVALID_ARGUMENT;
    }
    if (len == 0) {
        return PQC_OK;
    }

    status = BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)len,
                             BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status)) {
        return PQC_ERROR_RNG_FAILED;
    }
    return PQC_OK;
}

#elif defined(__linux__)

pqc_status_t
pqc_os_randombytes(uint8_t *buf, size_t len)
{
    ssize_t ret;
    size_t remaining;
    uint8_t *p;

    if (buf == NULL && len > 0) {
        return PQC_ERROR_INVALID_ARGUMENT;
    }
    if (len == 0) {
        return PQC_OK;
    }

    p = buf;
    remaining = len;

    while (remaining > 0) {
        ret = getrandom(p, remaining, 0);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            return PQC_ERROR_RNG_FAILED;
        }
        p         += (size_t)ret;
        remaining -= (size_t)ret;
    }

    return PQC_OK;
}

#elif defined(__APPLE__) || defined(__FreeBSD__)

pqc_status_t
pqc_os_randombytes(uint8_t *buf, size_t len)
{
    if (buf == NULL && len > 0) {
        return PQC_ERROR_INVALID_ARGUMENT;
    }
    if (len == 0) {
        return PQC_OK;
    }

    arc4random_buf(buf, len);
    return PQC_OK;
}

#else  /* POSIX fallback: /dev/urandom */

pqc_status_t
pqc_os_randombytes(uint8_t *buf, size_t len)
{
    FILE *f;
    size_t nread;

    if (buf == NULL && len > 0) {
        return PQC_ERROR_INVALID_ARGUMENT;
    }
    if (len == 0) {
        return PQC_OK;
    }

    f = fopen("/dev/urandom", "rb");
    if (f == NULL) {
        return PQC_ERROR_RNG_FAILED;
    }

    nread = fread(buf, 1, len, f);
    fclose(f);

    if (nread != len) {
        return PQC_ERROR_RNG_FAILED;
    }

    return PQC_OK;
}

#endif /* platform selection */

/* -------------------------------------------------------------------------- */
/* pqc_randombytes (public entry point)                                       */
/* -------------------------------------------------------------------------- */

pqc_status_t
pqc_randombytes(uint8_t *buf, size_t len)
{
    pqc_rng_callback_t cb;
    void *ctx;

    if (buf == NULL && len > 0) {
        return PQC_ERROR_INVALID_ARGUMENT;
    }
    if (len == 0) {
        return PQC_OK;
    }

    /* Snapshot the custom RNG under the lock */
    RNG_LOCK();
    cb  = s_custom_rng_cb;
    ctx = s_custom_rng_ctx;
    RNG_UNLOCK();

    if (cb != NULL) {
        return cb(buf, len, ctx);
    }

    return pqc_os_randombytes(buf, len);
}
