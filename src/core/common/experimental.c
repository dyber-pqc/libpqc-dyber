/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Opt-in for experimental algorithms.
 *
 * Some algorithms are built but known not to work: their decapsulation
 * disagrees with encapsulation, their signatures do not verify, or their
 * key generation fails. The KEM and signature registries hide them --
 * pqc_kem_new()/pqc_sig_new() return NULL, *_is_enabled() returns 0 and
 * the enumeration skips them -- unless the caller opts in, either with
 * pqc_set_experimental(1) or by setting the environment variable
 * PQC_ENABLE_EXPERIMENTAL=1 before the first call into the library.
 * The opt-in exists for development and for the regression tests that
 * still exercise those code paths; nothing built on it is fit for use.
 */

#include <stdlib.h>
#include <string.h>

#include "pqc/common.h"

/* -1: not yet decided (read the environment on first use). */
static volatile int s_experimental = -1;

static int env_opt_in(void)
{
    const char *v = getenv("PQC_ENABLE_EXPERIMENTAL");
    return v != NULL && strcmp(v, "1") == 0;
}

void pqc_set_experimental(int enable)
{
    s_experimental = enable ? 1 : 0;
}

int pqc_experimental_enabled(void)
{
    int v = s_experimental;
    if (v < 0) {
        v = env_opt_in();
        s_experimental = v;
    }
    return v;
}
