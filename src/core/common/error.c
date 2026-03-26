/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Error-code descriptions, version reporting, and library lifecycle.
 */

#include "pqc/common.h"
#include "pqc/pqc_config.h"
#include "core/common/platform.h"

/* -------------------------------------------------------------------------- */
/* Version queries                                                            */
/* -------------------------------------------------------------------------- */

const char *
pqc_version(void)
{
    return PQC_VERSION_STRING;
}

int
pqc_version_major(void)
{
    return PQC_VERSION_MAJOR;
}

int
pqc_version_minor(void)
{
    return PQC_VERSION_MINOR;
}

int
pqc_version_patch(void)
{
    return PQC_VERSION_PATCH;
}

/* -------------------------------------------------------------------------- */
/* Status string                                                              */
/* -------------------------------------------------------------------------- */

const char *
pqc_status_string(pqc_status_t status)
{
    switch (status) {
    case PQC_OK:                          return "success";
    case PQC_ERROR:                       return "unspecified error";
    case PQC_ERROR_INVALID_ARGUMENT:      return "invalid argument";
    case PQC_ERROR_ALLOC:                 return "memory allocation failed";
    case PQC_ERROR_NOT_SUPPORTED:         return "operation not supported";
    case PQC_ERROR_INVALID_KEY:           return "invalid key";
    case PQC_ERROR_VERIFICATION_FAILED:   return "signature verification failed";
    case PQC_ERROR_DECAPSULATION_FAILED:  return "decapsulation failed";
    case PQC_ERROR_RNG_FAILED:            return "random number generation failed";
    case PQC_ERROR_BUFFER_TOO_SMALL:      return "buffer too small";
    case PQC_ERROR_INTERNAL:              return "internal error";
    case PQC_ERROR_STATE_EXHAUSTED:       return "stateful signature state exhausted";
    default:                              return "unknown error";
    }
}

/* -------------------------------------------------------------------------- */
/* Library initialization and cleanup                                         */
/* -------------------------------------------------------------------------- */

static int s_initialized = 0;

pqc_status_t
pqc_init(void)
{
    if (s_initialized) {
        return PQC_OK;
    }

    /* Probe CPU features so later algorithm dispatch is ready */
    pqc_cpu_detect();

    s_initialized = 1;
    return PQC_OK;
}

void
pqc_cleanup(void)
{
    if (!s_initialized) {
        return;
    }

    /*
     * Reset the custom RNG to the OS default.
     * This also serves as a defensive measure so stale function pointers
     * are not called after the owning module is unloaded.
     */
    pqc_set_rng(NULL, NULL);

    s_initialized = 0;
}
