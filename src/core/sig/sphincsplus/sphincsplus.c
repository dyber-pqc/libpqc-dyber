/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPHINCS+ signature scheme.
 *
 * SPHINCS+ is the pre-standardization version of SLH-DSA (FIPS 205).
 * The two schemes share identical internal structures (WOTS+, XMSS,
 * FORS, hypertree) and parameter sets. The primary difference is the
 * domain separator context used during hashing.
 *
 * This implementation wraps the SLH-DSA internals (pqc_slhdsa_keygen,
 * pqc_slhdsa_sign, pqc_slhdsa_verify) with SPHINCS+ algorithm names.
 * The SLH-DSA parameter sets are reused directly since SPHINCS+ Round 3
 * parameter sets match SLH-DSA exactly in structure and dimensions.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "core/sig/sig_internal.h"
#include "core/sig/slhdsa/slhdsa.h"
#include "core/sig/slhdsa/slhdsa_params.h"

/* ------------------------------------------------------------------ */
/* SPHINCS+ parameter set mapping                                       */
/*                                                                      */
/* Each SPHINCS+ variant maps to an SLH-DSA parameter set with the      */
/* same (n, h, d, a, k, w) values and hash function.                    */
/* ------------------------------------------------------------------ */

typedef struct {
    const char *sphincs_name;
    const slhdsa_params_t *params;
} sphincs_mapping_t;

static const sphincs_mapping_t sphincs_mappings[] = {
    { PQC_SIG_SPHINCS_SHA2_128S,  &SLHDSA_SHA2_128S  },
    { PQC_SIG_SPHINCS_SHA2_128F,  &SLHDSA_SHA2_128F  },
    { PQC_SIG_SPHINCS_SHA2_192S,  &SLHDSA_SHA2_192S  },
    { PQC_SIG_SPHINCS_SHA2_192F,  &SLHDSA_SHA2_192F  },
    { PQC_SIG_SPHINCS_SHA2_256S,  &SLHDSA_SHA2_256S  },
    { PQC_SIG_SPHINCS_SHA2_256F,  &SLHDSA_SHA2_256F  },
    { PQC_SIG_SPHINCS_SHAKE_128S, &SLHDSA_SHAKE_128S },
    { PQC_SIG_SPHINCS_SHAKE_128F, &SLHDSA_SHAKE_128F },
    { PQC_SIG_SPHINCS_SHAKE_192S, &SLHDSA_SHAKE_192S },
    { PQC_SIG_SPHINCS_SHAKE_192F, &SLHDSA_SHAKE_192F },
    { PQC_SIG_SPHINCS_SHAKE_256S, &SLHDSA_SHAKE_256S },
    { PQC_SIG_SPHINCS_SHAKE_256F, &SLHDSA_SHAKE_256F },
};

#define NUM_SPHINCS_VARIANTS (sizeof(sphincs_mappings) / sizeof(sphincs_mappings[0]))

/* ------------------------------------------------------------------ */
/* Per-variant keygen / sign / verify                                   */
/*                                                                      */
/* We use a macro to generate the static callback functions for each     */
/* variant, since each needs a different parameter set pointer.          */
/* ------------------------------------------------------------------ */

#define DEFINE_SPHINCS_OPS(idx)                                                 \
                                                                                 \
static pqc_status_t sphincs_keygen_##idx(uint8_t *pk, uint8_t *sk)              \
{                                                                                \
    int rc = pqc_slhdsa_keygen(pk, sk, sphincs_mappings[idx].params);           \
    return (rc == 0) ? PQC_OK : PQC_ERROR_INTERNAL;                             \
}                                                                                \
                                                                                 \
static pqc_status_t sphincs_sign_##idx(uint8_t *sig, size_t *siglen,            \
                                        const uint8_t *msg, size_t msglen,      \
                                        const uint8_t *sk)                      \
{                                                                                \
    int rc = pqc_slhdsa_sign(sig, siglen, msg, msglen, sk,                      \
                              sphincs_mappings[idx].params);                     \
    return (rc == 0) ? PQC_OK : PQC_ERROR_INTERNAL;                             \
}                                                                                \
                                                                                 \
static pqc_status_t sphincs_verify_##idx(const uint8_t *msg, size_t msglen,     \
                                          const uint8_t *sig, size_t siglen,    \
                                          const uint8_t *pk)                    \
{                                                                                \
    int rc = pqc_slhdsa_verify(msg, msglen, sig, siglen, pk,                    \
                                sphincs_mappings[idx].params);                   \
    return (rc == 0) ? PQC_OK : PQC_ERROR_VERIFICATION_FAILED;                  \
}

/* Generate operations for all 12 variants */
DEFINE_SPHINCS_OPS(0)   /* SHA2-128s  */
DEFINE_SPHINCS_OPS(1)   /* SHA2-128f  */
DEFINE_SPHINCS_OPS(2)   /* SHA2-192s  */
DEFINE_SPHINCS_OPS(3)   /* SHA2-192f  */
DEFINE_SPHINCS_OPS(4)   /* SHA2-256s  */
DEFINE_SPHINCS_OPS(5)   /* SHA2-256f  */
DEFINE_SPHINCS_OPS(6)   /* SHAKE-128s */
DEFINE_SPHINCS_OPS(7)   /* SHAKE-128f */
DEFINE_SPHINCS_OPS(8)   /* SHAKE-192s */
DEFINE_SPHINCS_OPS(9)   /* SHAKE-192f */
DEFINE_SPHINCS_OPS(10)  /* SHAKE-256s */
DEFINE_SPHINCS_OPS(11)  /* SHAKE-256f */

/* ------------------------------------------------------------------ */
/* Vtables -- 12 SPHINCS+ parameter sets                                */
/* ------------------------------------------------------------------ */

#define SPHINCS_VTABLE(idx, alg_name, sec_level, pk_sz, sk_sz, sig_sz)  \
static const pqc_sig_vtable_t sphincs_vtable_##idx = {                  \
    .algorithm_name     = alg_name,                                      \
    .security_level     = sec_level,                                     \
    .nist_standard      = "SPHINCS+ (Round 3)",                          \
    .is_stateful        = 0,                                             \
    .public_key_size    = pk_sz,                                         \
    .secret_key_size    = sk_sz,                                         \
    .max_signature_size = sig_sz,                                        \
    .keygen  = sphincs_keygen_##idx,                                     \
    .sign    = sphincs_sign_##idx,                                       \
    .verify  = sphincs_verify_##idx,                                     \
    .sign_stateful = NULL,                                               \
}

/*                  idx  algorithm name               level                  pk  sk   sig    */
SPHINCS_VTABLE(0,  PQC_SIG_SPHINCS_SHA2_128S,  PQC_SECURITY_LEVEL_1,  32,  64,   7856);
SPHINCS_VTABLE(1,  PQC_SIG_SPHINCS_SHA2_128F,  PQC_SECURITY_LEVEL_1,  32,  64,  17088);
SPHINCS_VTABLE(2,  PQC_SIG_SPHINCS_SHA2_192S,  PQC_SECURITY_LEVEL_3,  48,  96,  16224);
SPHINCS_VTABLE(3,  PQC_SIG_SPHINCS_SHA2_192F,  PQC_SECURITY_LEVEL_3,  48,  96,  35664);
SPHINCS_VTABLE(4,  PQC_SIG_SPHINCS_SHA2_256S,  PQC_SECURITY_LEVEL_5,  64, 128,  29792);
SPHINCS_VTABLE(5,  PQC_SIG_SPHINCS_SHA2_256F,  PQC_SECURITY_LEVEL_5,  64, 128,  49856);
SPHINCS_VTABLE(6,  PQC_SIG_SPHINCS_SHAKE_128S, PQC_SECURITY_LEVEL_1,  32,  64,   7856);
SPHINCS_VTABLE(7,  PQC_SIG_SPHINCS_SHAKE_128F, PQC_SECURITY_LEVEL_1,  32,  64,  17088);
SPHINCS_VTABLE(8,  PQC_SIG_SPHINCS_SHAKE_192S, PQC_SECURITY_LEVEL_3,  48,  96,  16224);
SPHINCS_VTABLE(9,  PQC_SIG_SPHINCS_SHAKE_192F, PQC_SECURITY_LEVEL_3,  48,  96,  35664);
SPHINCS_VTABLE(10, PQC_SIG_SPHINCS_SHAKE_256S, PQC_SECURITY_LEVEL_5,  64, 128,  29792);
SPHINCS_VTABLE(11, PQC_SIG_SPHINCS_SHAKE_256F, PQC_SECURITY_LEVEL_5,  64, 128,  49856);

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_sig_sphincsplus_register(void)
{
    int rc = 0;
    rc |= pqc_sig_add_vtable(&sphincs_vtable_0);
    rc |= pqc_sig_add_vtable(&sphincs_vtable_1);
    rc |= pqc_sig_add_vtable(&sphincs_vtable_2);
    rc |= pqc_sig_add_vtable(&sphincs_vtable_3);
    rc |= pqc_sig_add_vtable(&sphincs_vtable_4);
    rc |= pqc_sig_add_vtable(&sphincs_vtable_5);
    rc |= pqc_sig_add_vtable(&sphincs_vtable_6);
    rc |= pqc_sig_add_vtable(&sphincs_vtable_7);
    rc |= pqc_sig_add_vtable(&sphincs_vtable_8);
    rc |= pqc_sig_add_vtable(&sphincs_vtable_9);
    rc |= pqc_sig_add_vtable(&sphincs_vtable_10);
    rc |= pqc_sig_add_vtable(&sphincs_vtable_11);
    return rc;
}
