/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * HQC - Key/ciphertext parsing and serialization.
 *
 * Packs and unpacks public keys, secret keys, and ciphertexts
 * between byte arrays and internal vector representations.
 */

#include <string.h>
#include "hqc.h"
#include "hqc_params.h"

/* ------------------------------------------------------------------ */
/* Bit-vector pack/unpack utilities                                     */
/* ------------------------------------------------------------------ */

/*
 * Pack a uint64_t vector (bit-vector) into a byte array.
 * n = number of bits to pack.
 */
static void vect_to_bytes(uint8_t *dest, const uint64_t *src, uint32_t n)
{
    uint32_t n_bytes = (n + 7) / 8;
    memcpy(dest, src, n_bytes);
    /* Clear trailing bits in last byte */
    uint32_t rem = n % 8;
    if (rem) {
        dest[n_bytes - 1] &= (uint8_t)((1u << rem) - 1);
    }
}

/*
 * Unpack a byte array into a uint64_t vector (bit-vector).
 * n = number of bits.
 */
static void bytes_to_vect(uint64_t *dest, const uint8_t *src, uint32_t n)
{
    uint32_t n_bytes = (n + 7) / 8;
    uint32_t n_words = (n + 63) / 64;
    memset(dest, 0, n_words * sizeof(uint64_t));
    memcpy(dest, src, n_bytes);
    /* Clear trailing bits */
    uint32_t rem = n % 64;
    if (rem) {
        dest[n_words - 1] &= ((uint64_t)1 << rem) - 1;
    }
}

/* ------------------------------------------------------------------ */
/* Public key packing                                                   */
/*                                                                      */
/* pk = seed (40 bytes) || h (n bits packed)                            */
/* ------------------------------------------------------------------ */

void hqc_pk_pack(uint8_t *pk, const uint8_t *seed,
                 const uint64_t *h, const hqc_params_t *params)
{
    memcpy(pk, seed, HQC_SEED_BYTES);
    vect_to_bytes(pk + HQC_SEED_BYTES, h, params->n);
}

void hqc_pk_unpack(uint8_t *seed, uint64_t *h,
                   const uint8_t *pk, const hqc_params_t *params)
{
    memcpy(seed, pk, HQC_SEED_BYTES);
    bytes_to_vect(h, pk + HQC_SEED_BYTES, params->n);
}

/* ------------------------------------------------------------------ */
/* Secret key packing                                                   */
/*                                                                      */
/* sk = seed (40 bytes) || pk (pk_bytes)                               */
/* ------------------------------------------------------------------ */

void hqc_sk_pack(uint8_t *sk, const uint8_t *seed,
                 const uint8_t *pk, const hqc_params_t *params)
{
    memcpy(sk, seed, HQC_SEED_BYTES);
    memcpy(sk + HQC_SEED_BYTES, pk, params->pk_bytes);
}

void hqc_sk_unpack(uint8_t *seed, uint8_t *pk,
                   const uint8_t *sk, const hqc_params_t *params)
{
    memcpy(seed, sk, HQC_SEED_BYTES);
    memcpy(pk, sk + HQC_SEED_BYTES, params->pk_bytes);
}

/* ------------------------------------------------------------------ */
/* Ciphertext packing                                                   */
/*                                                                      */
/* ct = u (n bits) || v (n1n2 bits) || salt (16 bytes)                 */
/* ------------------------------------------------------------------ */

void hqc_ct_pack(uint8_t *ct, const uint64_t *u, const uint64_t *v,
                 const uint8_t *salt, const hqc_params_t *params)
{
    uint32_t offset = 0;
    vect_to_bytes(ct, u, params->n);
    offset += params->n_bytes;
    vect_to_bytes(ct + offset, v, params->n1n2);
    offset += params->n1n2_bytes;
    memcpy(ct + offset, salt, HQC_SALT_SIZE_BYTES);
}

void hqc_ct_unpack(uint64_t *u, uint64_t *v, uint8_t *salt,
                   const uint8_t *ct, const hqc_params_t *params)
{
    uint32_t offset = 0;
    bytes_to_vect(u, ct, params->n);
    offset += params->n_bytes;
    bytes_to_vect(v, ct + offset, params->n1n2);
    offset += params->n1n2_bytes;
    memcpy(salt, ct + offset, HQC_SALT_SIZE_BYTES);
}
