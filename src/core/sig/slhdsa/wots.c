/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SLH-DSA (FIPS 205) - WOTS+ one-time signature scheme.
 *
 * WOTS+ uses a Winternitz chain of tweakable hashes to sign n-byte
 * messages.  With w=16, each chain has 15 steps, and the message is
 * split into base-16 digits plus a checksum.
 */

#include <string.h>
#include <stdint.h>

#include "slhdsa.h"

/* ------------------------------------------------------------------ */
/* Base-w encoding                                                      */
/*                                                                      */
/* Convert an n-byte message into wots_len1 base-w digits, then         */
/* append wots_len2 checksum digits.                                    */
/* For w=16, each byte yields two base-16 digits.                       */
/* ------------------------------------------------------------------ */

static void base_w(uint32_t *output, uint32_t out_len,
                    const uint8_t *input, uint32_t w)
{
    uint32_t i;
    uint32_t bits = 0;
    uint32_t total = 0;
    uint32_t consumed = 0;
    uint32_t lg_w;

    /* Compute log2(w) — w is always a power of 2 */
    for (lg_w = 0; (1u << lg_w) < w; lg_w++)
        ;

    for (i = 0; i < out_len; i++) {
        if (bits == 0) {
            total = input[consumed];
            consumed++;
            bits = 8;
        }
        bits -= lg_w;
        output[i] = (total >> bits) & (w - 1);
    }
}

/*
 * Compute the WOTS+ checksum and append it to the base-w message.
 */
static void wots_checksum(uint32_t *msg_base_w,
                           uint32_t wots_len1, uint32_t wots_len2,
                           uint32_t w)
{
    uint32_t csum = 0;
    uint32_t i;
    uint8_t csum_bytes[4]; /* enough for any checksum */
    uint32_t csum_bits;

    /* Compute log2(w) */
    uint32_t lg_w;
    for (lg_w = 0; (1u << lg_w) < w; lg_w++)
        ;

    /* Sum the complement values */
    for (i = 0; i < wots_len1; i++) {
        csum += (w - 1) - msg_base_w[i];
    }

    /* Left-shift checksum to fill full base-w digits */
    csum_bits = wots_len2 * lg_w;
    csum <<= (8 - (csum_bits % 8)) % 8;

    /* Encode checksum in big-endian bytes */
    {
        uint32_t csum_byte_len = (csum_bits + 7) / 8;
        uint32_t j;
        memset(csum_bytes, 0, sizeof(csum_bytes));
        for (j = 0; j < csum_byte_len; j++) {
            csum_bytes[csum_byte_len - 1 - j] = (uint8_t)(csum & 0xff);
            csum >>= 8;
        }

        /* Convert checksum bytes to base-w and append */
        base_w(msg_base_w + wots_len1, wots_len2, csum_bytes, w);
    }
}

/* ------------------------------------------------------------------ */
/* Chain function: apply the tweakable hash 'steps' times starting      */
/* from 'start'.                                                        */
/*                                                                      */
/* chain(X, start, steps, PK.seed, ADRS) applies:                      */
/*   for i in [start, start+steps):                                     */
/*     ADRS.hash = i                                                    */
/*     X = T(PK.seed, ADRS, X)                                         */
/* ------------------------------------------------------------------ */

static void wots_chain(uint8_t *out,
                        const uint8_t *in, uint32_t start, uint32_t steps,
                        const uint8_t *pub_seed,
                        uint8_t addr[32],
                        const slhdsa_params_t *p)
{
    uint32_t n = p->n;
    uint32_t i;

    if (out != in)
        memcpy(out, in, n);

    for (i = start; i < start + steps; i++) {
        slhdsa_set_hash_addr(addr, i);
        slhdsa_thash(out, out, 1, pub_seed, addr, p);
    }
}

/* ------------------------------------------------------------------ */
/* WOTS+ public key generation                                          */
/*                                                                      */
/* Generate each chain's secret key via PRF, then chain it w-1 times.   */
/* Compress with T_len to produce the WOTS+ public key.                 */
/* ------------------------------------------------------------------ */

void slhdsa_wots_gen_pk(uint8_t *pk,
                         const uint8_t *sk_seed,
                         const uint8_t *pub_seed,
                         uint8_t addr[32],
                         const slhdsa_params_t *p)
{
    uint32_t n = p->n;
    uint32_t wots_len = p->wots_len;
    uint32_t w = p->w;
    uint8_t tmp[SLHDSA_MAX_WOTS_LEN * SLHDSA_MAX_N];
    uint32_t i;
    uint8_t prf_addr[32];

    memset(prf_addr, 0, 32);
    slhdsa_copy_subtree_addr(prf_addr, addr);
    slhdsa_set_type(prf_addr, SLHDSA_ADDR_TYPE_WOTSPRF);
    slhdsa_set_keypair_addr(prf_addr, 0);
    /* Copy keypair from the original address */
    {
        uint8_t kp_addr[32];
        memset(kp_addr, 0, 32);
        slhdsa_copy_keypair_addr(kp_addr, addr);
        slhdsa_set_keypair_addr(prf_addr,
            ((uint32_t)kp_addr[16] << 24) | ((uint32_t)kp_addr[17] << 16) |
            ((uint32_t)kp_addr[18] <<  8) | ((uint32_t)kp_addr[19]));
    }

    slhdsa_set_type(addr, SLHDSA_ADDR_TYPE_WOTS);

    for (i = 0; i < wots_len; i++) {
        /* Generate secret key element via PRF */
        slhdsa_set_chain_addr(prf_addr, i);
        slhdsa_prf(tmp + i * n, sk_seed, pub_seed, prf_addr, p);

        /* Chain from 0 to w-1 */
        slhdsa_set_chain_addr(addr, i);
        wots_chain(tmp + i * n, tmp + i * n, 0, w - 1, pub_seed, addr, p);
    }

    /* Compress all chain endpoints into single n-byte PK */
    slhdsa_set_type(addr, SLHDSA_ADDR_TYPE_WOTSPK);
    slhdsa_thash(pk, tmp, wots_len, pub_seed, addr, p);
}

/* ------------------------------------------------------------------ */
/* WOTS+ sign                                                           */
/*                                                                      */
/* Sign an n-byte message digest. For each base-w digit d_i, chain      */
/* the secret key d_i times.                                            */
/* ------------------------------------------------------------------ */

void slhdsa_wots_sign(uint8_t *sig,
                       const uint8_t *msg,
                       const uint8_t *sk_seed,
                       const uint8_t *pub_seed,
                       uint8_t addr[32],
                       const slhdsa_params_t *p)
{
    uint32_t n = p->n;
    uint32_t wots_len = p->wots_len;
    uint32_t w = p->w;
    uint32_t msg_base_w[SLHDSA_MAX_WOTS_LEN];
    uint32_t i;
    uint8_t prf_addr[32];

    /* Compute base-w representation with checksum */
    base_w(msg_base_w, p->wots_len1, msg, w);
    wots_checksum(msg_base_w, p->wots_len1, p->wots_len2, w);

    /* Set up PRF address */
    memset(prf_addr, 0, 32);
    slhdsa_copy_subtree_addr(prf_addr, addr);
    slhdsa_set_type(prf_addr, SLHDSA_ADDR_TYPE_WOTSPRF);
    {
        uint8_t kp_addr[32];
        memset(kp_addr, 0, 32);
        slhdsa_copy_keypair_addr(kp_addr, addr);
        slhdsa_set_keypair_addr(prf_addr,
            ((uint32_t)kp_addr[16] << 24) | ((uint32_t)kp_addr[17] << 16) |
            ((uint32_t)kp_addr[18] <<  8) | ((uint32_t)kp_addr[19]));
    }

    slhdsa_set_type(addr, SLHDSA_ADDR_TYPE_WOTS);

    for (i = 0; i < wots_len; i++) {
        slhdsa_set_chain_addr(prf_addr, i);
        slhdsa_prf(sig + i * n, sk_seed, pub_seed, prf_addr, p);

        slhdsa_set_chain_addr(addr, i);
        wots_chain(sig + i * n, sig + i * n, 0, msg_base_w[i],
                   pub_seed, addr, p);
    }
}

/* ------------------------------------------------------------------ */
/* WOTS+ public key recovery from signature                             */
/*                                                                      */
/* Given a WOTS+ signature and the signed message, complete each chain  */
/* to produce the public key.                                           */
/* ------------------------------------------------------------------ */

void slhdsa_wots_pk_from_sig(uint8_t *pk,
                              const uint8_t *sig,
                              const uint8_t *msg,
                              const uint8_t *pub_seed,
                              uint8_t addr[32],
                              const slhdsa_params_t *p)
{
    uint32_t n = p->n;
    uint32_t wots_len = p->wots_len;
    uint32_t w = p->w;
    uint32_t msg_base_w[SLHDSA_MAX_WOTS_LEN];
    uint8_t tmp[SLHDSA_MAX_WOTS_LEN * SLHDSA_MAX_N];
    uint32_t i;

    base_w(msg_base_w, p->wots_len1, msg, w);
    wots_checksum(msg_base_w, p->wots_len1, p->wots_len2, w);

    slhdsa_set_type(addr, SLHDSA_ADDR_TYPE_WOTS);

    for (i = 0; i < wots_len; i++) {
        slhdsa_set_chain_addr(addr, i);
        wots_chain(tmp + i * n, sig + i * n,
                   msg_base_w[i], (w - 1) - msg_base_w[i],
                   pub_seed, addr, p);
    }

    /* Compress */
    slhdsa_set_type(addr, SLHDSA_ADDR_TYPE_WOTSPK);
    slhdsa_thash(pk, tmp, wots_len, pub_seed, addr, p);
}
