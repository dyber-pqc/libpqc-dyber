/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Key and signature packing/unpacking for ML-DSA (FIPS 204).
 *
 * Adapted from the reference pq-crystals/dilithium implementation
 * (Public Domain / CC0).
 */

#include <string.h>

#include "core/sig/mldsa/packing.h"
#include "core/sig/mldsa/mldsa_params.h"

/* ================================================================= */
/*  t1 packing (10-bit coefficients)                                   */
/* ================================================================= */

void pqc_mldsa_polyt1_pack(uint8_t *r, const pqc_mldsa_poly *a)
{
    unsigned int i;
    for (i = 0; i < PQC_MLDSA_N / 4; ++i) {
        r[5 * i + 0] = (uint8_t)(a->coeffs[4 * i + 0] >> 0);
        r[5 * i + 1] = (uint8_t)((a->coeffs[4 * i + 0] >> 8) |
                                   (a->coeffs[4 * i + 1] << 2));
        r[5 * i + 2] = (uint8_t)((a->coeffs[4 * i + 1] >> 6) |
                                   (a->coeffs[4 * i + 2] << 4));
        r[5 * i + 3] = (uint8_t)((a->coeffs[4 * i + 2] >> 4) |
                                   (a->coeffs[4 * i + 3] << 6));
        r[5 * i + 4] = (uint8_t)(a->coeffs[4 * i + 3] >> 2);
    }
}

void pqc_mldsa_polyt1_unpack(pqc_mldsa_poly *r, const uint8_t *a)
{
    unsigned int i;
    for (i = 0; i < PQC_MLDSA_N / 4; ++i) {
        r->coeffs[4 * i + 0] = (((uint32_t)a[5 * i + 0] >> 0) |
                                  ((uint32_t)a[5 * i + 1] << 8)) & 0x3FF;
        r->coeffs[4 * i + 1] = (((uint32_t)a[5 * i + 1] >> 2) |
                                  ((uint32_t)a[5 * i + 2] << 6)) & 0x3FF;
        r->coeffs[4 * i + 2] = (((uint32_t)a[5 * i + 2] >> 4) |
                                  ((uint32_t)a[5 * i + 3] << 4)) & 0x3FF;
        r->coeffs[4 * i + 3] = (((uint32_t)a[5 * i + 3] >> 6) |
                                  ((uint32_t)a[5 * i + 4] << 2)) & 0x3FF;
    }
}

/* ================================================================= */
/*  t0 packing (13-bit coefficients, centered around 2^{D-1})          */
/* ================================================================= */

void pqc_mldsa_polyt0_pack(uint8_t *r, const pqc_mldsa_poly *a)
{
    unsigned int i;
    uint32_t t[8];

    for (i = 0; i < PQC_MLDSA_N / 8; ++i) {
        t[0] = (uint32_t)((1 << (PQC_MLDSA_D - 1)) - a->coeffs[8 * i + 0]);
        t[1] = (uint32_t)((1 << (PQC_MLDSA_D - 1)) - a->coeffs[8 * i + 1]);
        t[2] = (uint32_t)((1 << (PQC_MLDSA_D - 1)) - a->coeffs[8 * i + 2]);
        t[3] = (uint32_t)((1 << (PQC_MLDSA_D - 1)) - a->coeffs[8 * i + 3]);
        t[4] = (uint32_t)((1 << (PQC_MLDSA_D - 1)) - a->coeffs[8 * i + 4]);
        t[5] = (uint32_t)((1 << (PQC_MLDSA_D - 1)) - a->coeffs[8 * i + 5]);
        t[6] = (uint32_t)((1 << (PQC_MLDSA_D - 1)) - a->coeffs[8 * i + 6]);
        t[7] = (uint32_t)((1 << (PQC_MLDSA_D - 1)) - a->coeffs[8 * i + 7]);

        r[13 * i +  0]  = (uint8_t)(t[0]);
        r[13 * i +  1]  = (uint8_t)(t[0] >>  8);
        r[13 * i +  1] |= (uint8_t)(t[1] <<  5);
        r[13 * i +  2]  = (uint8_t)(t[1] >>  3);
        r[13 * i +  3]  = (uint8_t)(t[1] >> 11);
        r[13 * i +  3] |= (uint8_t)(t[2] <<  2);
        r[13 * i +  4]  = (uint8_t)(t[2] >>  6);
        r[13 * i +  4] |= (uint8_t)(t[3] <<  7);
        r[13 * i +  5]  = (uint8_t)(t[3] >>  1);
        r[13 * i +  6]  = (uint8_t)(t[3] >>  9);
        r[13 * i +  6] |= (uint8_t)(t[4] <<  4);
        r[13 * i +  7]  = (uint8_t)(t[4] >>  4);
        r[13 * i +  8]  = (uint8_t)(t[4] >> 12);
        r[13 * i +  8] |= (uint8_t)(t[5] <<  1);
        r[13 * i +  9]  = (uint8_t)(t[5] >>  7);
        r[13 * i +  9] |= (uint8_t)(t[6] <<  6);
        r[13 * i + 10]  = (uint8_t)(t[6] >>  2);
        r[13 * i + 11]  = (uint8_t)(t[6] >> 10);
        r[13 * i + 11] |= (uint8_t)(t[7] <<  3);
        r[13 * i + 12]  = (uint8_t)(t[7] >>  5);
    }
}

void pqc_mldsa_polyt0_unpack(pqc_mldsa_poly *r, const uint8_t *a)
{
    unsigned int i;

    for (i = 0; i < PQC_MLDSA_N / 8; ++i) {
        r->coeffs[8 * i + 0]  = (int32_t)a[13 * i + 0];
        r->coeffs[8 * i + 0] |= (uint32_t)a[13 * i + 1] << 8;
        r->coeffs[8 * i + 0] &= 0x1FFF;

        r->coeffs[8 * i + 1]  = (int32_t)(a[13 * i + 1] >> 5);
        r->coeffs[8 * i + 1] |= (uint32_t)a[13 * i + 2] << 3;
        r->coeffs[8 * i + 1] |= (uint32_t)a[13 * i + 3] << 11;
        r->coeffs[8 * i + 1] &= 0x1FFF;

        r->coeffs[8 * i + 2]  = (int32_t)(a[13 * i + 3] >> 2);
        r->coeffs[8 * i + 2] |= (uint32_t)a[13 * i + 4] << 6;
        r->coeffs[8 * i + 2] &= 0x1FFF;

        r->coeffs[8 * i + 3]  = (int32_t)(a[13 * i + 4] >> 7);
        r->coeffs[8 * i + 3] |= (uint32_t)a[13 * i + 5] << 1;
        r->coeffs[8 * i + 3] |= (uint32_t)a[13 * i + 6] << 9;
        r->coeffs[8 * i + 3] &= 0x1FFF;

        r->coeffs[8 * i + 4]  = (int32_t)(a[13 * i + 6] >> 4);
        r->coeffs[8 * i + 4] |= (uint32_t)a[13 * i + 7] << 4;
        r->coeffs[8 * i + 4] |= (uint32_t)a[13 * i + 8] << 12;
        r->coeffs[8 * i + 4] &= 0x1FFF;

        r->coeffs[8 * i + 5]  = (int32_t)(a[13 * i + 8] >> 1);
        r->coeffs[8 * i + 5] |= (uint32_t)a[13 * i + 9] << 7;
        r->coeffs[8 * i + 5] &= 0x1FFF;

        r->coeffs[8 * i + 6]  = (int32_t)(a[13 * i + 9] >> 6);
        r->coeffs[8 * i + 6] |= (uint32_t)a[13 * i + 10] << 2;
        r->coeffs[8 * i + 6] |= (uint32_t)a[13 * i + 11] << 10;
        r->coeffs[8 * i + 6] &= 0x1FFF;

        r->coeffs[8 * i + 7]  = (int32_t)(a[13 * i + 11] >> 3);
        r->coeffs[8 * i + 7] |= (uint32_t)a[13 * i + 12] << 5;
        r->coeffs[8 * i + 7] &= 0x1FFF;

        r->coeffs[8 * i + 0] = (1 << (PQC_MLDSA_D - 1)) - r->coeffs[8 * i + 0];
        r->coeffs[8 * i + 1] = (1 << (PQC_MLDSA_D - 1)) - r->coeffs[8 * i + 1];
        r->coeffs[8 * i + 2] = (1 << (PQC_MLDSA_D - 1)) - r->coeffs[8 * i + 2];
        r->coeffs[8 * i + 3] = (1 << (PQC_MLDSA_D - 1)) - r->coeffs[8 * i + 3];
        r->coeffs[8 * i + 4] = (1 << (PQC_MLDSA_D - 1)) - r->coeffs[8 * i + 4];
        r->coeffs[8 * i + 5] = (1 << (PQC_MLDSA_D - 1)) - r->coeffs[8 * i + 5];
        r->coeffs[8 * i + 6] = (1 << (PQC_MLDSA_D - 1)) - r->coeffs[8 * i + 6];
        r->coeffs[8 * i + 7] = (1 << (PQC_MLDSA_D - 1)) - r->coeffs[8 * i + 7];
    }
}

/* ================================================================= */
/*  eta packing                                                        */
/* ================================================================= */

void pqc_mldsa_polyeta_pack(uint8_t *r, const pqc_mldsa_poly *a,
                             unsigned eta)
{
    unsigned int i;
    uint8_t t[8];

    if (eta == 2) {
        /* 3-bit packing: 8 coefficients -> 3 bytes */
        for (i = 0; i < PQC_MLDSA_N / 8; ++i) {
            t[0] = (uint8_t)((int32_t)eta - a->coeffs[8 * i + 0]);
            t[1] = (uint8_t)((int32_t)eta - a->coeffs[8 * i + 1]);
            t[2] = (uint8_t)((int32_t)eta - a->coeffs[8 * i + 2]);
            t[3] = (uint8_t)((int32_t)eta - a->coeffs[8 * i + 3]);
            t[4] = (uint8_t)((int32_t)eta - a->coeffs[8 * i + 4]);
            t[5] = (uint8_t)((int32_t)eta - a->coeffs[8 * i + 5]);
            t[6] = (uint8_t)((int32_t)eta - a->coeffs[8 * i + 6]);
            t[7] = (uint8_t)((int32_t)eta - a->coeffs[8 * i + 7]);

            r[3 * i + 0]  = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
            r[3 * i + 1]  = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
            r[3 * i + 2]  = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
        }
    } else { /* eta == 4 */
        /* 4-bit packing: 2 coefficients -> 1 byte */
        for (i = 0; i < PQC_MLDSA_N / 2; ++i) {
            t[0] = (uint8_t)((int32_t)eta - a->coeffs[2 * i + 0]);
            t[1] = (uint8_t)((int32_t)eta - a->coeffs[2 * i + 1]);
            r[i] = t[0] | (t[1] << 4);
        }
    }
}

void pqc_mldsa_polyeta_unpack(pqc_mldsa_poly *r, const uint8_t *a,
                               unsigned eta)
{
    unsigned int i;

    if (eta == 2) {
        for (i = 0; i < PQC_MLDSA_N / 8; ++i) {
            r->coeffs[8 * i + 0] = (int32_t)((a[3 * i + 0] >> 0) & 7);
            r->coeffs[8 * i + 1] = (int32_t)((a[3 * i + 0] >> 3) & 7);
            r->coeffs[8 * i + 2] = (int32_t)(((a[3 * i + 0] >> 6) |
                                               (a[3 * i + 1] << 2)) & 7);
            r->coeffs[8 * i + 3] = (int32_t)((a[3 * i + 1] >> 1) & 7);
            r->coeffs[8 * i + 4] = (int32_t)((a[3 * i + 1] >> 4) & 7);
            r->coeffs[8 * i + 5] = (int32_t)(((a[3 * i + 1] >> 7) |
                                               (a[3 * i + 2] << 1)) & 7);
            r->coeffs[8 * i + 6] = (int32_t)((a[3 * i + 2] >> 2) & 7);
            r->coeffs[8 * i + 7] = (int32_t)((a[3 * i + 2] >> 5) & 7);

            r->coeffs[8 * i + 0] = (int32_t)eta - r->coeffs[8 * i + 0];
            r->coeffs[8 * i + 1] = (int32_t)eta - r->coeffs[8 * i + 1];
            r->coeffs[8 * i + 2] = (int32_t)eta - r->coeffs[8 * i + 2];
            r->coeffs[8 * i + 3] = (int32_t)eta - r->coeffs[8 * i + 3];
            r->coeffs[8 * i + 4] = (int32_t)eta - r->coeffs[8 * i + 4];
            r->coeffs[8 * i + 5] = (int32_t)eta - r->coeffs[8 * i + 5];
            r->coeffs[8 * i + 6] = (int32_t)eta - r->coeffs[8 * i + 6];
            r->coeffs[8 * i + 7] = (int32_t)eta - r->coeffs[8 * i + 7];
        }
    } else { /* eta == 4 */
        for (i = 0; i < PQC_MLDSA_N / 2; ++i) {
            r->coeffs[2 * i + 0] = (int32_t)(a[i] & 0x0F);
            r->coeffs[2 * i + 1] = (int32_t)(a[i] >> 4);
            r->coeffs[2 * i + 0] = (int32_t)eta - r->coeffs[2 * i + 0];
            r->coeffs[2 * i + 1] = (int32_t)eta - r->coeffs[2 * i + 1];
        }
    }
}

/* ================================================================= */
/*  z packing (gamma1-centered coefficients)                           */
/* ================================================================= */

void pqc_mldsa_polyz_pack(uint8_t *r, const pqc_mldsa_poly *a,
                           int32_t gamma1)
{
    unsigned int i;
    uint32_t t[4];

    if (gamma1 == (1 << 17)) {
        /* 18-bit encoding */
        for (i = 0; i < PQC_MLDSA_N / 4; ++i) {
            t[0] = (uint32_t)(gamma1 - a->coeffs[4 * i + 0]);
            t[1] = (uint32_t)(gamma1 - a->coeffs[4 * i + 1]);
            t[2] = (uint32_t)(gamma1 - a->coeffs[4 * i + 2]);
            t[3] = (uint32_t)(gamma1 - a->coeffs[4 * i + 3]);

            r[9 * i + 0]  = (uint8_t)(t[0]);
            r[9 * i + 1]  = (uint8_t)(t[0] >> 8);
            r[9 * i + 2]  = (uint8_t)(t[0] >> 16);
            r[9 * i + 2] |= (uint8_t)(t[1] << 2);
            r[9 * i + 3]  = (uint8_t)(t[1] >> 6);
            r[9 * i + 4]  = (uint8_t)(t[1] >> 14);
            r[9 * i + 4] |= (uint8_t)(t[2] << 4);
            r[9 * i + 5]  = (uint8_t)(t[2] >> 4);
            r[9 * i + 6]  = (uint8_t)(t[2] >> 12);
            r[9 * i + 6] |= (uint8_t)(t[3] << 6);
            r[9 * i + 7]  = (uint8_t)(t[3] >> 2);
            r[9 * i + 8]  = (uint8_t)(t[3] >> 10);
        }
    } else {
        /* 20-bit encoding (gamma1 = 2^19) */
        for (i = 0; i < PQC_MLDSA_N / 2; ++i) {
            t[0] = (uint32_t)(gamma1 - a->coeffs[2 * i + 0]);
            t[1] = (uint32_t)(gamma1 - a->coeffs[2 * i + 1]);

            r[5 * i + 0]  = (uint8_t)(t[0]);
            r[5 * i + 1]  = (uint8_t)(t[0] >> 8);
            r[5 * i + 2]  = (uint8_t)(t[0] >> 16);
            r[5 * i + 2] |= (uint8_t)(t[1] << 4);
            r[5 * i + 3]  = (uint8_t)(t[1] >> 4);
            r[5 * i + 4]  = (uint8_t)(t[1] >> 12);
        }
    }
}

void pqc_mldsa_polyz_unpack(pqc_mldsa_poly *r, const uint8_t *a,
                             int32_t gamma1)
{
    unsigned int i;

    if (gamma1 == (1 << 17)) {
        for (i = 0; i < PQC_MLDSA_N / 4; ++i) {
            r->coeffs[4 * i + 0]  = (int32_t)a[9 * i + 0];
            r->coeffs[4 * i + 0] |= (uint32_t)a[9 * i + 1] << 8;
            r->coeffs[4 * i + 0] |= (uint32_t)a[9 * i + 2] << 16;
            r->coeffs[4 * i + 0] &= 0x3FFFF;

            r->coeffs[4 * i + 1]  = (int32_t)(a[9 * i + 2] >> 2);
            r->coeffs[4 * i + 1] |= (uint32_t)a[9 * i + 3] << 6;
            r->coeffs[4 * i + 1] |= (uint32_t)a[9 * i + 4] << 14;
            r->coeffs[4 * i + 1] &= 0x3FFFF;

            r->coeffs[4 * i + 2]  = (int32_t)(a[9 * i + 4] >> 4);
            r->coeffs[4 * i + 2] |= (uint32_t)a[9 * i + 5] << 4;
            r->coeffs[4 * i + 2] |= (uint32_t)a[9 * i + 6] << 12;
            r->coeffs[4 * i + 2] &= 0x3FFFF;

            r->coeffs[4 * i + 3]  = (int32_t)(a[9 * i + 6] >> 6);
            r->coeffs[4 * i + 3] |= (uint32_t)a[9 * i + 7] << 2;
            r->coeffs[4 * i + 3] |= (uint32_t)a[9 * i + 8] << 10;
            r->coeffs[4 * i + 3] &= 0x3FFFF;

            r->coeffs[4 * i + 0] = gamma1 - r->coeffs[4 * i + 0];
            r->coeffs[4 * i + 1] = gamma1 - r->coeffs[4 * i + 1];
            r->coeffs[4 * i + 2] = gamma1 - r->coeffs[4 * i + 2];
            r->coeffs[4 * i + 3] = gamma1 - r->coeffs[4 * i + 3];
        }
    } else {
        for (i = 0; i < PQC_MLDSA_N / 2; ++i) {
            r->coeffs[2 * i + 0]  = (int32_t)a[5 * i + 0];
            r->coeffs[2 * i + 0] |= (uint32_t)a[5 * i + 1] << 8;
            r->coeffs[2 * i + 0] |= (uint32_t)a[5 * i + 2] << 16;
            r->coeffs[2 * i + 0] &= 0xFFFFF;

            r->coeffs[2 * i + 1]  = (int32_t)(a[5 * i + 2] >> 4);
            r->coeffs[2 * i + 1] |= (uint32_t)a[5 * i + 3] << 4;
            r->coeffs[2 * i + 1] |= (uint32_t)a[5 * i + 4] << 12;

            r->coeffs[2 * i + 0] = gamma1 - r->coeffs[2 * i + 0];
            r->coeffs[2 * i + 1] = gamma1 - r->coeffs[2 * i + 1];
        }
    }
}

/* ================================================================= */
/*  w1 packing                                                         */
/* ================================================================= */

void pqc_mldsa_polyw1_pack(uint8_t *r, const pqc_mldsa_poly *a,
                            int32_t gamma2)
{
    unsigned int i;

    if (gamma2 == (PQC_MLDSA_Q - 1) / 88) {
        /* 6-bit coefficients: 4 coefficients -> 3 bytes */
        for (i = 0; i < PQC_MLDSA_N / 4; ++i) {
            r[3 * i + 0]  = (uint8_t)(a->coeffs[4 * i + 0]);
            r[3 * i + 0] |= (uint8_t)(a->coeffs[4 * i + 1] << 6);
            r[3 * i + 1]  = (uint8_t)(a->coeffs[4 * i + 1] >> 2);
            r[3 * i + 1] |= (uint8_t)(a->coeffs[4 * i + 2] << 4);
            r[3 * i + 2]  = (uint8_t)(a->coeffs[4 * i + 2] >> 4);
            r[3 * i + 2] |= (uint8_t)(a->coeffs[4 * i + 3] << 2);
        }
    } else {
        /* 4-bit coefficients: 2 coefficients -> 1 byte */
        for (i = 0; i < PQC_MLDSA_N / 2; ++i) {
            r[i] = (uint8_t)(a->coeffs[2 * i + 0]) |
                   (uint8_t)(a->coeffs[2 * i + 1] << 4);
        }
    }
}

/* ================================================================= */
/*  Public key: pk = rho || t1                                         */
/* ================================================================= */

void pqc_mldsa_pack_pk(uint8_t *pk,
                        const uint8_t rho[PQC_MLDSA_SEEDBYTES],
                        const pqc_mldsa_polyveck *t1,
                        unsigned k)
{
    unsigned int i;

    memcpy(pk, rho, PQC_MLDSA_SEEDBYTES);
    pk += PQC_MLDSA_SEEDBYTES;

    for (i = 0; i < k; ++i) {
        pqc_mldsa_polyt1_pack(pk, &t1->vec[i]);
        pk += PQC_MLDSA_POLYT1_PACKEDBYTES;
    }
}

void pqc_mldsa_unpack_pk(uint8_t rho[PQC_MLDSA_SEEDBYTES],
                          pqc_mldsa_polyveck *t1,
                          const uint8_t *pk,
                          unsigned k)
{
    unsigned int i;

    memcpy(rho, pk, PQC_MLDSA_SEEDBYTES);
    pk += PQC_MLDSA_SEEDBYTES;

    for (i = 0; i < k; ++i) {
        pqc_mldsa_polyt1_unpack(&t1->vec[i], pk);
        pk += PQC_MLDSA_POLYT1_PACKEDBYTES;
    }
}

/* ================================================================= */
/*  Secret key: sk = rho || K || tr || s1 || s2 || t0                  */
/*  Note: reference order is rho, key, tr, s1, s2, t0                 */
/* ================================================================= */

void pqc_mldsa_pack_sk(uint8_t *sk,
                        const uint8_t rho[PQC_MLDSA_SEEDBYTES],
                        const uint8_t tr[PQC_MLDSA_TRBYTES],
                        const uint8_t K[PQC_MLDSA_SEEDBYTES],
                        const pqc_mldsa_polyveck *t0,
                        const pqc_mldsa_polyvecl *s1,
                        const pqc_mldsa_polyveck *s2,
                        const pqc_mldsa_params_t *params)
{
    unsigned int i;

    memcpy(sk, rho, PQC_MLDSA_SEEDBYTES);
    sk += PQC_MLDSA_SEEDBYTES;

    memcpy(sk, K, PQC_MLDSA_SEEDBYTES);
    sk += PQC_MLDSA_SEEDBYTES;

    memcpy(sk, tr, PQC_MLDSA_TRBYTES);
    sk += PQC_MLDSA_TRBYTES;

    for (i = 0; i < params->l; ++i) {
        pqc_mldsa_polyeta_pack(sk, &s1->vec[i], params->eta);
        sk += params->polyeta_packed;
    }

    for (i = 0; i < params->k; ++i) {
        pqc_mldsa_polyeta_pack(sk, &s2->vec[i], params->eta);
        sk += params->polyeta_packed;
    }

    for (i = 0; i < params->k; ++i) {
        pqc_mldsa_polyt0_pack(sk, &t0->vec[i]);
        sk += PQC_MLDSA_POLYT0_PACKEDBYTES;
    }
}

void pqc_mldsa_unpack_sk(uint8_t rho[PQC_MLDSA_SEEDBYTES],
                          uint8_t tr[PQC_MLDSA_TRBYTES],
                          uint8_t K[PQC_MLDSA_SEEDBYTES],
                          pqc_mldsa_polyveck *t0,
                          pqc_mldsa_polyvecl *s1,
                          pqc_mldsa_polyveck *s2,
                          const uint8_t *sk,
                          const pqc_mldsa_params_t *params)
{
    unsigned int i;

    memcpy(rho, sk, PQC_MLDSA_SEEDBYTES);
    sk += PQC_MLDSA_SEEDBYTES;

    memcpy(K, sk, PQC_MLDSA_SEEDBYTES);
    sk += PQC_MLDSA_SEEDBYTES;

    memcpy(tr, sk, PQC_MLDSA_TRBYTES);
    sk += PQC_MLDSA_TRBYTES;

    for (i = 0; i < params->l; ++i) {
        pqc_mldsa_polyeta_unpack(&s1->vec[i], sk, params->eta);
        sk += params->polyeta_packed;
    }

    for (i = 0; i < params->k; ++i) {
        pqc_mldsa_polyeta_unpack(&s2->vec[i], sk, params->eta);
        sk += params->polyeta_packed;
    }

    for (i = 0; i < params->k; ++i) {
        pqc_mldsa_polyt0_unpack(&t0->vec[i], sk);
        sk += PQC_MLDSA_POLYT0_PACKEDBYTES;
    }
}

/* ================================================================= */
/*  Signature: sig = c_tilde || z || h                                 */
/* ================================================================= */

void pqc_mldsa_pack_sig(uint8_t *sig,
                         const uint8_t *ctilde,
                         const pqc_mldsa_polyvecl *z,
                         const pqc_mldsa_polyveck *h,
                         const pqc_mldsa_params_t *params)
{
    unsigned int i, j, k_cnt;

    memcpy(sig, ctilde, params->ctilde_bytes);
    sig += params->ctilde_bytes;

    for (i = 0; i < params->l; ++i) {
        pqc_mldsa_polyz_pack(sig, &z->vec[i], params->gamma1);
        sig += params->polyz_packed;
    }

    /* Encode hint h */
    memset(sig, 0, params->omega + params->k);
    k_cnt = 0;
    for (i = 0; i < params->k; ++i) {
        for (j = 0; j < PQC_MLDSA_N; ++j)
            if (h->vec[i].coeffs[j] != 0)
                sig[k_cnt++] = (uint8_t)j;
        sig[params->omega + i] = (uint8_t)k_cnt;
    }
}

int pqc_mldsa_unpack_sig(uint8_t *ctilde,
                          pqc_mldsa_polyvecl *z,
                          pqc_mldsa_polyveck *h,
                          const uint8_t *sig,
                          const pqc_mldsa_params_t *params)
{
    unsigned int i, j, k_cnt;

    memcpy(ctilde, sig, params->ctilde_bytes);
    sig += params->ctilde_bytes;

    for (i = 0; i < params->l; ++i) {
        pqc_mldsa_polyz_unpack(&z->vec[i], sig, params->gamma1);
        sig += params->polyz_packed;
    }

    /* Decode hint h */
    k_cnt = 0;
    for (i = 0; i < params->k; ++i) {
        for (j = 0; j < PQC_MLDSA_N; ++j)
            h->vec[i].coeffs[j] = 0;

        if (sig[params->omega + i] < k_cnt || sig[params->omega + i] > params->omega)
            return 1;

        for (j = k_cnt; j < sig[params->omega + i]; ++j) {
            /* Coefficients are ordered for strong unforgeability */
            if (j > k_cnt && sig[j] <= sig[j - 1])
                return 1;
            h->vec[i].coeffs[sig[j]] = 1;
        }

        k_cnt = sig[params->omega + i];
    }

    /* Extra indices must be zero for strong unforgeability */
    for (j = k_cnt; j < params->omega; ++j)
        if (sig[j])
            return 1;

    return 0;
}
