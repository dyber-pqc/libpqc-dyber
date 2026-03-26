/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Polynomial vector operations for ML-DSA (FIPS 204).
 */

#include "core/sig/mldsa/polyvec.h"
#include "core/sig/mldsa/poly.h"
#include "core/sig/mldsa/ntt.h"
#include "core/sig/mldsa/mldsa_params.h"

/* ================================================================= */
/*  l-vector operations                                                */
/* ================================================================= */

void pqc_mldsa_polyvecl_add(pqc_mldsa_polyvecl *w,
                             const pqc_mldsa_polyvecl *u,
                             const pqc_mldsa_polyvecl *v,
                             unsigned l)
{
    unsigned i;
    for (i = 0; i < l; i++)
        pqc_mldsa_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

void pqc_mldsa_polyvecl_ntt(pqc_mldsa_polyvecl *v, unsigned l)
{
    unsigned i;
    for (i = 0; i < l; i++)
        pqc_mldsa_poly_ntt(&v->vec[i]);
}

void pqc_mldsa_polyvecl_invntt(pqc_mldsa_polyvecl *v, unsigned l)
{
    unsigned i;
    for (i = 0; i < l; i++)
        pqc_mldsa_poly_invntt(&v->vec[i]);
}

void pqc_mldsa_polyvecl_reduce(pqc_mldsa_polyvecl *v, unsigned l)
{
    unsigned i;
    for (i = 0; i < l; i++)
        pqc_mldsa_poly_reduce(&v->vec[i]);
}

void pqc_mldsa_polyvecl_pointwise_poly(pqc_mldsa_polyvecl *r,
                                        const pqc_mldsa_poly *a,
                                        const pqc_mldsa_polyvecl *v,
                                        unsigned l)
{
    unsigned i;
    for (i = 0; i < l; i++)
        pqc_mldsa_poly_pointwise(&r->vec[i], a, &v->vec[i]);
}

int pqc_mldsa_polyvecl_chknorm(const pqc_mldsa_polyvecl *v,
                                int32_t bound, unsigned l)
{
    unsigned i;
    for (i = 0; i < l; i++)
        if (pqc_mldsa_poly_chknorm(&v->vec[i], bound))
            return 1;
    return 0;
}

/* ================================================================= */
/*  k-vector operations                                                */
/* ================================================================= */

void pqc_mldsa_polyveck_add(pqc_mldsa_polyveck *w,
                             const pqc_mldsa_polyveck *u,
                             const pqc_mldsa_polyveck *v,
                             unsigned k)
{
    unsigned i;
    for (i = 0; i < k; i++)
        pqc_mldsa_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

void pqc_mldsa_polyveck_sub(pqc_mldsa_polyveck *w,
                             const pqc_mldsa_polyveck *u,
                             const pqc_mldsa_polyveck *v,
                             unsigned k)
{
    unsigned i;
    for (i = 0; i < k; i++)
        pqc_mldsa_poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
}

void pqc_mldsa_polyveck_ntt(pqc_mldsa_polyveck *v, unsigned k)
{
    unsigned i;
    for (i = 0; i < k; i++)
        pqc_mldsa_poly_ntt(&v->vec[i]);
}

void pqc_mldsa_polyveck_invntt(pqc_mldsa_polyveck *v, unsigned k)
{
    unsigned i;
    for (i = 0; i < k; i++)
        pqc_mldsa_poly_invntt(&v->vec[i]);
}

void pqc_mldsa_polyveck_reduce(pqc_mldsa_polyveck *v, unsigned k)
{
    unsigned i;
    for (i = 0; i < k; i++)
        pqc_mldsa_poly_reduce(&v->vec[i]);
}

void pqc_mldsa_polyveck_caddq(pqc_mldsa_polyveck *v, unsigned k)
{
    unsigned i;
    for (i = 0; i < k; i++)
        pqc_mldsa_poly_caddq(&v->vec[i]);
}

void pqc_mldsa_polyveck_shiftl(pqc_mldsa_polyveck *v, unsigned k)
{
    unsigned i;
    for (i = 0; i < k; i++)
        pqc_mldsa_poly_shiftl(&v->vec[i]);
}

int pqc_mldsa_polyveck_chknorm(const pqc_mldsa_polyveck *v,
                                int32_t bound, unsigned k)
{
    unsigned i;
    for (i = 0; i < k; i++)
        if (pqc_mldsa_poly_chknorm(&v->vec[i], bound))
            return 1;
    return 0;
}

void pqc_mldsa_polyveck_power2round(pqc_mldsa_polyveck *v1,
                                     pqc_mldsa_polyveck *v0,
                                     const pqc_mldsa_polyveck *v,
                                     unsigned k)
{
    unsigned i;
    for (i = 0; i < k; i++)
        pqc_mldsa_poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

void pqc_mldsa_polyveck_decompose(pqc_mldsa_polyveck *v1,
                                   pqc_mldsa_polyveck *v0,
                                   const pqc_mldsa_polyveck *v,
                                   int32_t gamma2, unsigned k)
{
    unsigned i;
    for (i = 0; i < k; i++)
        pqc_mldsa_poly_decompose(&v1->vec[i], &v0->vec[i],
                                  &v->vec[i], gamma2);
}

unsigned pqc_mldsa_polyveck_make_hint(pqc_mldsa_polyveck *h,
                                       const pqc_mldsa_polyveck *v0,
                                       const pqc_mldsa_polyveck *v1,
                                       int32_t gamma2, unsigned k)
{
    unsigned i, s = 0;
    for (i = 0; i < k; i++)
        s += pqc_mldsa_poly_make_hint(&h->vec[i], &v0->vec[i],
                                       &v1->vec[i], gamma2);
    return s;
}

void pqc_mldsa_polyveck_use_hint(pqc_mldsa_polyveck *w,
                                  const pqc_mldsa_polyveck *v,
                                  const pqc_mldsa_polyveck *h,
                                  int32_t gamma2, unsigned k)
{
    unsigned i;
    for (i = 0; i < k; i++)
        pqc_mldsa_poly_use_hint(&w->vec[i], &v->vec[i],
                                 &h->vec[i], gamma2);
}

/* ================================================================= */
/*  Matrix-vector multiplication: t = A * s                            */
/*  A is stored as k*l polynomials in NTT domain.                      */
/*  s must be in NTT domain.                                           */
/* ================================================================= */

void pqc_mldsa_polyvec_matrix_pointwise(
    pqc_mldsa_polyveck *t,
    const pqc_mldsa_poly mat[PQC_MLDSA_K_MAX * PQC_MLDSA_L_MAX],
    const pqc_mldsa_polyvecl *s,
    unsigned k, unsigned l)
{
    unsigned i, j;
    pqc_mldsa_poly tmp;

    for (i = 0; i < k; i++) {
        pqc_mldsa_poly_pointwise(&t->vec[i], &mat[i * l + 0], &s->vec[0]);
        for (j = 1; j < l; j++) {
            pqc_mldsa_poly_pointwise(&tmp, &mat[i * l + j], &s->vec[j]);
            pqc_mldsa_poly_add(&t->vec[i], &t->vec[i], &tmp);
        }
    }
}
