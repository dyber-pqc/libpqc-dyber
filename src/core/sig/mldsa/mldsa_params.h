/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * ML-DSA (FIPS 204) parameter definitions for all security levels.
 */

#ifndef PQC_MLDSA_PARAMS_H
#define PQC_MLDSA_PARAMS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Common parameters                                                    */
/* ------------------------------------------------------------------ */

#define PQC_MLDSA_N             256
#define PQC_MLDSA_Q             8380417
#define PQC_MLDSA_D             13       /* dropped bits in t            */
#define PQC_MLDSA_SEEDBYTES     32       /* rho, rho', K seed lengths    */
#define PQC_MLDSA_CRHBYTES      64       /* mu, rho' length              */
#define PQC_MLDSA_TRBYTES       64       /* tr = H(pk) length            */
#define PQC_MLDSA_POLYT1_PACKEDBYTES  320  /* 256 * 10 / 8               */
#define PQC_MLDSA_POLYT0_PACKEDBYTES  416  /* 256 * 13 / 8               */

/* Maximum dimensions across all parameter sets */
#define PQC_MLDSA_K_MAX         8
#define PQC_MLDSA_L_MAX         7

/* ------------------------------------------------------------------ */
/* ML-DSA-44 (NIST security level 2)                                    */
/* ------------------------------------------------------------------ */

#define PQC_MLDSA44_K           4
#define PQC_MLDSA44_L           4
#define PQC_MLDSA44_ETA         2
#define PQC_MLDSA44_TAU         39
#define PQC_MLDSA44_BETA        78       /* tau * eta                    */
#define PQC_MLDSA44_GAMMA1      (1 << 17)  /* 2^17 = 131072             */
#define PQC_MLDSA44_GAMMA2      ((PQC_MLDSA_Q - 1) / 88)  /* 95232     */
#define PQC_MLDSA44_OMEGA       80

#define PQC_MLDSA44_POLYZ_PACKEDBYTES   576   /* 256 * 18 / 8           */
#define PQC_MLDSA44_POLYW1_PACKEDBYTES  192   /* 256 * 6 / 8            */
#define PQC_MLDSA44_POLYETA_PACKEDBYTES  96   /* 256 * 3 / 8            */

#define PQC_MLDSA44_PUBLICKEYBYTES   1312
#define PQC_MLDSA44_SECRETKEYBYTES   2560
#define PQC_MLDSA44_SIGBYTES         2420
#define PQC_MLDSA44_CTILDEBYTES      32

/* ------------------------------------------------------------------ */
/* ML-DSA-65 (NIST security level 3)                                    */
/* ------------------------------------------------------------------ */

#define PQC_MLDSA65_K           6
#define PQC_MLDSA65_L           5
#define PQC_MLDSA65_ETA         4
#define PQC_MLDSA65_TAU         49
#define PQC_MLDSA65_BETA        196      /* tau * eta                    */
#define PQC_MLDSA65_GAMMA1      (1 << 19)  /* 2^19 = 524288             */
#define PQC_MLDSA65_GAMMA2      ((PQC_MLDSA_Q - 1) / 32)  /* 261888    */
#define PQC_MLDSA65_OMEGA       55

#define PQC_MLDSA65_POLYZ_PACKEDBYTES   640   /* 256 * 20 / 8           */
#define PQC_MLDSA65_POLYW1_PACKEDBYTES  128   /* 256 * 4 / 8            */
#define PQC_MLDSA65_POLYETA_PACKEDBYTES 128   /* 256 * 4 / 8            */

#define PQC_MLDSA65_PUBLICKEYBYTES   1952
#define PQC_MLDSA65_SECRETKEYBYTES   4032
#define PQC_MLDSA65_SIGBYTES         3309
#define PQC_MLDSA65_CTILDEBYTES      48

/* ------------------------------------------------------------------ */
/* ML-DSA-87 (NIST security level 5)                                    */
/* ------------------------------------------------------------------ */

#define PQC_MLDSA87_K           8
#define PQC_MLDSA87_L           7
#define PQC_MLDSA87_ETA         2
#define PQC_MLDSA87_TAU         60
#define PQC_MLDSA87_BETA        120      /* tau * eta                    */
#define PQC_MLDSA87_GAMMA1      (1 << 19)  /* 2^19 = 524288             */
#define PQC_MLDSA87_GAMMA2      ((PQC_MLDSA_Q - 1) / 32)  /* 261888    */
#define PQC_MLDSA87_OMEGA       75

#define PQC_MLDSA87_POLYZ_PACKEDBYTES   640   /* 256 * 20 / 8           */
#define PQC_MLDSA87_POLYW1_PACKEDBYTES  128   /* 256 * 4 / 8            */
#define PQC_MLDSA87_POLYETA_PACKEDBYTES  96   /* 256 * 3 / 8            */

#define PQC_MLDSA87_PUBLICKEYBYTES   2592
#define PQC_MLDSA87_SECRETKEYBYTES   4896
#define PQC_MLDSA87_SIGBYTES         4627
#define PQC_MLDSA87_CTILDEBYTES      64

/* ------------------------------------------------------------------ */
/* Runtime parameter structure                                          */
/* ------------------------------------------------------------------ */

/**
 * ML-DSA parameter set descriptor.
 *
 * Holds every constant needed to drive the generic (parameterised)
 * ML-DSA implementation at runtime.
 */
typedef struct {
    const char *name;           /* e.g. "ML-DSA-65"                    */
    unsigned    k;              /* rows in matrix A                     */
    unsigned    l;              /* columns in matrix A                  */
    unsigned    eta;            /* secret coefficient range [-eta,eta]  */
    unsigned    tau;            /* number of +/-1 in challenge c        */
    unsigned    beta;           /* tau * eta                            */
    int32_t     gamma1;         /* y coefficient range                  */
    int32_t     gamma2;         /* low-order rounding range             */
    unsigned    omega;          /* max number of 1s in hint             */
    unsigned    ctilde_bytes;   /* challenge hash length                */

    /* Packed byte-lengths */
    size_t      polyz_packed;   /* packed z polynomial bytes            */
    size_t      polyw1_packed;  /* packed w1 polynomial bytes           */
    size_t      polyeta_packed; /* packed eta polynomial bytes          */

    size_t      pk_bytes;       /* public key size                      */
    size_t      sk_bytes;       /* secret key size                      */
    size_t      sig_bytes;      /* signature size                       */
} pqc_mldsa_params_t;

/* Pre-initialised parameter sets (const globals defined in mldsa.c). */
extern const pqc_mldsa_params_t PQC_MLDSA_44;
extern const pqc_mldsa_params_t PQC_MLDSA_65;
extern const pqc_mldsa_params_t PQC_MLDSA_87;

#ifdef __cplusplus
}
#endif

#endif /* PQC_MLDSA_PARAMS_H */
