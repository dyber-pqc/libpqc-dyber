/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * ML-KEM (FIPS 203) parameter definitions for all security levels.
 */

#ifndef PQC_MLKEM_PARAMS_H
#define PQC_MLKEM_PARAMS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Common parameters                                                    */
/* ------------------------------------------------------------------ */

#define PQC_MLKEM_N             256
#define PQC_MLKEM_Q             3329
#define PQC_MLKEM_SYMBYTES      32   /* seed / shared-secret length    */
#define PQC_MLKEM_SSBYTES       32   /* shared secret length           */
#define PQC_MLKEM_POLYBYTES     384  /* 256 * 12 / 8                   */

/* Maximum k across all parameter sets (ML-KEM-1024 uses k=4). */
#define PQC_MLKEM_K_MAX         4

/* ------------------------------------------------------------------ */
/* ML-KEM-512 (NIST security level 1)                                   */
/* ------------------------------------------------------------------ */

#define PQC_MLKEM512_K          2
#define PQC_MLKEM512_ETA1       3
#define PQC_MLKEM512_ETA2       2
#define PQC_MLKEM512_DU         10
#define PQC_MLKEM512_DV         4

/* Derived sizes (bytes) */
#define PQC_MLKEM512_POLYCOMPRESSEDBYTES_DU    320  /* 256*10/8 */
#define PQC_MLKEM512_POLYCOMPRESSEDBYTES_DV    128  /* 256*4/8  */
#define PQC_MLKEM512_POLYVECBYTES              (PQC_MLKEM512_K * PQC_MLKEM_POLYBYTES)        /* 768  */
#define PQC_MLKEM512_POLYVECCOMPRESSEDBYTES    (PQC_MLKEM512_K * PQC_MLKEM512_POLYCOMPRESSEDBYTES_DU) /* 640 */
#define PQC_MLKEM512_INDCPA_MSGBYTES           PQC_MLKEM_SYMBYTES                            /* 32   */
#define PQC_MLKEM512_INDCPA_PUBLICKEYBYTES     (PQC_MLKEM512_POLYVECBYTES + PQC_MLKEM_SYMBYTES) /* 800 */
#define PQC_MLKEM512_INDCPA_SECRETKEYBYTES     PQC_MLKEM512_POLYVECBYTES                     /* 768  */
#define PQC_MLKEM512_INDCPA_BYTES              (PQC_MLKEM512_POLYVECCOMPRESSEDBYTES + PQC_MLKEM512_POLYCOMPRESSEDBYTES_DV) /* 768 */

#define PQC_MLKEM512_PUBLICKEYBYTES            PQC_MLKEM512_INDCPA_PUBLICKEYBYTES             /* 800  */
#define PQC_MLKEM512_SECRETKEYBYTES            (PQC_MLKEM512_INDCPA_SECRETKEYBYTES + PQC_MLKEM512_INDCPA_PUBLICKEYBYTES + 2 * PQC_MLKEM_SYMBYTES) /* 1632 */
#define PQC_MLKEM512_CIPHERTEXTBYTES           PQC_MLKEM512_INDCPA_BYTES                      /* 768  */

/* ------------------------------------------------------------------ */
/* ML-KEM-768 (NIST security level 3)                                   */
/* ------------------------------------------------------------------ */

#define PQC_MLKEM768_K          3
#define PQC_MLKEM768_ETA1       2
#define PQC_MLKEM768_ETA2       2
#define PQC_MLKEM768_DU         10
#define PQC_MLKEM768_DV         4

#define PQC_MLKEM768_POLYCOMPRESSEDBYTES_DU    320  /* 256*10/8 */
#define PQC_MLKEM768_POLYCOMPRESSEDBYTES_DV    128  /* 256*4/8  */
#define PQC_MLKEM768_POLYVECBYTES              (PQC_MLKEM768_K * PQC_MLKEM_POLYBYTES)        /* 1152 */
#define PQC_MLKEM768_POLYVECCOMPRESSEDBYTES    (PQC_MLKEM768_K * PQC_MLKEM768_POLYCOMPRESSEDBYTES_DU) /* 960 */
#define PQC_MLKEM768_INDCPA_MSGBYTES           PQC_MLKEM_SYMBYTES
#define PQC_MLKEM768_INDCPA_PUBLICKEYBYTES     (PQC_MLKEM768_POLYVECBYTES + PQC_MLKEM_SYMBYTES) /* 1184 */
#define PQC_MLKEM768_INDCPA_SECRETKEYBYTES     PQC_MLKEM768_POLYVECBYTES                     /* 1152 */
#define PQC_MLKEM768_INDCPA_BYTES              (PQC_MLKEM768_POLYVECCOMPRESSEDBYTES + PQC_MLKEM768_POLYCOMPRESSEDBYTES_DV) /* 1088 */

#define PQC_MLKEM768_PUBLICKEYBYTES            PQC_MLKEM768_INDCPA_PUBLICKEYBYTES             /* 1184 */
#define PQC_MLKEM768_SECRETKEYBYTES            (PQC_MLKEM768_INDCPA_SECRETKEYBYTES + PQC_MLKEM768_INDCPA_PUBLICKEYBYTES + 2 * PQC_MLKEM_SYMBYTES) /* 2400 */
#define PQC_MLKEM768_CIPHERTEXTBYTES           PQC_MLKEM768_INDCPA_BYTES                      /* 1088 */

/* ------------------------------------------------------------------ */
/* ML-KEM-1024 (NIST security level 5)                                  */
/* ------------------------------------------------------------------ */

#define PQC_MLKEM1024_K         4
#define PQC_MLKEM1024_ETA1      2
#define PQC_MLKEM1024_ETA2      2
#define PQC_MLKEM1024_DU        11
#define PQC_MLKEM1024_DV        5

#define PQC_MLKEM1024_POLYCOMPRESSEDBYTES_DU   352  /* 256*11/8 */
#define PQC_MLKEM1024_POLYCOMPRESSEDBYTES_DV   160  /* 256*5/8  */
#define PQC_MLKEM1024_POLYVECBYTES             (PQC_MLKEM1024_K * PQC_MLKEM_POLYBYTES)       /* 1536 */
#define PQC_MLKEM1024_POLYVECCOMPRESSEDBYTES   (PQC_MLKEM1024_K * PQC_MLKEM1024_POLYCOMPRESSEDBYTES_DU) /* 1408 */
#define PQC_MLKEM1024_INDCPA_MSGBYTES          PQC_MLKEM_SYMBYTES
#define PQC_MLKEM1024_INDCPA_PUBLICKEYBYTES    (PQC_MLKEM1024_POLYVECBYTES + PQC_MLKEM_SYMBYTES) /* 1568 */
#define PQC_MLKEM1024_INDCPA_SECRETKEYBYTES    PQC_MLKEM1024_POLYVECBYTES                    /* 1536 */
#define PQC_MLKEM1024_INDCPA_BYTES             (PQC_MLKEM1024_POLYVECCOMPRESSEDBYTES + PQC_MLKEM1024_POLYCOMPRESSEDBYTES_DV) /* 1568 */

#define PQC_MLKEM1024_PUBLICKEYBYTES           PQC_MLKEM1024_INDCPA_PUBLICKEYBYTES            /* 1568 */
#define PQC_MLKEM1024_SECRETKEYBYTES           (PQC_MLKEM1024_INDCPA_SECRETKEYBYTES + PQC_MLKEM1024_INDCPA_PUBLICKEYBYTES + 2 * PQC_MLKEM_SYMBYTES) /* 3168 */
#define PQC_MLKEM1024_CIPHERTEXTBYTES          PQC_MLKEM1024_INDCPA_BYTES                     /* 1568 */

/* ------------------------------------------------------------------ */
/* Runtime parameter structure                                          */
/* ------------------------------------------------------------------ */

/**
 * ML-KEM parameter set descriptor.
 *
 * Holds every constant needed to drive the generic (parameterised)
 * ML-KEM implementation at runtime.
 */
typedef struct {
    const char *name;           /* e.g. "ML-KEM-768"                  */
    unsigned    k;              /* module rank: 2, 3, or 4            */
    unsigned    eta1;           /* CBD parameter for secret/noise     */
    unsigned    eta2;           /* CBD parameter for encryption noise */
    unsigned    du;             /* compression bits for vector u      */
    unsigned    dv;             /* compression bits for polynomial v  */

    /* Derived byte-lengths */
    size_t      poly_compressed_du;   /* 256 * du / 8               */
    size_t      poly_compressed_dv;   /* 256 * dv / 8               */
    size_t      polyvec_bytes;        /* k * POLYBYTES              */
    size_t      polyvec_compressed;   /* k * poly_compressed_du     */
    size_t      indcpa_pk_bytes;      /* polyvec_bytes + SYMBYTES   */
    size_t      indcpa_sk_bytes;      /* polyvec_bytes              */
    size_t      indcpa_bytes;         /* polyvec_compressed + poly_compressed_dv */
    size_t      pk_bytes;             /* = indcpa_pk_bytes          */
    size_t      sk_bytes;             /* indcpa_sk + indcpa_pk + 2*SYMBYTES */
    size_t      ct_bytes;             /* = indcpa_bytes             */
    size_t      ss_bytes;             /* SSBYTES (32)               */
} pqc_mlkem_params_t;

/* Pre-initialised parameter sets (const globals defined in mlkem.c). */
extern const pqc_mlkem_params_t PQC_MLKEM_512;
extern const pqc_mlkem_params_t PQC_MLKEM_768;
extern const pqc_mlkem_params_t PQC_MLKEM_1024;

#ifdef __cplusplus
}
#endif

#endif /* PQC_MLKEM_PARAMS_H */
