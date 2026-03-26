/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * UOV (Unbalanced Oil and Vinegar) parameter definitions.
 *
 * Classic UOV over GF(256).  n = v + o, m = o.
 */

#ifndef PQC_UOV_PARAMS_H
#define PQC_UOV_PARAMS_H

#define PQC_UOV_Q   256

/* ------------------------------------------------------------------ */
/* UOV-Is: (v,o,q) = (112,44,256), Level 1                             */
/* n = 156, m = 44                                                      */
/* ------------------------------------------------------------------ */

#define PQC_UOV_IS_N                   156
#define PQC_UOV_IS_V                   112
#define PQC_UOV_IS_O                   44
#define PQC_UOV_IS_PUBLICKEYBYTES      278432
#define PQC_UOV_IS_SECRETKEYBYTES      237896
#define PQC_UOV_IS_SIGBYTES            96

/* ------------------------------------------------------------------ */
/* UOV-IIIs: (v,o,q) = (160,64,256), Level 3                           */
/* n = 224, m = 64                                                      */
/* ------------------------------------------------------------------ */

#define PQC_UOV_IIIS_N                 224
#define PQC_UOV_IIIS_V                 160
#define PQC_UOV_IIIS_O                 64
#define PQC_UOV_IIIS_PUBLICKEYBYTES    1225440
#define PQC_UOV_IIIS_SECRETKEYBYTES    1044320
#define PQC_UOV_IIIS_SIGBYTES          200

/* ------------------------------------------------------------------ */
/* UOV-Vs: (v,o,q) = (184,72,256), Level 5                             */
/* n = 256, m = 72                                                      */
/* ------------------------------------------------------------------ */

#define PQC_UOV_VS_N                   256
#define PQC_UOV_VS_V                   184
#define PQC_UOV_VS_O                   72
#define PQC_UOV_VS_PUBLICKEYBYTES      2869440
#define PQC_UOV_VS_SECRETKEYBYTES      2436704
#define PQC_UOV_VS_SIGBYTES            260

/* ------------------------------------------------------------------ */
/* Maximums for static allocation                                       */
/* ------------------------------------------------------------------ */

#define PQC_UOV_MAX_N  256
#define PQC_UOV_MAX_V  184
#define PQC_UOV_MAX_O  72

#endif /* PQC_UOV_PARAMS_H */
