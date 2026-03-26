/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * R routine registration.
 */

#include <R.h>
#include <Rinternals.h>
#include <R_ext/Rdynload.h>
#include <pqc/pqc.h>

/* Declarations from pqc_r.c */
extern SEXP C_pqc_version(void);
extern SEXP C_pqc_kem_algorithms(void);
extern SEXP C_pqc_sig_algorithms(void);
extern SEXP C_kem_new(SEXP algorithm);
extern SEXP C_kem_keygen(SEXP kem_ptr);
extern SEXP C_kem_encaps(SEXP kem_ptr, SEXP public_key);
extern SEXP C_kem_decaps(SEXP kem_ptr, SEXP ciphertext, SEXP secret_key);
extern SEXP C_sig_new(SEXP algorithm);
extern SEXP C_sig_keygen(SEXP sig_ptr);
extern SEXP C_sig_sign(SEXP sig_ptr, SEXP message, SEXP secret_key);
extern SEXP C_sig_verify(SEXP sig_ptr, SEXP message, SEXP signature, SEXP public_key);

static const R_CallMethodDef CallEntries[] = {
    {"C_pqc_version",        (DL_FUNC) &C_pqc_version,        0},
    {"C_pqc_kem_algorithms", (DL_FUNC) &C_pqc_kem_algorithms, 0},
    {"C_pqc_sig_algorithms", (DL_FUNC) &C_pqc_sig_algorithms, 0},
    {"C_kem_new",            (DL_FUNC) &C_kem_new,             1},
    {"C_kem_keygen",         (DL_FUNC) &C_kem_keygen,          1},
    {"C_kem_encaps",         (DL_FUNC) &C_kem_encaps,          2},
    {"C_kem_decaps",         (DL_FUNC) &C_kem_decaps,          3},
    {"C_sig_new",            (DL_FUNC) &C_sig_new,             1},
    {"C_sig_keygen",         (DL_FUNC) &C_sig_keygen,          1},
    {"C_sig_sign",           (DL_FUNC) &C_sig_sign,            3},
    {"C_sig_verify",         (DL_FUNC) &C_sig_verify,          4},
    {NULL, NULL, 0}
};

void R_init_pqcDyber(DllInfo *dll) {
    R_registerRoutines(dll, NULL, CallEntries, NULL, NULL);
    R_useDynamicSymbols(dll, FALSE);

    /* Initialize the PQC library */
    pqc_init();
}
