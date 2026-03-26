/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * R .Call interface for libpqc.
 */

#include <R.h>
#include <Rinternals.h>
#include <stdlib.h>
#include <string.h>
#include <pqc/pqc.h>

/* -------------------------------------------------------------------------- */
/* Helpers                                                                     */
/* -------------------------------------------------------------------------- */

static void kem_finalizer(SEXP ptr) {
    PQC_KEM *kem = (PQC_KEM *)R_ExternalPtrAddr(ptr);
    if (kem) {
        pqc_kem_free(kem);
        R_ClearExternalPtr(ptr);
    }
}

static void sig_finalizer(SEXP ptr) {
    PQC_SIG *sig = (PQC_SIG *)R_ExternalPtrAddr(ptr);
    if (sig) {
        pqc_sig_free(sig);
        R_ClearExternalPtr(ptr);
    }
}

/* -------------------------------------------------------------------------- */
/* Version / algorithm listing                                                 */
/* -------------------------------------------------------------------------- */

SEXP C_pqc_version(void) {
    return Rf_mkString(pqc_version());
}

SEXP C_pqc_kem_algorithms(void) {
    int count = pqc_kem_algorithm_count();
    SEXP result = PROTECT(Rf_allocVector(STRSXP, count));
    for (int i = 0; i < count; i++) {
        SET_STRING_ELT(result, i, Rf_mkChar(pqc_kem_algorithm_name(i)));
    }
    UNPROTECT(1);
    return result;
}

SEXP C_pqc_sig_algorithms(void) {
    int count = pqc_sig_algorithm_count();
    SEXP result = PROTECT(Rf_allocVector(STRSXP, count));
    for (int i = 0; i < count; i++) {
        SET_STRING_ELT(result, i, Rf_mkChar(pqc_sig_algorithm_name(i)));
    }
    UNPROTECT(1);
    return result;
}

/* -------------------------------------------------------------------------- */
/* KEM                                                                         */
/* -------------------------------------------------------------------------- */

SEXP C_kem_new(SEXP algorithm) {
    const char *alg = CHAR(STRING_ELT(algorithm, 0));
    PQC_KEM *kem = pqc_kem_new(alg);
    if (!kem) {
        Rf_error("Unsupported KEM algorithm: %s", alg);
    }
    SEXP ptr = PROTECT(R_MakeExternalPtr(kem, R_NilValue, R_NilValue));
    R_RegisterCFinalizerEx(ptr, kem_finalizer, TRUE);
    UNPROTECT(1);
    return ptr;
}

SEXP C_kem_keygen(SEXP kem_ptr) {
    PQC_KEM *kem = (PQC_KEM *)R_ExternalPtrAddr(kem_ptr);
    if (!kem) Rf_error("Invalid KEM handle");

    size_t pk_size = pqc_kem_public_key_size(kem);
    size_t sk_size = pqc_kem_secret_key_size(kem);

    SEXP pk = PROTECT(Rf_allocVector(RAWSXP, pk_size));
    SEXP sk = PROTECT(Rf_allocVector(RAWSXP, sk_size));

    pqc_status_t rc = pqc_kem_keygen(kem, RAW(pk), RAW(sk));
    if (rc != PQC_OK) {
        UNPROTECT(2);
        Rf_error("KEM keygen failed: %s", pqc_status_string(rc));
    }

    SEXP result = PROTECT(Rf_allocVector(VECSXP, 2));
    SEXP names = PROTECT(Rf_allocVector(STRSXP, 2));
    SET_STRING_ELT(names, 0, Rf_mkChar("public_key"));
    SET_STRING_ELT(names, 1, Rf_mkChar("secret_key"));
    Rf_setAttrib(result, R_NamesSymbol, names);
    SET_VECTOR_ELT(result, 0, pk);
    SET_VECTOR_ELT(result, 1, sk);

    UNPROTECT(4);
    return result;
}

SEXP C_kem_encaps(SEXP kem_ptr, SEXP public_key) {
    PQC_KEM *kem = (PQC_KEM *)R_ExternalPtrAddr(kem_ptr);
    if (!kem) Rf_error("Invalid KEM handle");

    size_t ct_size = pqc_kem_ciphertext_size(kem);
    size_t ss_size = pqc_kem_shared_secret_size(kem);

    SEXP ct = PROTECT(Rf_allocVector(RAWSXP, ct_size));
    SEXP ss = PROTECT(Rf_allocVector(RAWSXP, ss_size));

    pqc_status_t rc = pqc_kem_encaps(kem, RAW(ct), RAW(ss), RAW(public_key));
    if (rc != PQC_OK) {
        UNPROTECT(2);
        Rf_error("KEM encaps failed: %s", pqc_status_string(rc));
    }

    SEXP result = PROTECT(Rf_allocVector(VECSXP, 2));
    SEXP names = PROTECT(Rf_allocVector(STRSXP, 2));
    SET_STRING_ELT(names, 0, Rf_mkChar("ciphertext"));
    SET_STRING_ELT(names, 1, Rf_mkChar("shared_secret"));
    Rf_setAttrib(result, R_NamesSymbol, names);
    SET_VECTOR_ELT(result, 0, ct);
    SET_VECTOR_ELT(result, 1, ss);

    UNPROTECT(4);
    return result;
}

SEXP C_kem_decaps(SEXP kem_ptr, SEXP ciphertext, SEXP secret_key) {
    PQC_KEM *kem = (PQC_KEM *)R_ExternalPtrAddr(kem_ptr);
    if (!kem) Rf_error("Invalid KEM handle");

    size_t ss_size = pqc_kem_shared_secret_size(kem);
    SEXP ss = PROTECT(Rf_allocVector(RAWSXP, ss_size));

    pqc_status_t rc = pqc_kem_decaps(kem, RAW(ss), RAW(ciphertext), RAW(secret_key));
    if (rc != PQC_OK) {
        UNPROTECT(1);
        Rf_error("KEM decaps failed: %s", pqc_status_string(rc));
    }

    UNPROTECT(1);
    return ss;
}

/* -------------------------------------------------------------------------- */
/* Signature                                                                   */
/* -------------------------------------------------------------------------- */

SEXP C_sig_new(SEXP algorithm) {
    const char *alg = CHAR(STRING_ELT(algorithm, 0));
    PQC_SIG *sig = pqc_sig_new(alg);
    if (!sig) {
        Rf_error("Unsupported signature algorithm: %s", alg);
    }
    SEXP ptr = PROTECT(R_MakeExternalPtr(sig, R_NilValue, R_NilValue));
    R_RegisterCFinalizerEx(ptr, sig_finalizer, TRUE);
    UNPROTECT(1);
    return ptr;
}

SEXP C_sig_keygen(SEXP sig_ptr) {
    PQC_SIG *sig = (PQC_SIG *)R_ExternalPtrAddr(sig_ptr);
    if (!sig) Rf_error("Invalid signature handle");

    size_t pk_size = pqc_sig_public_key_size(sig);
    size_t sk_size = pqc_sig_secret_key_size(sig);

    SEXP pk = PROTECT(Rf_allocVector(RAWSXP, pk_size));
    SEXP sk = PROTECT(Rf_allocVector(RAWSXP, sk_size));

    pqc_status_t rc = pqc_sig_keygen(sig, RAW(pk), RAW(sk));
    if (rc != PQC_OK) {
        UNPROTECT(2);
        Rf_error("Signature keygen failed: %s", pqc_status_string(rc));
    }

    SEXP result = PROTECT(Rf_allocVector(VECSXP, 2));
    SEXP names = PROTECT(Rf_allocVector(STRSXP, 2));
    SET_STRING_ELT(names, 0, Rf_mkChar("public_key"));
    SET_STRING_ELT(names, 1, Rf_mkChar("secret_key"));
    Rf_setAttrib(result, R_NamesSymbol, names);
    SET_VECTOR_ELT(result, 0, pk);
    SET_VECTOR_ELT(result, 1, sk);

    UNPROTECT(4);
    return result;
}

SEXP C_sig_sign(SEXP sig_ptr, SEXP message, SEXP secret_key) {
    PQC_SIG *sig = (PQC_SIG *)R_ExternalPtrAddr(sig_ptr);
    if (!sig) Rf_error("Invalid signature handle");

    size_t max_sig_size = pqc_sig_max_signature_size(sig);
    uint8_t *sig_buf = (uint8_t *)R_alloc(max_sig_size, 1);
    size_t sig_len = max_sig_size;

    pqc_status_t rc = pqc_sig_sign(sig, sig_buf, &sig_len,
                                    RAW(message), Rf_length(message),
                                    RAW(secret_key));
    if (rc != PQC_OK) {
        Rf_error("Signature sign failed: %s", pqc_status_string(rc));
    }

    SEXP result = PROTECT(Rf_allocVector(RAWSXP, sig_len));
    memcpy(RAW(result), sig_buf, sig_len);
    UNPROTECT(1);
    return result;
}

SEXP C_sig_verify(SEXP sig_ptr, SEXP message, SEXP signature, SEXP public_key) {
    PQC_SIG *sig = (PQC_SIG *)R_ExternalPtrAddr(sig_ptr);
    if (!sig) Rf_error("Invalid signature handle");

    pqc_status_t rc = pqc_sig_verify(sig,
                                      RAW(message), Rf_length(message),
                                      RAW(signature), Rf_length(signature),
                                      RAW(public_key));

    return Rf_ScalarLogical(rc == PQC_OK);
}
