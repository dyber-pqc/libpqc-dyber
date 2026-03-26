/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Perl XS bindings for libpqc.
 */

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <pqc/pqc.h>

MODULE = Crypt::PQC::Dyber    PACKAGE = Crypt::PQC::Dyber

PROTOTYPES: DISABLE

int
_pqc_init()
    CODE:
        RETVAL = (pqc_init() == PQC_OK) ? 1 : 0;
    OUTPUT:
        RETVAL

const char *
_pqc_version()
    CODE:
        RETVAL = pqc_version();
    OUTPUT:
        RETVAL

int
_pqc_kem_algorithm_count()
    CODE:
        RETVAL = pqc_kem_algorithm_count();
    OUTPUT:
        RETVAL

const char *
_pqc_kem_algorithm_name(index)
        int index
    CODE:
        RETVAL = pqc_kem_algorithm_name(index);
    OUTPUT:
        RETVAL

int
_pqc_sig_algorithm_count()
    CODE:
        RETVAL = pqc_sig_algorithm_count();
    OUTPUT:
        RETVAL

const char *
_pqc_sig_algorithm_name(index)
        int index
    CODE:
        RETVAL = pqc_sig_algorithm_name(index);
    OUTPUT:
        RETVAL

void *
_kem_new(algorithm)
        const char *algorithm
    CODE:
        RETVAL = pqc_kem_new(algorithm);
    OUTPUT:
        RETVAL

void
_kem_free(handle)
        void *handle
    CODE:
        pqc_kem_free((PQC_KEM *)handle);

size_t
_kem_public_key_size(handle)
        void *handle
    CODE:
        RETVAL = pqc_kem_public_key_size((PQC_KEM *)handle);
    OUTPUT:
        RETVAL

size_t
_kem_secret_key_size(handle)
        void *handle
    CODE:
        RETVAL = pqc_kem_secret_key_size((PQC_KEM *)handle);
    OUTPUT:
        RETVAL

size_t
_kem_ciphertext_size(handle)
        void *handle
    CODE:
        RETVAL = pqc_kem_ciphertext_size((PQC_KEM *)handle);
    OUTPUT:
        RETVAL

size_t
_kem_shared_secret_size(handle)
        void *handle
    CODE:
        RETVAL = pqc_kem_shared_secret_size((PQC_KEM *)handle);
    OUTPUT:
        RETVAL

void
_kem_keygen(handle)
        void *handle
    PPCODE:
    {
        PQC_KEM *kem = (PQC_KEM *)handle;
        size_t pk_size = pqc_kem_public_key_size(kem);
        size_t sk_size = pqc_kem_secret_key_size(kem);
        uint8_t *pk = (uint8_t *)malloc(pk_size);
        uint8_t *sk = (uint8_t *)malloc(sk_size);

        pqc_status_t rc = pqc_kem_keygen(kem, pk, sk);
        if (rc != PQC_OK) {
            free(pk); free(sk);
            croak("KEM keygen failed: %s", pqc_status_string(rc));
        }

        EXTEND(SP, 2);
        PUSHs(sv_2mortal(newSVpvn((const char *)pk, pk_size)));
        PUSHs(sv_2mortal(newSVpvn((const char *)sk, sk_size)));
        free(pk); free(sk);
    }

void
_kem_encaps(handle, public_key)
        void *handle
        SV *public_key
    PPCODE:
    {
        PQC_KEM *kem = (PQC_KEM *)handle;
        STRLEN pk_len;
        const uint8_t *pk = (const uint8_t *)SvPVbyte(public_key, pk_len);

        size_t ct_size = pqc_kem_ciphertext_size(kem);
        size_t ss_size = pqc_kem_shared_secret_size(kem);
        uint8_t *ct = (uint8_t *)malloc(ct_size);
        uint8_t *ss = (uint8_t *)malloc(ss_size);

        pqc_status_t rc = pqc_kem_encaps(kem, ct, ss, pk);
        if (rc != PQC_OK) {
            free(ct); free(ss);
            croak("KEM encaps failed: %s", pqc_status_string(rc));
        }

        EXTEND(SP, 2);
        PUSHs(sv_2mortal(newSVpvn((const char *)ct, ct_size)));
        PUSHs(sv_2mortal(newSVpvn((const char *)ss, ss_size)));
        free(ct); free(ss);
    }

SV *
_kem_decaps(handle, ciphertext, secret_key)
        void *handle
        SV *ciphertext
        SV *secret_key
    CODE:
    {
        PQC_KEM *kem = (PQC_KEM *)handle;
        STRLEN ct_len, sk_len;
        const uint8_t *ct = (const uint8_t *)SvPVbyte(ciphertext, ct_len);
        const uint8_t *sk = (const uint8_t *)SvPVbyte(secret_key, sk_len);

        size_t ss_size = pqc_kem_shared_secret_size(kem);
        uint8_t *ss = (uint8_t *)malloc(ss_size);

        pqc_status_t rc = pqc_kem_decaps(kem, ss, ct, sk);
        if (rc != PQC_OK) {
            free(ss);
            croak("KEM decaps failed: %s", pqc_status_string(rc));
        }

        RETVAL = newSVpvn((const char *)ss, ss_size);
        free(ss);
    }
    OUTPUT:
        RETVAL

void *
_sig_new(algorithm)
        const char *algorithm
    CODE:
        RETVAL = pqc_sig_new(algorithm);
    OUTPUT:
        RETVAL

void
_sig_free(handle)
        void *handle
    CODE:
        pqc_sig_free((PQC_SIG *)handle);

size_t
_sig_public_key_size(handle)
        void *handle
    CODE:
        RETVAL = pqc_sig_public_key_size((PQC_SIG *)handle);
    OUTPUT:
        RETVAL

size_t
_sig_secret_key_size(handle)
        void *handle
    CODE:
        RETVAL = pqc_sig_secret_key_size((PQC_SIG *)handle);
    OUTPUT:
        RETVAL

size_t
_sig_max_signature_size(handle)
        void *handle
    CODE:
        RETVAL = pqc_sig_max_signature_size((PQC_SIG *)handle);
    OUTPUT:
        RETVAL

void
_sig_keygen(handle)
        void *handle
    PPCODE:
    {
        PQC_SIG *sig = (PQC_SIG *)handle;
        size_t pk_size = pqc_sig_public_key_size(sig);
        size_t sk_size = pqc_sig_secret_key_size(sig);
        uint8_t *pk = (uint8_t *)malloc(pk_size);
        uint8_t *sk = (uint8_t *)malloc(sk_size);

        pqc_status_t rc = pqc_sig_keygen(sig, pk, sk);
        if (rc != PQC_OK) {
            free(pk); free(sk);
            croak("Signature keygen failed: %s", pqc_status_string(rc));
        }

        EXTEND(SP, 2);
        PUSHs(sv_2mortal(newSVpvn((const char *)pk, pk_size)));
        PUSHs(sv_2mortal(newSVpvn((const char *)sk, sk_size)));
        free(pk); free(sk);
    }

SV *
_sig_sign(handle, message, secret_key)
        void *handle
        SV *message
        SV *secret_key
    CODE:
    {
        PQC_SIG *sig = (PQC_SIG *)handle;
        STRLEN msg_len, sk_len;
        const uint8_t *msg = (const uint8_t *)SvPVbyte(message, msg_len);
        const uint8_t *sk = (const uint8_t *)SvPVbyte(secret_key, sk_len);

        size_t max_sig_size = pqc_sig_max_signature_size(sig);
        uint8_t *sig_buf = (uint8_t *)malloc(max_sig_size);
        size_t sig_len = max_sig_size;

        pqc_status_t rc = pqc_sig_sign(sig, sig_buf, &sig_len, msg, msg_len, sk);
        if (rc != PQC_OK) {
            free(sig_buf);
            croak("Signature sign failed: %s", pqc_status_string(rc));
        }

        RETVAL = newSVpvn((const char *)sig_buf, sig_len);
        free(sig_buf);
    }
    OUTPUT:
        RETVAL

int
_sig_verify(handle, message, signature, public_key)
        void *handle
        SV *message
        SV *signature
        SV *public_key
    CODE:
    {
        PQC_SIG *sig = (PQC_SIG *)handle;
        STRLEN msg_len, sig_len, pk_len;
        const uint8_t *msg = (const uint8_t *)SvPVbyte(message, msg_len);
        const uint8_t *sig_data = (const uint8_t *)SvPVbyte(signature, sig_len);
        const uint8_t *pk = (const uint8_t *)SvPVbyte(public_key, pk_len);

        pqc_status_t rc = pqc_sig_verify(sig, msg, msg_len, sig_data, sig_len, pk);
        RETVAL = (rc == PQC_OK) ? 1 : 0;
    }
    OUTPUT:
        RETVAL
