/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * MATLAB MEX gateway for libpqc.
 */

#include "mex.h"
#include <string.h>
#include <pqc/pqc.h>

static int initialized = 0;

static void ensure_init(void) {
    if (!initialized) {
        pqc_init();
        initialized = 1;
    }
}

static char *get_string(const mxArray *arg) {
    if (!mxIsChar(arg)) mexErrMsgIdAndTxt("pqc:type", "Expected a string argument");
    return mxArrayToString(arg);
}

static uint64_t get_handle(const mxArray *arg) {
    if (!mxIsUint64(arg)) mexErrMsgIdAndTxt("pqc:type", "Expected a uint64 handle");
    return *((uint64_t *)mxGetData(arg));
}

static mxArray *make_uint8(const uint8_t *data, size_t len) {
    mxArray *arr = mxCreateNumericMatrix(len, 1, mxUINT8_CLASS, mxREAL);
    memcpy(mxGetData(arr), data, len);
    return arr;
}

static mxArray *make_handle(void *ptr) {
    mxArray *arr = mxCreateNumericMatrix(1, 1, mxUINT64_CLASS, mxREAL);
    *((uint64_t *)mxGetData(arr)) = (uint64_t)(uintptr_t)ptr;
    return arr;
}

void mexFunction(int nlhs, mxArray *plhs[], int nrhs, const mxArray *prhs[]) {
    ensure_init();

    if (nrhs < 1 || !mxIsChar(prhs[0]))
        mexErrMsgIdAndTxt("pqc:args", "First argument must be a command string");

    char *cmd = mxArrayToString(prhs[0]);

    /* ------------------------------------------------------------------ */
    /* Version                                                             */
    /* ------------------------------------------------------------------ */
    if (strcmp(cmd, "version") == 0) {
        plhs[0] = mxCreateString(pqc_version());
    }
    /* ------------------------------------------------------------------ */
    /* KEM                                                                 */
    /* ------------------------------------------------------------------ */
    else if (strcmp(cmd, "kem_new") == 0) {
        char *alg = get_string(prhs[1]);
        PQC_KEM *kem = pqc_kem_new(alg);
        mxFree(alg);
        plhs[0] = make_handle(kem);
    }
    else if (strcmp(cmd, "kem_free") == 0) {
        PQC_KEM *kem = (PQC_KEM *)(uintptr_t)get_handle(prhs[1]);
        if (kem) pqc_kem_free(kem);
    }
    else if (strcmp(cmd, "kem_public_key_size") == 0) {
        PQC_KEM *kem = (PQC_KEM *)(uintptr_t)get_handle(prhs[1]);
        plhs[0] = mxCreateDoubleScalar((double)pqc_kem_public_key_size(kem));
    }
    else if (strcmp(cmd, "kem_secret_key_size") == 0) {
        PQC_KEM *kem = (PQC_KEM *)(uintptr_t)get_handle(prhs[1]);
        plhs[0] = mxCreateDoubleScalar((double)pqc_kem_secret_key_size(kem));
    }
    else if (strcmp(cmd, "kem_ciphertext_size") == 0) {
        PQC_KEM *kem = (PQC_KEM *)(uintptr_t)get_handle(prhs[1]);
        plhs[0] = mxCreateDoubleScalar((double)pqc_kem_ciphertext_size(kem));
    }
    else if (strcmp(cmd, "kem_shared_secret_size") == 0) {
        PQC_KEM *kem = (PQC_KEM *)(uintptr_t)get_handle(prhs[1]);
        plhs[0] = mxCreateDoubleScalar((double)pqc_kem_shared_secret_size(kem));
    }
    else if (strcmp(cmd, "kem_security_level") == 0) {
        PQC_KEM *kem = (PQC_KEM *)(uintptr_t)get_handle(prhs[1]);
        plhs[0] = mxCreateDoubleScalar((double)pqc_kem_security_level(kem));
    }
    else if (strcmp(cmd, "kem_keygen") == 0) {
        PQC_KEM *kem = (PQC_KEM *)(uintptr_t)get_handle(prhs[1]);
        size_t pk_size = pqc_kem_public_key_size(kem);
        size_t sk_size = pqc_kem_secret_key_size(kem);
        uint8_t *pk = mxMalloc(pk_size);
        uint8_t *sk = mxMalloc(sk_size);

        pqc_status_t rc = pqc_kem_keygen(kem, pk, sk);
        if (rc != PQC_OK) {
            mxFree(pk); mxFree(sk);
            mexErrMsgIdAndTxt("pqc:keygen", "KEM keygen failed: %s", pqc_status_string(rc));
        }

        plhs[0] = make_uint8(pk, pk_size);
        if (nlhs > 1) plhs[1] = make_uint8(sk, sk_size);
        mxFree(pk); mxFree(sk);
    }
    else if (strcmp(cmd, "kem_encaps") == 0) {
        PQC_KEM *kem = (PQC_KEM *)(uintptr_t)get_handle(prhs[1]);
        const uint8_t *pk = (const uint8_t *)mxGetData(prhs[2]);

        size_t ct_size = pqc_kem_ciphertext_size(kem);
        size_t ss_size = pqc_kem_shared_secret_size(kem);
        uint8_t *ct = mxMalloc(ct_size);
        uint8_t *ss = mxMalloc(ss_size);

        pqc_status_t rc = pqc_kem_encaps(kem, ct, ss, pk);
        if (rc != PQC_OK) {
            mxFree(ct); mxFree(ss);
            mexErrMsgIdAndTxt("pqc:encaps", "KEM encaps failed: %s", pqc_status_string(rc));
        }

        plhs[0] = make_uint8(ct, ct_size);
        if (nlhs > 1) plhs[1] = make_uint8(ss, ss_size);
        mxFree(ct); mxFree(ss);
    }
    else if (strcmp(cmd, "kem_decaps") == 0) {
        PQC_KEM *kem = (PQC_KEM *)(uintptr_t)get_handle(prhs[1]);
        const uint8_t *ct = (const uint8_t *)mxGetData(prhs[2]);
        const uint8_t *sk = (const uint8_t *)mxGetData(prhs[3]);

        size_t ss_size = pqc_kem_shared_secret_size(kem);
        uint8_t *ss = mxMalloc(ss_size);

        pqc_status_t rc = pqc_kem_decaps(kem, ss, ct, sk);
        if (rc != PQC_OK) {
            mxFree(ss);
            mexErrMsgIdAndTxt("pqc:decaps", "KEM decaps failed: %s", pqc_status_string(rc));
        }

        plhs[0] = make_uint8(ss, ss_size);
        mxFree(ss);
    }
    /* ------------------------------------------------------------------ */
    /* Signature                                                           */
    /* ------------------------------------------------------------------ */
    else if (strcmp(cmd, "sig_new") == 0) {
        char *alg = get_string(prhs[1]);
        PQC_SIG *sig = pqc_sig_new(alg);
        mxFree(alg);
        plhs[0] = make_handle(sig);
    }
    else if (strcmp(cmd, "sig_free") == 0) {
        PQC_SIG *sig = (PQC_SIG *)(uintptr_t)get_handle(prhs[1]);
        if (sig) pqc_sig_free(sig);
    }
    else if (strcmp(cmd, "sig_public_key_size") == 0) {
        PQC_SIG *sig = (PQC_SIG *)(uintptr_t)get_handle(prhs[1]);
        plhs[0] = mxCreateDoubleScalar((double)pqc_sig_public_key_size(sig));
    }
    else if (strcmp(cmd, "sig_secret_key_size") == 0) {
        PQC_SIG *sig = (PQC_SIG *)(uintptr_t)get_handle(prhs[1]);
        plhs[0] = mxCreateDoubleScalar((double)pqc_sig_secret_key_size(sig));
    }
    else if (strcmp(cmd, "sig_max_signature_size") == 0) {
        PQC_SIG *sig = (PQC_SIG *)(uintptr_t)get_handle(prhs[1]);
        plhs[0] = mxCreateDoubleScalar((double)pqc_sig_max_signature_size(sig));
    }
    else if (strcmp(cmd, "sig_security_level") == 0) {
        PQC_SIG *sig = (PQC_SIG *)(uintptr_t)get_handle(prhs[1]);
        plhs[0] = mxCreateDoubleScalar((double)pqc_sig_security_level(sig));
    }
    else if (strcmp(cmd, "sig_is_stateful") == 0) {
        PQC_SIG *sig = (PQC_SIG *)(uintptr_t)get_handle(prhs[1]);
        plhs[0] = mxCreateLogicalScalar(pqc_sig_is_stateful(sig) != 0);
    }
    else if (strcmp(cmd, "sig_keygen") == 0) {
        PQC_SIG *sig = (PQC_SIG *)(uintptr_t)get_handle(prhs[1]);
        size_t pk_size = pqc_sig_public_key_size(sig);
        size_t sk_size = pqc_sig_secret_key_size(sig);
        uint8_t *pk = mxMalloc(pk_size);
        uint8_t *sk = mxMalloc(sk_size);

        pqc_status_t rc = pqc_sig_keygen(sig, pk, sk);
        if (rc != PQC_OK) {
            mxFree(pk); mxFree(sk);
            mexErrMsgIdAndTxt("pqc:keygen", "Signature keygen failed: %s", pqc_status_string(rc));
        }

        plhs[0] = make_uint8(pk, pk_size);
        if (nlhs > 1) plhs[1] = make_uint8(sk, sk_size);
        mxFree(pk); mxFree(sk);
    }
    else if (strcmp(cmd, "sig_sign") == 0) {
        PQC_SIG *sig = (PQC_SIG *)(uintptr_t)get_handle(prhs[1]);
        const uint8_t *msg = (const uint8_t *)mxGetData(prhs[2]);
        size_t msg_len = mxGetNumberOfElements(prhs[2]);
        const uint8_t *sk = (const uint8_t *)mxGetData(prhs[3]);

        size_t max_sig_size = pqc_sig_max_signature_size(sig);
        uint8_t *sig_buf = mxMalloc(max_sig_size);
        size_t sig_len = max_sig_size;

        pqc_status_t rc = pqc_sig_sign(sig, sig_buf, &sig_len, msg, msg_len, sk);
        if (rc != PQC_OK) {
            mxFree(sig_buf);
            mexErrMsgIdAndTxt("pqc:sign", "Signature sign failed: %s", pqc_status_string(rc));
        }

        plhs[0] = make_uint8(sig_buf, sig_len);
        mxFree(sig_buf);
    }
    else if (strcmp(cmd, "sig_verify") == 0) {
        PQC_SIG *sig = (PQC_SIG *)(uintptr_t)get_handle(prhs[1]);
        const uint8_t *msg = (const uint8_t *)mxGetData(prhs[2]);
        size_t msg_len = mxGetNumberOfElements(prhs[2]);
        const uint8_t *sig_data = (const uint8_t *)mxGetData(prhs[3]);
        size_t sig_len = mxGetNumberOfElements(prhs[3]);
        const uint8_t *pk = (const uint8_t *)mxGetData(prhs[4]);

        pqc_status_t rc = pqc_sig_verify(sig, msg, msg_len, sig_data, sig_len, pk);
        plhs[0] = mxCreateLogicalScalar(rc == PQC_OK);
    }
    else {
        mexErrMsgIdAndTxt("pqc:cmd", "Unknown command: %s", cmd);
    }

    mxFree(cmd);
}
