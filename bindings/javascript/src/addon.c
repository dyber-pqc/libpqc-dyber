/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Node.js N-API C addon for libpqc.
 */

#include <node_api.h>
#include <stdlib.h>
#include <string.h>
#include <pqc/pqc.h>

#define NAPI_CALL(env, call)                                    \
    do {                                                        \
        napi_status status = (call);                            \
        if (status != napi_ok) {                                \
            napi_throw_error(env, NULL, "N-API call failed");   \
            return NULL;                                        \
        }                                                       \
    } while (0)

/* -------------------------------------------------------------------------- */
/* Helper: extract string argument                                             */
/* -------------------------------------------------------------------------- */

static char *get_string_arg(napi_env env, napi_callback_info info, int index, size_t max_len) {
    size_t argc = index + 1;
    napi_value *argv = malloc(sizeof(napi_value) * argc);
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

    size_t len;
    napi_get_value_string_utf8(env, argv[index], NULL, 0, &len);
    char *buf = malloc(len + 1);
    napi_get_value_string_utf8(env, argv[index], buf, len + 1, &len);
    free(argv);
    return buf;
}

/* -------------------------------------------------------------------------- */
/* pqc_version()                                                               */
/* -------------------------------------------------------------------------- */

static napi_value js_pqc_version(napi_env env, napi_callback_info info) {
    const char *ver = pqc_version();
    napi_value result;
    napi_create_string_utf8(env, ver, NAPI_AUTO_LENGTH, &result);
    return result;
}

/* -------------------------------------------------------------------------- */
/* KEM algorithm listing                                                       */
/* -------------------------------------------------------------------------- */

static napi_value js_pqc_kem_algorithms(napi_env env, napi_callback_info info) {
    int count = pqc_kem_algorithm_count();
    napi_value arr;
    napi_create_array_with_length(env, count, &arr);
    for (int i = 0; i < count; i++) {
        const char *name = pqc_kem_algorithm_name(i);
        napi_value str;
        napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &str);
        napi_set_element(env, arr, i, str);
    }
    return arr;
}

/* -------------------------------------------------------------------------- */
/* Signature algorithm listing                                                 */
/* -------------------------------------------------------------------------- */

static napi_value js_pqc_sig_algorithms(napi_env env, napi_callback_info info) {
    int count = pqc_sig_algorithm_count();
    napi_value arr;
    napi_create_array_with_length(env, count, &arr);
    for (int i = 0; i < count; i++) {
        const char *name = pqc_sig_algorithm_name(i);
        napi_value str;
        napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &str);
        napi_set_element(env, arr, i, str);
    }
    return arr;
}

/* -------------------------------------------------------------------------- */
/* KEM keygen(algorithm) -> { publicKey, secretKey }                           */
/* -------------------------------------------------------------------------- */

static napi_value js_kem_keygen(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

    size_t len;
    napi_get_value_string_utf8(env, argv[0], NULL, 0, &len);
    char *alg = malloc(len + 1);
    napi_get_value_string_utf8(env, argv[0], alg, len + 1, &len);

    PQC_KEM *kem = pqc_kem_new(alg);
    free(alg);
    if (!kem) {
        napi_throw_error(env, NULL, "Unsupported KEM algorithm");
        return NULL;
    }

    size_t pk_size = pqc_kem_public_key_size(kem);
    size_t sk_size = pqc_kem_secret_key_size(kem);

    uint8_t *pk = malloc(pk_size);
    uint8_t *sk = malloc(sk_size);

    pqc_status_t rc = pqc_kem_keygen(kem, pk, sk);
    if (rc != PQC_OK) {
        free(pk); free(sk);
        pqc_kem_free(kem);
        napi_throw_error(env, NULL, "KEM keygen failed");
        return NULL;
    }

    napi_value result, pk_buf, sk_buf;
    void *pk_data, *sk_data;

    napi_create_buffer_copy(env, pk_size, pk, &pk_data, &pk_buf);
    napi_create_buffer_copy(env, sk_size, sk, &sk_data, &sk_buf);

    napi_create_object(env, &result);
    napi_set_named_property(env, result, "publicKey", pk_buf);
    napi_set_named_property(env, result, "secretKey", sk_buf);

    free(pk); free(sk);
    pqc_kem_free(kem);
    return result;
}

/* -------------------------------------------------------------------------- */
/* KEM encaps(algorithm, publicKey) -> { ciphertext, sharedSecret }            */
/* -------------------------------------------------------------------------- */

static napi_value js_kem_encaps(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value argv[2];
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

    size_t len;
    napi_get_value_string_utf8(env, argv[0], NULL, 0, &len);
    char *alg = malloc(len + 1);
    napi_get_value_string_utf8(env, argv[0], alg, len + 1, &len);

    PQC_KEM *kem = pqc_kem_new(alg);
    free(alg);
    if (!kem) {
        napi_throw_error(env, NULL, "Unsupported KEM algorithm");
        return NULL;
    }

    uint8_t *pk_data;
    size_t pk_len;
    napi_get_buffer_info(env, argv[1], (void **)&pk_data, &pk_len);

    size_t ct_size = pqc_kem_ciphertext_size(kem);
    size_t ss_size = pqc_kem_shared_secret_size(kem);

    uint8_t *ct = malloc(ct_size);
    uint8_t *ss = malloc(ss_size);

    pqc_status_t rc = pqc_kem_encaps(kem, ct, ss, pk_data);
    if (rc != PQC_OK) {
        free(ct); free(ss);
        pqc_kem_free(kem);
        napi_throw_error(env, NULL, "KEM encaps failed");
        return NULL;
    }

    napi_value result, ct_buf, ss_buf;
    void *ct_out, *ss_out;

    napi_create_buffer_copy(env, ct_size, ct, &ct_out, &ct_buf);
    napi_create_buffer_copy(env, ss_size, ss, &ss_out, &ss_buf);

    napi_create_object(env, &result);
    napi_set_named_property(env, result, "ciphertext", ct_buf);
    napi_set_named_property(env, result, "sharedSecret", ss_buf);

    free(ct); free(ss);
    pqc_kem_free(kem);
    return result;
}

/* -------------------------------------------------------------------------- */
/* KEM decaps(algorithm, ciphertext, secretKey) -> sharedSecret                */
/* -------------------------------------------------------------------------- */

static napi_value js_kem_decaps(napi_env env, napi_callback_info info) {
    size_t argc = 3;
    napi_value argv[3];
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

    size_t len;
    napi_get_value_string_utf8(env, argv[0], NULL, 0, &len);
    char *alg = malloc(len + 1);
    napi_get_value_string_utf8(env, argv[0], alg, len + 1, &len);

    PQC_KEM *kem = pqc_kem_new(alg);
    free(alg);
    if (!kem) {
        napi_throw_error(env, NULL, "Unsupported KEM algorithm");
        return NULL;
    }

    uint8_t *ct_data;
    size_t ct_len;
    napi_get_buffer_info(env, argv[1], (void **)&ct_data, &ct_len);

    uint8_t *sk_data;
    size_t sk_len;
    napi_get_buffer_info(env, argv[2], (void **)&sk_data, &sk_len);

    size_t ss_size = pqc_kem_shared_secret_size(kem);
    uint8_t *ss = malloc(ss_size);

    pqc_status_t rc = pqc_kem_decaps(kem, ss, ct_data, sk_data);
    if (rc != PQC_OK) {
        free(ss);
        pqc_kem_free(kem);
        napi_throw_error(env, NULL, "KEM decaps failed");
        return NULL;
    }

    napi_value ss_buf;
    void *ss_out;
    napi_create_buffer_copy(env, ss_size, ss, &ss_out, &ss_buf);

    free(ss);
    pqc_kem_free(kem);
    return ss_buf;
}

/* -------------------------------------------------------------------------- */
/* Signature keygen(algorithm) -> { publicKey, secretKey }                     */
/* -------------------------------------------------------------------------- */

static napi_value js_sig_keygen(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

    size_t len;
    napi_get_value_string_utf8(env, argv[0], NULL, 0, &len);
    char *alg = malloc(len + 1);
    napi_get_value_string_utf8(env, argv[0], alg, len + 1, &len);

    PQC_SIG *sig = pqc_sig_new(alg);
    free(alg);
    if (!sig) {
        napi_throw_error(env, NULL, "Unsupported signature algorithm");
        return NULL;
    }

    size_t pk_size = pqc_sig_public_key_size(sig);
    size_t sk_size = pqc_sig_secret_key_size(sig);

    uint8_t *pk = malloc(pk_size);
    uint8_t *sk = malloc(sk_size);

    pqc_status_t rc = pqc_sig_keygen(sig, pk, sk);
    if (rc != PQC_OK) {
        free(pk); free(sk);
        pqc_sig_free(sig);
        napi_throw_error(env, NULL, "Signature keygen failed");
        return NULL;
    }

    napi_value result, pk_buf, sk_buf;
    void *pk_out, *sk_out;

    napi_create_buffer_copy(env, pk_size, pk, &pk_out, &pk_buf);
    napi_create_buffer_copy(env, sk_size, sk, &sk_out, &sk_buf);

    napi_create_object(env, &result);
    napi_set_named_property(env, result, "publicKey", pk_buf);
    napi_set_named_property(env, result, "secretKey", sk_buf);

    free(pk); free(sk);
    pqc_sig_free(sig);
    return result;
}

/* -------------------------------------------------------------------------- */
/* Signature sign(algorithm, message, secretKey) -> signature                  */
/* -------------------------------------------------------------------------- */

static napi_value js_sig_sign(napi_env env, napi_callback_info info) {
    size_t argc = 3;
    napi_value argv[3];
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

    size_t len;
    napi_get_value_string_utf8(env, argv[0], NULL, 0, &len);
    char *alg = malloc(len + 1);
    napi_get_value_string_utf8(env, argv[0], alg, len + 1, &len);

    PQC_SIG *sig = pqc_sig_new(alg);
    free(alg);
    if (!sig) {
        napi_throw_error(env, NULL, "Unsupported signature algorithm");
        return NULL;
    }

    uint8_t *msg_data;
    size_t msg_len;
    napi_get_buffer_info(env, argv[1], (void **)&msg_data, &msg_len);

    uint8_t *sk_data;
    size_t sk_len;
    napi_get_buffer_info(env, argv[2], (void **)&sk_data, &sk_len);

    size_t max_sig_size = pqc_sig_max_signature_size(sig);
    uint8_t *sig_buf = malloc(max_sig_size);
    size_t sig_len = max_sig_size;

    pqc_status_t rc = pqc_sig_sign(sig, sig_buf, &sig_len, msg_data, msg_len, sk_data);
    if (rc != PQC_OK) {
        free(sig_buf);
        pqc_sig_free(sig);
        napi_throw_error(env, NULL, "Signature sign failed");
        return NULL;
    }

    napi_value result;
    void *out;
    napi_create_buffer_copy(env, sig_len, sig_buf, &out, &result);

    free(sig_buf);
    pqc_sig_free(sig);
    return result;
}

/* -------------------------------------------------------------------------- */
/* Signature verify(algorithm, message, signature, publicKey) -> boolean       */
/* -------------------------------------------------------------------------- */

static napi_value js_sig_verify(napi_env env, napi_callback_info info) {
    size_t argc = 4;
    napi_value argv[4];
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

    size_t len;
    napi_get_value_string_utf8(env, argv[0], NULL, 0, &len);
    char *alg = malloc(len + 1);
    napi_get_value_string_utf8(env, argv[0], alg, len + 1, &len);

    PQC_SIG *sig = pqc_sig_new(alg);
    free(alg);
    if (!sig) {
        napi_throw_error(env, NULL, "Unsupported signature algorithm");
        return NULL;
    }

    uint8_t *msg_data;
    size_t msg_len;
    napi_get_buffer_info(env, argv[1], (void **)&msg_data, &msg_len);

    uint8_t *sig_data;
    size_t sig_len;
    napi_get_buffer_info(env, argv[2], (void **)&sig_data, &sig_len);

    uint8_t *pk_data;
    size_t pk_len;
    napi_get_buffer_info(env, argv[3], (void **)&pk_data, &pk_len);

    pqc_status_t rc = pqc_sig_verify(sig, msg_data, msg_len, sig_data, sig_len, pk_data);

    napi_value result;
    napi_get_boolean(env, rc == PQC_OK, &result);

    pqc_sig_free(sig);
    return result;
}

/* -------------------------------------------------------------------------- */
/* Module initialization                                                       */
/* -------------------------------------------------------------------------- */

static napi_value Init(napi_env env, napi_value exports) {
    pqc_init();

    napi_property_descriptor props[] = {
        {"version",        NULL, js_pqc_version,       NULL, NULL, NULL, napi_default, NULL},
        {"kemAlgorithms",  NULL, js_pqc_kem_algorithms, NULL, NULL, NULL, napi_default, NULL},
        {"sigAlgorithms",  NULL, js_pqc_sig_algorithms, NULL, NULL, NULL, napi_default, NULL},
        {"kemKeygen",      NULL, js_kem_keygen,         NULL, NULL, NULL, napi_default, NULL},
        {"kemEncaps",      NULL, js_kem_encaps,         NULL, NULL, NULL, napi_default, NULL},
        {"kemDecaps",      NULL, js_kem_decaps,         NULL, NULL, NULL, napi_default, NULL},
        {"sigKeygen",      NULL, js_sig_keygen,         NULL, NULL, NULL, napi_default, NULL},
        {"sigSign",        NULL, js_sig_sign,           NULL, NULL, NULL, napi_default, NULL},
        {"sigVerify",      NULL, js_sig_verify,         NULL, NULL, NULL, napi_default, NULL},
    };

    napi_define_properties(env, exports, sizeof(props) / sizeof(props[0]), props);
    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
