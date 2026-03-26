/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * TLS Integration — TLS 1.2 Compatibility Layer
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Provides limited PQC support for TLS 1.2 via custom extensions.
 * Only hybrid key exchange modes are practical in TLS 1.2; pure PQC
 * key exchange requires TLS 1.3.
 *
 * Wire format for the custom hybrid extension:
 *
 *   Extension type:  0xFF01 (private-use range)
 *
 *   ClientHello extension data:
 *     uint16  group_id
 *     uint16  key_share_length
 *     opaque  key_share[key_share_length]
 *
 *   ServerHello extension data:
 *     uint16  group_id
 *     uint16  key_share_length
 *     opaque  key_share[key_share_length]
 *
 * The shared secret derived from the hybrid exchange is mixed into
 * the TLS 1.2 master secret via the extended_master_secret mechanism
 * or a custom PRF label.
 */

#include "pqc_tls.h"
#include "pqc_tls_internal.h"

#include <pqc/common.h>
#include <string.h>
#include <stdlib.h>

/* -------------------------------------------------------------------------- */
/* Constants                                                                   */
/* -------------------------------------------------------------------------- */

/* Private-use TLS extension type for hybrid PQC key exchange */
#define PQC_TLS12_EXTENSION_TYPE    0xFF01

/* Supported hybrid groups for TLS 1.2 */
static const uint16_t tls12_hybrid_groups[] = {
    PQC_TLS_GROUP_X25519_MLKEM768,
    PQC_TLS_GROUP_SECP256R1_MLKEM768,
};
static const size_t tls12_hybrid_group_count =
    sizeof(tls12_hybrid_groups) / sizeof(tls12_hybrid_groups[0]);

/* -------------------------------------------------------------------------- */
/* Extension data builders                                                     */
/* -------------------------------------------------------------------------- */

/*
 * Build the ClientHello extension payload for a hybrid PQC key exchange.
 *
 *   group_id     - the hybrid group to use
 *   out          - output buffer (must be pre-allocated)
 *   out_len      - on input: buffer size; on output: bytes written
 *   ks_out       - receives the key-share context for later decapsulation
 *
 * Returns 0 on success, -1 on failure.
 */
int pqc_tls12_build_client_extension(
        uint16_t group_id,
        uint8_t *out, size_t *out_len,
        PQC_TLS_KeyShare **ks_out)
{
    if (!out || !out_len || !ks_out)
        return -1;

    /* Verify it is a supported hybrid group */
    int found = 0;
    for (size_t i = 0; i < tls12_hybrid_group_count; i++) {
        if (tls12_hybrid_groups[i] == group_id) {
            found = 1;
            break;
        }
    }
    if (!found)
        return -1;

    PQC_TLS_KeyShare *ks = pqc_tls_keyshare_new(group_id);
    if (!ks)
        return -1;

    /* Reserve header space: 2 (group_id) + 2 (length) */
    size_t header_sz = 4;
    size_t share_buf_sz = *out_len > header_sz ? *out_len - header_sz : 0;
    uint8_t *share_buf = out + header_sz;

    if (pqc_tls_keyshare_generate(ks, share_buf, &share_buf_sz) != 0) {
        pqc_tls_keyshare_free(ks);
        return -1;
    }

    /* Write header */
    out[0] = (uint8_t)(group_id >> 8);
    out[1] = (uint8_t)(group_id & 0xFF);
    out[2] = (uint8_t)(share_buf_sz >> 8);
    out[3] = (uint8_t)(share_buf_sz & 0xFF);

    *out_len = header_sz + share_buf_sz;
    *ks_out = ks;
    return 0;
}

/*
 * Parse a ClientHello hybrid extension, perform encapsulation, and
 * build the ServerHello extension response.
 *
 *   ext_data          - the client extension payload
 *   ext_data_len      - length of ext_data
 *   response          - output buffer for server extension
 *   response_len      - on input: buffer size; on output: bytes written
 *   shared_secret_out - output buffer for shared secret
 *   shared_secret_len - on input: buffer size; on output: bytes written
 *
 * Returns 0 on success, -1 on failure.
 */
int pqc_tls12_process_client_extension(
        const uint8_t *ext_data, size_t ext_data_len,
        uint8_t *response, size_t *response_len,
        uint8_t *shared_secret_out, size_t *shared_secret_len)
{
    if (!ext_data || ext_data_len < 4 || !response ||
        !response_len || !shared_secret_out || !shared_secret_len)
        return -1;

    uint16_t group_id = ((uint16_t)ext_data[0] << 8) | ext_data[1];
    uint16_t share_len = ((uint16_t)ext_data[2] << 8) | ext_data[3];

    if (ext_data_len < 4u + share_len)
        return -1;

    const uint8_t *client_share = ext_data + 4;

    PQC_TLS_KeyShare *ks = pqc_tls_keyshare_new(group_id);
    if (!ks)
        return -1;

    /* Reserve header in response */
    size_t header_sz = 4;
    size_t server_share_sz = *response_len > header_sz
                                 ? *response_len - header_sz : 0;
    uint8_t *server_share = response + header_sz;

    if (pqc_tls_keyshare_encapsulate(ks,
                                      client_share, share_len,
                                      server_share, &server_share_sz,
                                      shared_secret_out,
                                      shared_secret_len) != 0) {
        pqc_tls_keyshare_free(ks);
        return -1;
    }

    /* Write header */
    response[0] = (uint8_t)(group_id >> 8);
    response[1] = (uint8_t)(group_id & 0xFF);
    response[2] = (uint8_t)(server_share_sz >> 8);
    response[3] = (uint8_t)(server_share_sz & 0xFF);

    *response_len = header_sz + server_share_sz;

    pqc_tls_keyshare_free(ks);
    return 0;
}

/*
 * Client-side: parse the ServerHello hybrid extension and recover the
 * shared secret.
 *
 *   ks                - key-share context from pqc_tls12_build_client_extension
 *   ext_data          - the server extension payload
 *   ext_data_len      - length of ext_data
 *   shared_secret_out - output buffer
 *   shared_secret_len - on input: buffer size; on output: bytes written
 *
 * Returns 0 on success, -1 on failure. Frees ks on success.
 */
int pqc_tls12_process_server_extension(
        PQC_TLS_KeyShare *ks,
        const uint8_t *ext_data, size_t ext_data_len,
        uint8_t *shared_secret_out, size_t *shared_secret_len)
{
    if (!ks || !ext_data || ext_data_len < 4 ||
        !shared_secret_out || !shared_secret_len)
        return -1;

    /* uint16_t group_id = ((uint16_t)ext_data[0] << 8) | ext_data[1]; */
    uint16_t share_len = ((uint16_t)ext_data[2] << 8) | ext_data[3];

    if (ext_data_len < 4u + share_len)
        return -1;

    const uint8_t *server_share = ext_data + 4;

    int rc = pqc_tls_keyshare_decapsulate(ks,
                                           server_share, share_len,
                                           shared_secret_out,
                                           shared_secret_len);

    pqc_tls_keyshare_free(ks);
    return rc;
}

/* -------------------------------------------------------------------------- */
/* SSL_CTX registration (portable)                                             */
/* -------------------------------------------------------------------------- */

int pqc_tls12_register_hybrid_kex(void *ssl_ctx)
{
    if (!ssl_ctx)
        return -1;

    /*
     * Registering custom TLS extensions is library-specific. This
     * function documents the intent; the actual registration must be
     * done by the caller using their TLS library's extension API
     * (e.g. SSL_CTX_add_custom_ext in OpenSSL, or the equivalent
     * BoringSSL hook).
     *
     * The caller should:
     *   1. Register extension type PQC_TLS12_EXTENSION_TYPE (0xFF01).
     *   2. In the ClientHello callback, call
     *      pqc_tls12_build_client_extension().
     *   3. In the ServerHello callback, call
     *      pqc_tls12_process_client_extension().
     *   4. Mix the resulting shared_secret into the TLS PRF.
     */
    (void)ssl_ctx;
    return 0;
}
