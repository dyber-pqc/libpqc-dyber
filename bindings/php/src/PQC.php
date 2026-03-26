<?php
/**
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Main PQC class providing FFI access to the native library.
 */

declare(strict_types=1);

namespace Dyber\PQC;

use FFI;
use RuntimeException;

final class PQC
{
    private static ?FFI $ffi = null;

    private const HEADER_DEFS = <<<'CDEF'
    typedef int pqc_status_t;

    const char *pqc_version(void);
    int pqc_version_major(void);
    int pqc_version_minor(void);
    int pqc_version_patch(void);

    pqc_status_t pqc_init(void);
    void pqc_cleanup(void);

    const char *pqc_status_string(pqc_status_t status);

    int pqc_kem_algorithm_count(void);
    const char *pqc_kem_algorithm_name(int index);
    int pqc_kem_is_enabled(const char *algorithm);

    int pqc_sig_algorithm_count(void);
    const char *pqc_sig_algorithm_name(int index);
    int pqc_sig_is_enabled(const char *algorithm);

    typedef struct pqc_kem_s PQC_KEM;
    PQC_KEM *pqc_kem_new(const char *algorithm);
    void pqc_kem_free(PQC_KEM *kem);
    const char *pqc_kem_algorithm(const PQC_KEM *kem);
    size_t pqc_kem_public_key_size(const PQC_KEM *kem);
    size_t pqc_kem_secret_key_size(const PQC_KEM *kem);
    size_t pqc_kem_ciphertext_size(const PQC_KEM *kem);
    size_t pqc_kem_shared_secret_size(const PQC_KEM *kem);
    int pqc_kem_security_level(const PQC_KEM *kem);
    pqc_status_t pqc_kem_keygen(const PQC_KEM *kem, uint8_t *public_key, uint8_t *secret_key);
    pqc_status_t pqc_kem_encaps(const PQC_KEM *kem, uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
    pqc_status_t pqc_kem_decaps(const PQC_KEM *kem, uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);

    typedef struct pqc_sig_s PQC_SIG;
    PQC_SIG *pqc_sig_new(const char *algorithm);
    void pqc_sig_free(PQC_SIG *sig);
    const char *pqc_sig_algorithm(const PQC_SIG *sig);
    size_t pqc_sig_public_key_size(const PQC_SIG *sig);
    size_t pqc_sig_secret_key_size(const PQC_SIG *sig);
    size_t pqc_sig_max_signature_size(const PQC_SIG *sig);
    int pqc_sig_security_level(const PQC_SIG *sig);
    int pqc_sig_is_stateful(const PQC_SIG *sig);
    pqc_status_t pqc_sig_keygen(const PQC_SIG *sig, uint8_t *public_key, uint8_t *secret_key);
    pqc_status_t pqc_sig_sign(const PQC_SIG *sig, uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
    pqc_status_t pqc_sig_verify(const PQC_SIG *sig, const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
    CDEF;

    /**
     * Get the FFI instance, initializing if needed.
     */
    public static function ffi(): FFI
    {
        if (self::$ffi === null) {
            $libName = PHP_OS_FAMILY === 'Windows' ? 'pqc.dll' : 'libpqc.so';
            self::$ffi = FFI::cdef(self::HEADER_DEFS, $libName);
            $rc = self::$ffi->pqc_init();
            if ($rc !== 0) {
                throw new RuntimeException('Failed to initialize libpqc: ' . $rc);
            }
        }
        return self::$ffi;
    }

    /**
     * Get the library version string.
     */
    public static function version(): string
    {
        return self::ffi()->pqc_version();
    }

    /**
     * List all enabled KEM algorithm names.
     *
     * @return string[]
     */
    public static function kemAlgorithms(): array
    {
        $ffi = self::ffi();
        $count = $ffi->pqc_kem_algorithm_count();
        $algorithms = [];
        for ($i = 0; $i < $count; $i++) {
            $algorithms[] = $ffi->pqc_kem_algorithm_name($i);
        }
        return $algorithms;
    }

    /**
     * List all enabled signature algorithm names.
     *
     * @return string[]
     */
    public static function sigAlgorithms(): array
    {
        $ffi = self::ffi();
        $count = $ffi->pqc_sig_algorithm_count();
        $algorithms = [];
        for ($i = 0; $i < $count; $i++) {
            $algorithms[] = $ffi->pqc_sig_algorithm_name($i);
        }
        return $algorithms;
    }
}
