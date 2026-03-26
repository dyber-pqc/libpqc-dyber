<?php
/**
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * KEM (Key Encapsulation Mechanism) class.
 */

declare(strict_types=1);

namespace Dyber\PQC;

use RuntimeException;

final class KEM
{
    /** @var \FFI\CData */
    private $handle;
    private string $algorithm;

    /**
     * Create a KEM context for the specified algorithm.
     *
     * @param string $algorithm Algorithm name, e.g. "ML-KEM-768"
     * @throws RuntimeException if the algorithm is not supported
     */
    public function __construct(string $algorithm)
    {
        $this->algorithm = $algorithm;
        $ffi = PQC::ffi();
        $this->handle = $ffi->pqc_kem_new($algorithm);
        if (\FFI::isNull($this->handle)) {
            throw new RuntimeException("Unsupported KEM algorithm: {$algorithm}");
        }
    }

    public function __destruct()
    {
        if (isset($this->handle) && !$this->freed) {
            PQC::ffi()->pqc_kem_free($this->handle);
        }
    }

    private bool $freed = false;

    public function free(): void
    {
        if (!$this->freed) {
            PQC::ffi()->pqc_kem_free($this->handle);
            $this->freed = true;
        }
    }

    public function algorithm(): string
    {
        return $this->algorithm;
    }

    public function publicKeySize(): int
    {
        return PQC::ffi()->pqc_kem_public_key_size($this->handle);
    }

    public function secretKeySize(): int
    {
        return PQC::ffi()->pqc_kem_secret_key_size($this->handle);
    }

    public function ciphertextSize(): int
    {
        return PQC::ffi()->pqc_kem_ciphertext_size($this->handle);
    }

    public function sharedSecretSize(): int
    {
        return PQC::ffi()->pqc_kem_shared_secret_size($this->handle);
    }

    /**
     * Generate a keypair.
     *
     * @return array{publicKey: string, secretKey: string}
     */
    public function keygen(): array
    {
        $ffi = PQC::ffi();
        $pkSize = $this->publicKeySize();
        $skSize = $this->secretKeySize();

        $pk = $ffi->new("uint8_t[{$pkSize}]");
        $sk = $ffi->new("uint8_t[{$skSize}]");

        $rc = $ffi->pqc_kem_keygen($this->handle, $pk, $sk);
        if ($rc !== 0) {
            throw new RuntimeException("KEM keygen failed: " . $ffi->pqc_status_string($rc));
        }

        return [
            'publicKey' => \FFI::string($pk, $pkSize),
            'secretKey' => \FFI::string($sk, $skSize),
        ];
    }

    /**
     * Encapsulate: generate shared secret and ciphertext from a public key.
     *
     * @param string $publicKey
     * @return array{ciphertext: string, sharedSecret: string}
     */
    public function encaps(string $publicKey): array
    {
        $ffi = PQC::ffi();
        $ctSize = $this->ciphertextSize();
        $ssSize = $this->sharedSecretSize();

        $ct = $ffi->new("uint8_t[{$ctSize}]");
        $ss = $ffi->new("uint8_t[{$ssSize}]");

        $pkBuf = $ffi->new("uint8_t[" . strlen($publicKey) . "]");
        \FFI::memcpy($pkBuf, $publicKey, strlen($publicKey));

        $rc = $ffi->pqc_kem_encaps($this->handle, $ct, $ss, $pkBuf);
        if ($rc !== 0) {
            throw new RuntimeException("KEM encaps failed: " . $ffi->pqc_status_string($rc));
        }

        return [
            'ciphertext' => \FFI::string($ct, $ctSize),
            'sharedSecret' => \FFI::string($ss, $ssSize),
        ];
    }

    /**
     * Decapsulate: recover shared secret from ciphertext using secret key.
     *
     * @param string $ciphertext
     * @param string $secretKey
     * @return string The shared secret
     */
    public function decaps(string $ciphertext, string $secretKey): string
    {
        $ffi = PQC::ffi();
        $ssSize = $this->sharedSecretSize();

        $ss = $ffi->new("uint8_t[{$ssSize}]");

        $ctBuf = $ffi->new("uint8_t[" . strlen($ciphertext) . "]");
        \FFI::memcpy($ctBuf, $ciphertext, strlen($ciphertext));

        $skBuf = $ffi->new("uint8_t[" . strlen($secretKey) . "]");
        \FFI::memcpy($skBuf, $secretKey, strlen($secretKey));

        $rc = $ffi->pqc_kem_decaps($this->handle, $ss, $ctBuf, $skBuf);
        if ($rc !== 0) {
            throw new RuntimeException("KEM decaps failed: " . $ffi->pqc_status_string($rc));
        }

        return \FFI::string($ss, $ssSize);
    }
}
