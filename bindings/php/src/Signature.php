<?php
/**
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Signature class.
 */

declare(strict_types=1);

namespace Dyber\PQC;

use RuntimeException;

final class Signature
{
    /** @var \FFI\CData */
    private $handle;
    private string $algorithm;
    private bool $freed = false;

    /**
     * Create a Signature context for the specified algorithm.
     *
     * @param string $algorithm Algorithm name, e.g. "ML-DSA-65"
     * @throws RuntimeException if the algorithm is not supported
     */
    public function __construct(string $algorithm)
    {
        $this->algorithm = $algorithm;
        $ffi = PQC::ffi();
        $this->handle = $ffi->pqc_sig_new($algorithm);
        if (\FFI::isNull($this->handle)) {
            throw new RuntimeException("Unsupported signature algorithm: {$algorithm}");
        }
    }

    public function __destruct()
    {
        if (!$this->freed) {
            PQC::ffi()->pqc_sig_free($this->handle);
        }
    }

    public function free(): void
    {
        if (!$this->freed) {
            PQC::ffi()->pqc_sig_free($this->handle);
            $this->freed = true;
        }
    }

    public function algorithm(): string
    {
        return $this->algorithm;
    }

    public function publicKeySize(): int
    {
        return PQC::ffi()->pqc_sig_public_key_size($this->handle);
    }

    public function secretKeySize(): int
    {
        return PQC::ffi()->pqc_sig_secret_key_size($this->handle);
    }

    public function maxSignatureSize(): int
    {
        return PQC::ffi()->pqc_sig_max_signature_size($this->handle);
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

        $rc = $ffi->pqc_sig_keygen($this->handle, $pk, $sk);
        if ($rc !== 0) {
            throw new RuntimeException("Signature keygen failed: " . $ffi->pqc_status_string($rc));
        }

        return [
            'publicKey' => \FFI::string($pk, $pkSize),
            'secretKey' => \FFI::string($sk, $skSize),
        ];
    }

    /**
     * Sign a message.
     *
     * @param string $message
     * @param string $secretKey
     * @return string The signature
     */
    public function sign(string $message, string $secretKey): string
    {
        $ffi = PQC::ffi();
        $maxSigSize = $this->maxSignatureSize();

        $sigBuf = $ffi->new("uint8_t[{$maxSigSize}]");
        $sigLen = $ffi->new("size_t");
        $sigLen->cdata = $maxSigSize;

        $msgLen = strlen($message);
        $msgBuf = $ffi->new("uint8_t[{$msgLen}]");
        \FFI::memcpy($msgBuf, $message, $msgLen);

        $skLen = strlen($secretKey);
        $skBuf = $ffi->new("uint8_t[{$skLen}]");
        \FFI::memcpy($skBuf, $secretKey, $skLen);

        $rc = $ffi->pqc_sig_sign($this->handle, $sigBuf, \FFI::addr($sigLen), $msgBuf, $msgLen, $skBuf);
        if ($rc !== 0) {
            throw new RuntimeException("Signature sign failed: " . $ffi->pqc_status_string($rc));
        }

        return \FFI::string($sigBuf, $sigLen->cdata);
    }

    /**
     * Verify a signature.
     *
     * @param string $message
     * @param string $signature
     * @param string $publicKey
     * @return bool True if valid
     */
    public function verify(string $message, string $signature, string $publicKey): bool
    {
        $ffi = PQC::ffi();

        $msgLen = strlen($message);
        $msgBuf = $ffi->new("uint8_t[{$msgLen}]");
        \FFI::memcpy($msgBuf, $message, $msgLen);

        $sigLen = strlen($signature);
        $sigBuf = $ffi->new("uint8_t[{$sigLen}]");
        \FFI::memcpy($sigBuf, $signature, $sigLen);

        $pkLen = strlen($publicKey);
        $pkBuf = $ffi->new("uint8_t[{$pkLen}]");
        \FFI::memcpy($pkBuf, $publicKey, $pkLen);

        $rc = $ffi->pqc_sig_verify($this->handle, $msgBuf, $msgLen, $sigBuf, $sigLen, $pkBuf);
        return $rc === 0;
    }
}
