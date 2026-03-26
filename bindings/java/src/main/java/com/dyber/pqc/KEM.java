/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

package com.dyber.pqc;

/**
 * Key Encapsulation Mechanism (KEM) wrapper.
 *
 * <p>Provides key generation, encapsulation, and decapsulation operations
 * for post-quantum KEM algorithms.</p>
 *
 * <pre>{@code
 * try (KEM kem = new KEM("ML-KEM-768")) {
 *     KEM.KeyPair kp = kem.keygen();
 *     KEM.EncapsResult enc = kem.encaps(kp.publicKey);
 *     byte[] ss = kem.decaps(enc.ciphertext, kp.secretKey);
 *     // enc.sharedSecret equals ss
 * }
 * }</pre>
 */
public class KEM implements AutoCloseable {

    private long handle;

    /**
     * Result of a key generation operation.
     */
    public static class KeyPair {
        /** The public key bytes. */
        public final byte[] publicKey;
        /** The secret key bytes. */
        public final byte[] secretKey;

        KeyPair(byte[] publicKey, byte[] secretKey) {
            this.publicKey = publicKey;
            this.secretKey = secretKey;
        }
    }

    /**
     * Result of an encapsulation operation.
     */
    public static class EncapsResult {
        /** The ciphertext bytes. */
        public final byte[] ciphertext;
        /** The shared secret bytes. */
        public final byte[] sharedSecret;

        EncapsResult(byte[] ciphertext, byte[] sharedSecret) {
            this.ciphertext = ciphertext;
            this.sharedSecret = sharedSecret;
        }
    }

    /**
     * Create a new KEM context for the specified algorithm.
     *
     * @param algorithm the algorithm name (e.g., "ML-KEM-768")
     * @throws PQCException if the algorithm is not supported
     */
    public KEM(String algorithm) throws PQCException {
        this.handle = PQC.nativeKemNew(algorithm);
        if (this.handle == 0) {
            throw new PQCException(PQCException.NOT_SUPPORTED,
                "Unsupported KEM algorithm: " + algorithm);
        }
    }

    private void ensureOpen() {
        if (handle == 0) {
            throw new IllegalStateException("KEM context has been closed");
        }
    }

    /**
     * Return the algorithm name.
     */
    public String algorithm() {
        ensureOpen();
        return PQC.nativeKemAlgorithm(handle);
    }

    /**
     * Return the public key size in bytes.
     */
    public int publicKeySize() {
        ensureOpen();
        return PQC.nativeKemPublicKeySize(handle);
    }

    /**
     * Return the secret key size in bytes.
     */
    public int secretKeySize() {
        ensureOpen();
        return PQC.nativeKemSecretKeySize(handle);
    }

    /**
     * Return the ciphertext size in bytes.
     */
    public int ciphertextSize() {
        ensureOpen();
        return PQC.nativeKemCiphertextSize(handle);
    }

    /**
     * Return the shared secret size in bytes.
     */
    public int sharedSecretSize() {
        ensureOpen();
        return PQC.nativeKemSharedSecretSize(handle);
    }

    /**
     * Return the NIST security level (1-5).
     */
    public int securityLevel() {
        ensureOpen();
        return PQC.nativeKemSecurityLevel(handle);
    }

    /**
     * Generate a new keypair.
     *
     * @return the generated key pair
     * @throws PQCException on failure
     */
    public KeyPair keygen() throws PQCException {
        ensureOpen();
        byte[][] result = PQC.nativeKemKeygen(handle);
        if (result == null || result.length != 2) {
            throw new PQCException(PQCException.INTERNAL, "keygen returned unexpected result");
        }
        return new KeyPair(result[0], result[1]);
    }

    /**
     * Encapsulate a shared secret using the given public key.
     *
     * @param publicKey the recipient's public key
     * @return the encapsulation result (ciphertext + shared secret)
     * @throws PQCException on failure
     */
    public EncapsResult encaps(byte[] publicKey) throws PQCException {
        ensureOpen();
        if (publicKey == null || publicKey.length != publicKeySize()) {
            throw new PQCException(PQCException.INVALID_ARGUMENT, "invalid public key length");
        }
        byte[][] result = PQC.nativeKemEncaps(handle, publicKey);
        if (result == null || result.length != 2) {
            throw new PQCException(PQCException.INTERNAL, "encaps returned unexpected result");
        }
        return new EncapsResult(result[0], result[1]);
    }

    /**
     * Decapsulate a ciphertext to recover the shared secret.
     *
     * @param ciphertext the ciphertext from encapsulation
     * @param secretKey  the recipient's secret key
     * @return the shared secret
     * @throws PQCException on failure
     */
    public byte[] decaps(byte[] ciphertext, byte[] secretKey) throws PQCException {
        ensureOpen();
        if (ciphertext == null || ciphertext.length != ciphertextSize()) {
            throw new PQCException(PQCException.INVALID_ARGUMENT, "invalid ciphertext length");
        }
        if (secretKey == null || secretKey.length != secretKeySize()) {
            throw new PQCException(PQCException.INVALID_ARGUMENT, "invalid secret key length");
        }
        byte[] ss = PQC.nativeKemDecaps(handle, ciphertext, secretKey);
        if (ss == null) {
            throw new PQCException(PQCException.DECAPSULATION_FAILED, "decapsulation failed");
        }
        return ss;
    }

    /**
     * Release the native KEM context.
     */
    @Override
    public void close() {
        if (handle != 0) {
            PQC.nativeKemFree(handle);
            handle = 0;
        }
    }
}
