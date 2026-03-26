/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

package com.dyber.pqc;

/**
 * Digital Signature wrapper.
 *
 * <p>Provides key generation, signing, and verification operations
 * for post-quantum signature algorithms.</p>
 *
 * <pre>{@code
 * try (Signature sig = new Signature("ML-DSA-65")) {
 *     Signature.KeyPair kp = sig.keygen();
 *     byte[] signature = sig.sign("hello".getBytes(), kp.secretKey);
 *     boolean valid = sig.verify("hello".getBytes(), signature, kp.publicKey);
 * }
 * }</pre>
 */
public class Signature implements AutoCloseable {

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
     * Create a new signature context for the specified algorithm.
     *
     * @param algorithm the algorithm name (e.g., "ML-DSA-65")
     * @throws PQCException if the algorithm is not supported
     */
    public Signature(String algorithm) throws PQCException {
        this.handle = PQC.nativeSigNew(algorithm);
        if (this.handle == 0) {
            throw new PQCException(PQCException.NOT_SUPPORTED,
                "Unsupported signature algorithm: " + algorithm);
        }
    }

    private void ensureOpen() {
        if (handle == 0) {
            throw new IllegalStateException("Signature context has been closed");
        }
    }

    /**
     * Return the algorithm name.
     */
    public String algorithm() {
        ensureOpen();
        return PQC.nativeSigAlgorithm(handle);
    }

    /**
     * Return the public key size in bytes.
     */
    public int publicKeySize() {
        ensureOpen();
        return PQC.nativeSigPublicKeySize(handle);
    }

    /**
     * Return the secret key size in bytes.
     */
    public int secretKeySize() {
        ensureOpen();
        return PQC.nativeSigSecretKeySize(handle);
    }

    /**
     * Return the maximum possible signature size in bytes.
     */
    public int maxSignatureSize() {
        ensureOpen();
        return PQC.nativeSigMaxSignatureSize(handle);
    }

    /**
     * Return the NIST security level (1-5).
     */
    public int securityLevel() {
        ensureOpen();
        return PQC.nativeSigSecurityLevel(handle);
    }

    /**
     * Return true if this is a stateful signature scheme (e.g., LMS, XMSS).
     */
    public boolean isStateful() {
        ensureOpen();
        return PQC.nativeSigIsStateful(handle);
    }

    /**
     * Generate a new keypair.
     *
     * @return the generated key pair
     * @throws PQCException on failure
     */
    public KeyPair keygen() throws PQCException {
        ensureOpen();
        byte[][] result = PQC.nativeSigKeygen(handle);
        if (result == null || result.length != 2) {
            throw new PQCException(PQCException.INTERNAL, "keygen returned unexpected result");
        }
        return new KeyPair(result[0], result[1]);
    }

    /**
     * Sign a message.
     *
     * @param message   the message to sign
     * @param secretKey the signer's secret key
     * @return the signature bytes
     * @throws PQCException on failure
     */
    public byte[] sign(byte[] message, byte[] secretKey) throws PQCException {
        ensureOpen();
        if (secretKey == null || secretKey.length != secretKeySize()) {
            throw new PQCException(PQCException.INVALID_ARGUMENT, "invalid secret key length");
        }
        byte[] sig = PQC.nativeSigSign(handle, message, secretKey);
        if (sig == null) {
            throw new PQCException(PQCException.INTERNAL, "sign failed");
        }
        return sig;
    }

    /**
     * Verify a signature on a message.
     *
     * @param message   the original message
     * @param signature the signature to verify
     * @param publicKey the signer's public key
     * @return true if the signature is valid
     * @throws PQCException on error (not thrown for invalid signatures)
     */
    public boolean verify(byte[] message, byte[] signature, byte[] publicKey) throws PQCException {
        ensureOpen();
        if (publicKey == null || publicKey.length != publicKeySize()) {
            throw new PQCException(PQCException.INVALID_ARGUMENT, "invalid public key length");
        }
        int status = PQC.nativeSigVerify(handle, message, signature, publicKey);
        if (status == PQCException.OK) {
            return true;
        } else if (status == PQCException.VERIFICATION_FAILED) {
            return false;
        } else {
            throw new PQCException(status);
        }
    }

    /**
     * Release the native signature context.
     */
    @Override
    public void close() {
        if (handle != 0) {
            PQC.nativeSigFree(handle);
            handle = 0;
        }
    }
}
