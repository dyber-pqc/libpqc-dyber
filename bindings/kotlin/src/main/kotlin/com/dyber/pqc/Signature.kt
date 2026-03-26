/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Kotlin Signature wrapper.
 */

package com.dyber.pqc

/**
 * Signature keypair.
 */
data class SignatureKeyPair(
    val publicKey: ByteArray,
    val secretKey: ByteArray
)

/**
 * Digital signature operations.
 *
 * @param algorithm Algorithm name, e.g. "ML-DSA-65"
 */
class Signature(val algorithm: String) : AutoCloseable {

    private val handle: Long

    init {
        handle = NativeLib.pqc_sig_new(algorithm)
        require(handle != 0L) { "Unsupported signature algorithm: $algorithm" }
    }

    /** Public key size in bytes. */
    val publicKeySize: Int
        get() = NativeLib.pqc_sig_public_key_size(handle)

    /** Secret key size in bytes. */
    val secretKeySize: Int
        get() = NativeLib.pqc_sig_secret_key_size(handle)

    /** Maximum signature size in bytes. */
    val maxSignatureSize: Int
        get() = NativeLib.pqc_sig_max_signature_size(handle)

    /** NIST security level (1-5). */
    val securityLevel: Int
        get() = NativeLib.pqc_sig_security_level(handle)

    /** Whether this is a stateful signature scheme. */
    val isStateful: Boolean
        get() = NativeLib.pqc_sig_is_stateful(handle)

    /**
     * Generate a new keypair.
     */
    fun keygen(): SignatureKeyPair {
        val pk = ByteArray(publicKeySize)
        val sk = ByteArray(secretKeySize)
        val rc = NativeLib.pqc_sig_keygen(handle, pk, sk)
        check(rc == 0) { "Signature keygen failed: ${NativeLib.pqc_status_string(rc)}" }
        return SignatureKeyPair(pk, sk)
    }

    /**
     * Sign a message.
     *
     * @param message The message to sign.
     * @param secretKey The signer's secret key.
     * @return The signature bytes (trimmed to actual length).
     */
    fun sign(message: ByteArray, secretKey: ByteArray): ByteArray {
        require(secretKey.size == secretKeySize) {
            "Secret key must be $secretKeySize bytes, got ${secretKey.size}"
        }
        val sigBuf = ByteArray(maxSignatureSize)
        return NativeLib.pqc_sig_sign(handle, sigBuf, message, secretKey)
    }

    /**
     * Verify a signature.
     *
     * @param message The message that was signed.
     * @param signature The signature to verify.
     * @param publicKey The signer's public key.
     * @return True if the signature is valid.
     */
    fun verify(message: ByteArray, signature: ByteArray, publicKey: ByteArray): Boolean {
        require(publicKey.size == publicKeySize) {
            "Public key must be $publicKeySize bytes, got ${publicKey.size}"
        }
        return NativeLib.pqc_sig_verify(handle, message, signature, publicKey)
    }

    override fun close() {
        NativeLib.pqc_sig_free(handle)
    }

    companion object {
        /** Well-known algorithm names. */
        const val ML_DSA_44 = "ML-DSA-44"
        const val ML_DSA_65 = "ML-DSA-65"
        const val ML_DSA_87 = "ML-DSA-87"
        const val FN_DSA_512 = "FN-DSA-512"
        const val FN_DSA_1024 = "FN-DSA-1024"

        /** List all available signature algorithms. */
        fun algorithms(): List<String> {
            val count = NativeLib.pqc_sig_algorithm_count()
            return (0 until count).map { NativeLib.pqc_sig_algorithm_name(it) }
        }
    }
}
