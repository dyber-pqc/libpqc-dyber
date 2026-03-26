/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Kotlin KEM (Key Encapsulation Mechanism) wrapper.
 */

package com.dyber.pqc

/**
 * KEM keypair.
 */
data class KEMKeyPair(
    val publicKey: ByteArray,
    val secretKey: ByteArray
)

/**
 * KEM encapsulation result.
 */
data class KEMEncapsResult(
    val ciphertext: ByteArray,
    val sharedSecret: ByteArray
)

/**
 * Key Encapsulation Mechanism (KEM) operations.
 *
 * @param algorithm Algorithm name, e.g. "ML-KEM-768"
 */
class KEM(val algorithm: String) : AutoCloseable {

    private val handle: Long

    init {
        handle = NativeLib.pqc_kem_new(algorithm)
        require(handle != 0L) { "Unsupported KEM algorithm: $algorithm" }
    }

    /** Public key size in bytes. */
    val publicKeySize: Int
        get() = NativeLib.pqc_kem_public_key_size(handle)

    /** Secret key size in bytes. */
    val secretKeySize: Int
        get() = NativeLib.pqc_kem_secret_key_size(handle)

    /** Ciphertext size in bytes. */
    val ciphertextSize: Int
        get() = NativeLib.pqc_kem_ciphertext_size(handle)

    /** Shared secret size in bytes. */
    val sharedSecretSize: Int
        get() = NativeLib.pqc_kem_shared_secret_size(handle)

    /** NIST security level (1-5). */
    val securityLevel: Int
        get() = NativeLib.pqc_kem_security_level(handle)

    /**
     * Generate a new keypair.
     */
    fun keygen(): KEMKeyPair {
        val pk = ByteArray(publicKeySize)
        val sk = ByteArray(secretKeySize)
        val rc = NativeLib.pqc_kem_keygen(handle, pk, sk)
        check(rc == 0) { "KEM keygen failed: ${NativeLib.pqc_status_string(rc)}" }
        return KEMKeyPair(pk, sk)
    }

    /**
     * Encapsulate: generate shared secret and ciphertext from a public key.
     */
    fun encaps(publicKey: ByteArray): KEMEncapsResult {
        require(publicKey.size == publicKeySize) {
            "Public key must be $publicKeySize bytes, got ${publicKey.size}"
        }
        val ct = ByteArray(ciphertextSize)
        val ss = ByteArray(sharedSecretSize)
        val rc = NativeLib.pqc_kem_encaps(handle, ct, ss, publicKey)
        check(rc == 0) { "KEM encaps failed: ${NativeLib.pqc_status_string(rc)}" }
        return KEMEncapsResult(ct, ss)
    }

    /**
     * Decapsulate: recover shared secret from ciphertext using secret key.
     */
    fun decaps(ciphertext: ByteArray, secretKey: ByteArray): ByteArray {
        require(ciphertext.size == ciphertextSize) {
            "Ciphertext must be $ciphertextSize bytes, got ${ciphertext.size}"
        }
        require(secretKey.size == secretKeySize) {
            "Secret key must be $secretKeySize bytes, got ${secretKey.size}"
        }
        val ss = ByteArray(sharedSecretSize)
        val rc = NativeLib.pqc_kem_decaps(handle, ss, ciphertext, secretKey)
        check(rc == 0) { "KEM decaps failed: ${NativeLib.pqc_status_string(rc)}" }
        return ss
    }

    override fun close() {
        NativeLib.pqc_kem_free(handle)
    }

    companion object {
        /** Well-known algorithm names. */
        const val ML_KEM_512 = "ML-KEM-512"
        const val ML_KEM_768 = "ML-KEM-768"
        const val ML_KEM_1024 = "ML-KEM-1024"
        const val HQC_128 = "HQC-128"
        const val HQC_192 = "HQC-192"
        const val HQC_256 = "HQC-256"

        /** List all available KEM algorithms. */
        fun algorithms(): List<String> {
            val count = NativeLib.pqc_kem_algorithm_count()
            return (0 until count).map { NativeLib.pqc_kem_algorithm_name(it) }
        }
    }
}

/**
 * JNI native method declarations.
 * Delegates to the Java JNI binding in the java module.
 */
internal object NativeLib {
    init {
        System.loadLibrary("pqc_jni")
    }

    @JvmStatic external fun pqc_init(): Int
    @JvmStatic external fun pqc_cleanup()
    @JvmStatic external fun pqc_version(): String
    @JvmStatic external fun pqc_status_string(status: Int): String

    @JvmStatic external fun pqc_kem_algorithm_count(): Int
    @JvmStatic external fun pqc_kem_algorithm_name(index: Int): String
    @JvmStatic external fun pqc_kem_is_enabled(algorithm: String): Boolean

    @JvmStatic external fun pqc_kem_new(algorithm: String): Long
    @JvmStatic external fun pqc_kem_free(handle: Long)
    @JvmStatic external fun pqc_kem_public_key_size(handle: Long): Int
    @JvmStatic external fun pqc_kem_secret_key_size(handle: Long): Int
    @JvmStatic external fun pqc_kem_ciphertext_size(handle: Long): Int
    @JvmStatic external fun pqc_kem_shared_secret_size(handle: Long): Int
    @JvmStatic external fun pqc_kem_security_level(handle: Long): Int
    @JvmStatic external fun pqc_kem_keygen(handle: Long, pk: ByteArray, sk: ByteArray): Int
    @JvmStatic external fun pqc_kem_encaps(handle: Long, ct: ByteArray, ss: ByteArray, pk: ByteArray): Int
    @JvmStatic external fun pqc_kem_decaps(handle: Long, ss: ByteArray, ct: ByteArray, sk: ByteArray): Int

    @JvmStatic external fun pqc_sig_algorithm_count(): Int
    @JvmStatic external fun pqc_sig_algorithm_name(index: Int): String
    @JvmStatic external fun pqc_sig_is_enabled(algorithm: String): Boolean

    @JvmStatic external fun pqc_sig_new(algorithm: String): Long
    @JvmStatic external fun pqc_sig_free(handle: Long)
    @JvmStatic external fun pqc_sig_public_key_size(handle: Long): Int
    @JvmStatic external fun pqc_sig_secret_key_size(handle: Long): Int
    @JvmStatic external fun pqc_sig_max_signature_size(handle: Long): Int
    @JvmStatic external fun pqc_sig_security_level(handle: Long): Int
    @JvmStatic external fun pqc_sig_is_stateful(handle: Long): Boolean
    @JvmStatic external fun pqc_sig_keygen(handle: Long, pk: ByteArray, sk: ByteArray): Int
    @JvmStatic external fun pqc_sig_sign(handle: Long, sig: ByteArray, msg: ByteArray, sk: ByteArray): ByteArray
    @JvmStatic external fun pqc_sig_verify(handle: Long, msg: ByteArray, sig: ByteArray, pk: ByteArray): Boolean
}
