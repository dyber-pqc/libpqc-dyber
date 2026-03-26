/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Scala KEM (Key Encapsulation Mechanism) wrapper.
 */

package com.dyber.pqc

/** KEM keypair result. */
case class KEMKeyPair(publicKey: Array[Byte], secretKey: Array[Byte])

/** KEM encapsulation result. */
case class KEMEncapsResult(ciphertext: Array[Byte], sharedSecret: Array[Byte])

/**
 * Key Encapsulation Mechanism (KEM) operations.
 *
 * @param algorithm Algorithm name, e.g. "ML-KEM-768"
 */
class KEM(val algorithm: String) extends AutoCloseable {

  private val handle: Long = NativeLib.pqc_kem_new(algorithm)
  require(handle != 0L, s"Unsupported KEM algorithm: $algorithm")

  /** Public key size in bytes. */
  def publicKeySize: Int = NativeLib.pqc_kem_public_key_size(handle)

  /** Secret key size in bytes. */
  def secretKeySize: Int = NativeLib.pqc_kem_secret_key_size(handle)

  /** Ciphertext size in bytes. */
  def ciphertextSize: Int = NativeLib.pqc_kem_ciphertext_size(handle)

  /** Shared secret size in bytes. */
  def sharedSecretSize: Int = NativeLib.pqc_kem_shared_secret_size(handle)

  /** NIST security level (1-5). */
  def securityLevel: Int = NativeLib.pqc_kem_security_level(handle)

  /** Generate a new keypair. */
  def keygen(): KEMKeyPair = {
    val pk = new Array[Byte](publicKeySize)
    val sk = new Array[Byte](secretKeySize)
    val rc = NativeLib.pqc_kem_keygen(handle, pk, sk)
    if (rc != 0) throw new RuntimeException(s"KEM keygen failed: ${NativeLib.pqc_status_string(rc)}")
    KEMKeyPair(pk, sk)
  }

  /** Encapsulate: generate shared secret and ciphertext from a public key. */
  def encaps(publicKey: Array[Byte]): KEMEncapsResult = {
    require(publicKey.length == publicKeySize, s"Public key must be $publicKeySize bytes")
    val ct = new Array[Byte](ciphertextSize)
    val ss = new Array[Byte](sharedSecretSize)
    val rc = NativeLib.pqc_kem_encaps(handle, ct, ss, publicKey)
    if (rc != 0) throw new RuntimeException(s"KEM encaps failed: ${NativeLib.pqc_status_string(rc)}")
    KEMEncapsResult(ct, ss)
  }

  /** Decapsulate: recover shared secret from ciphertext using secret key. */
  def decaps(ciphertext: Array[Byte], secretKey: Array[Byte]): Array[Byte] = {
    require(ciphertext.length == ciphertextSize, s"Ciphertext must be $ciphertextSize bytes")
    require(secretKey.length == secretKeySize, s"Secret key must be $secretKeySize bytes")
    val ss = new Array[Byte](sharedSecretSize)
    val rc = NativeLib.pqc_kem_decaps(handle, ss, ciphertext, secretKey)
    if (rc != 0) throw new RuntimeException(s"KEM decaps failed: ${NativeLib.pqc_status_string(rc)}")
    ss
  }

  override def close(): Unit = NativeLib.pqc_kem_free(handle)
}

object KEM {
  val MlKem512  = "ML-KEM-512"
  val MlKem768  = "ML-KEM-768"
  val MlKem1024 = "ML-KEM-1024"
  val Hqc128    = "HQC-128"
  val Hqc192    = "HQC-192"
  val Hqc256    = "HQC-256"

  /** List all available KEM algorithms. */
  def algorithms: Seq[String] = {
    val count = NativeLib.pqc_kem_algorithm_count()
    (0 until count).map(NativeLib.pqc_kem_algorithm_name)
  }
}

/** JNI native method declarations. */
@native
private[pqc] object NativeLib {
  System.loadLibrary("pqc_jni")

  @native def pqc_init(): Int
  @native def pqc_cleanup(): Unit
  @native def pqc_version(): String
  @native def pqc_status_string(status: Int): String

  @native def pqc_kem_algorithm_count(): Int
  @native def pqc_kem_algorithm_name(index: Int): String
  @native def pqc_kem_is_enabled(algorithm: String): Boolean

  @native def pqc_kem_new(algorithm: String): Long
  @native def pqc_kem_free(handle: Long): Unit
  @native def pqc_kem_public_key_size(handle: Long): Int
  @native def pqc_kem_secret_key_size(handle: Long): Int
  @native def pqc_kem_ciphertext_size(handle: Long): Int
  @native def pqc_kem_shared_secret_size(handle: Long): Int
  @native def pqc_kem_security_level(handle: Long): Int
  @native def pqc_kem_keygen(handle: Long, pk: Array[Byte], sk: Array[Byte]): Int
  @native def pqc_kem_encaps(handle: Long, ct: Array[Byte], ss: Array[Byte], pk: Array[Byte]): Int
  @native def pqc_kem_decaps(handle: Long, ss: Array[Byte], ct: Array[Byte], sk: Array[Byte]): Int

  @native def pqc_sig_algorithm_count(): Int
  @native def pqc_sig_algorithm_name(index: Int): String
  @native def pqc_sig_is_enabled(algorithm: String): Boolean

  @native def pqc_sig_new(algorithm: String): Long
  @native def pqc_sig_free(handle: Long): Unit
  @native def pqc_sig_public_key_size(handle: Long): Int
  @native def pqc_sig_secret_key_size(handle: Long): Int
  @native def pqc_sig_max_signature_size(handle: Long): Int
  @native def pqc_sig_security_level(handle: Long): Int
  @native def pqc_sig_is_stateful(handle: Long): Boolean
  @native def pqc_sig_keygen(handle: Long, pk: Array[Byte], sk: Array[Byte]): Int
  @native def pqc_sig_sign(handle: Long, sig: Array[Byte], msg: Array[Byte], sk: Array[Byte]): Array[Byte]
  @native def pqc_sig_verify(handle: Long, msg: Array[Byte], sig: Array[Byte], pk: Array[Byte]): Boolean
}
