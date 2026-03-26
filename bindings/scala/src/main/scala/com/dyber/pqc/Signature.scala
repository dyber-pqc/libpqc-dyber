/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Scala Signature wrapper.
 */

package com.dyber.pqc

/** Signature keypair result. */
case class SignatureKeyPair(publicKey: Array[Byte], secretKey: Array[Byte])

/**
 * Digital signature operations.
 *
 * @param algorithm Algorithm name, e.g. "ML-DSA-65"
 */
class Signature(val algorithm: String) extends AutoCloseable {

  private val handle: Long = NativeLib.pqc_sig_new(algorithm)
  require(handle != 0L, s"Unsupported signature algorithm: $algorithm")

  /** Public key size in bytes. */
  def publicKeySize: Int = NativeLib.pqc_sig_public_key_size(handle)

  /** Secret key size in bytes. */
  def secretKeySize: Int = NativeLib.pqc_sig_secret_key_size(handle)

  /** Maximum signature size in bytes. */
  def maxSignatureSize: Int = NativeLib.pqc_sig_max_signature_size(handle)

  /** NIST security level (1-5). */
  def securityLevel: Int = NativeLib.pqc_sig_security_level(handle)

  /** Whether this is a stateful signature scheme. */
  def isStateful: Boolean = NativeLib.pqc_sig_is_stateful(handle)

  /** Generate a new keypair. */
  def keygen(): SignatureKeyPair = {
    val pk = new Array[Byte](publicKeySize)
    val sk = new Array[Byte](secretKeySize)
    val rc = NativeLib.pqc_sig_keygen(handle, pk, sk)
    if (rc != 0) throw new RuntimeException(s"Signature keygen failed: ${NativeLib.pqc_status_string(rc)}")
    SignatureKeyPair(pk, sk)
  }

  /**
   * Sign a message.
   * @param message The message to sign.
   * @param secretKey The signer's secret key.
   * @return The signature bytes (trimmed to actual length).
   */
  def sign(message: Array[Byte], secretKey: Array[Byte]): Array[Byte] = {
    require(secretKey.length == secretKeySize, s"Secret key must be $secretKeySize bytes")
    val sigBuf = new Array[Byte](maxSignatureSize)
    NativeLib.pqc_sig_sign(handle, sigBuf, message, secretKey)
  }

  /**
   * Verify a signature.
   * @param message The message that was signed.
   * @param signature The signature to verify.
   * @param publicKey The signer's public key.
   * @return True if the signature is valid.
   */
  def verify(message: Array[Byte], signature: Array[Byte], publicKey: Array[Byte]): Boolean = {
    require(publicKey.length == publicKeySize, s"Public key must be $publicKeySize bytes")
    NativeLib.pqc_sig_verify(handle, message, signature, publicKey)
  }

  override def close(): Unit = NativeLib.pqc_sig_free(handle)
}

object Signature {
  val MlDsa44  = "ML-DSA-44"
  val MlDsa65  = "ML-DSA-65"
  val MlDsa87  = "ML-DSA-87"
  val FnDsa512 = "FN-DSA-512"
  val FnDsa1024 = "FN-DSA-1024"

  /** List all available signature algorithms. */
  def algorithms: Seq[String] = {
    val count = NativeLib.pqc_sig_algorithm_count()
    (0 until count).map(NativeLib.pqc_sig_algorithm_name)
  }
}
