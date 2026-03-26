// libpqc-dyber - Post-Quantum Cryptography Library
// Copyright (c) 2024-2026 Dyber, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT

import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'bindings.dart';

/// KEM keypair result.
class KemKeyPair {
  final Uint8List publicKey;
  final Uint8List secretKey;
  KemKeyPair(this.publicKey, this.secretKey);
}

/// KEM encapsulation result.
class KemEncapsResult {
  final Uint8List ciphertext;
  final Uint8List sharedSecret;
  KemEncapsResult(this.ciphertext, this.sharedSecret);
}

/// Key Encapsulation Mechanism (KEM) operations.
class Kem {
  final PqcBindings _bindings;
  final Pointer _handle;
  final String algorithm;

  /// Create a KEM context for the specified algorithm.
  ///
  /// Throws [ArgumentError] if the algorithm is not supported.
  Kem(this.algorithm) : _bindings = PqcBindings(), _handle = _createHandle(algorithm) {
    if (_handle == nullptr) {
      throw ArgumentError('Unsupported KEM algorithm: $algorithm');
    }
  }

  static Pointer _createHandle(String algorithm) {
    final b = PqcBindings();
    final algPtr = algorithm.toNativeUtf8();
    final h = b.kemNew(algPtr);
    malloc.free(algPtr);
    return h;
  }

  /// Public key size in bytes.
  int get publicKeySize => _bindings.kemPublicKeySize(_handle);

  /// Secret key size in bytes.
  int get secretKeySize => _bindings.kemSecretKeySize(_handle);

  /// Ciphertext size in bytes.
  int get ciphertextSize => _bindings.kemCiphertextSize(_handle);

  /// Shared secret size in bytes.
  int get sharedSecretSize => _bindings.kemSharedSecretSize(_handle);

  /// NIST security level (1-5).
  int get securityLevel => _bindings.kemSecurityLevel(_handle);

  /// Generate a new keypair.
  KemKeyPair keygen() {
    final pk = malloc<Uint8>(publicKeySize);
    final sk = malloc<Uint8>(secretKeySize);
    try {
      final rc = _bindings.kemKeygen(_handle, pk, sk);
      if (rc != 0) {
        throw StateError('KEM keygen failed: ${_bindings.statusString(rc)}');
      }
      return KemKeyPair(
        Uint8List.fromList(pk.asTypedList(publicKeySize)),
        Uint8List.fromList(sk.asTypedList(secretKeySize)),
      );
    } finally {
      malloc.free(pk);
      malloc.free(sk);
    }
  }

  /// Encapsulate: generate shared secret and ciphertext from a public key.
  KemEncapsResult encaps(Uint8List publicKey) {
    if (publicKey.length != publicKeySize) {
      throw ArgumentError('Public key must be $publicKeySize bytes');
    }
    final ct = malloc<Uint8>(ciphertextSize);
    final ss = malloc<Uint8>(sharedSecretSize);
    final pkPtr = malloc<Uint8>(publicKey.length);
    pkPtr.asTypedList(publicKey.length).setAll(0, publicKey);
    try {
      final rc = _bindings.kemEncaps(_handle, ct, ss, pkPtr);
      if (rc != 0) {
        throw StateError('KEM encaps failed: ${_bindings.statusString(rc)}');
      }
      return KemEncapsResult(
        Uint8List.fromList(ct.asTypedList(ciphertextSize)),
        Uint8List.fromList(ss.asTypedList(sharedSecretSize)),
      );
    } finally {
      malloc.free(ct);
      malloc.free(ss);
      malloc.free(pkPtr);
    }
  }

  /// Decapsulate: recover shared secret from ciphertext using secret key.
  Uint8List decaps(Uint8List ciphertext, Uint8List secretKey) {
    if (ciphertext.length != ciphertextSize) {
      throw ArgumentError('Ciphertext must be $ciphertextSize bytes');
    }
    final ss = malloc<Uint8>(sharedSecretSize);
    final ctPtr = malloc<Uint8>(ciphertext.length);
    ctPtr.asTypedList(ciphertext.length).setAll(0, ciphertext);
    final skPtr = malloc<Uint8>(secretKey.length);
    skPtr.asTypedList(secretKey.length).setAll(0, secretKey);
    try {
      final rc = _bindings.kemDecaps(_handle, ss, ctPtr, skPtr);
      if (rc != 0) {
        throw StateError('KEM decaps failed: ${_bindings.statusString(rc)}');
      }
      return Uint8List.fromList(ss.asTypedList(sharedSecretSize));
    } finally {
      malloc.free(ss);
      malloc.free(ctPtr);
      malloc.free(skPtr);
    }
  }

  /// Free the native KEM context.
  void dispose() {
    _bindings.kemFree(_handle);
  }
}
