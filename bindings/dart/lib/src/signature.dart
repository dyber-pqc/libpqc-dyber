// libpqc-dyber - Post-Quantum Cryptography Library
// Copyright (c) 2024-2026 Dyber, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT

import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'bindings.dart';

/// Signature keypair result.
class SigKeyPair {
  final Uint8List publicKey;
  final Uint8List secretKey;
  SigKeyPair(this.publicKey, this.secretKey);
}

/// Digital signature operations.
class Sig {
  final PqcBindings _bindings;
  final Pointer _handle;
  final String algorithm;

  /// Create a Signature context for the specified algorithm.
  ///
  /// Throws [ArgumentError] if the algorithm is not supported.
  Sig(this.algorithm) : _bindings = PqcBindings(), _handle = _createHandle(algorithm) {
    if (_handle == nullptr) {
      throw ArgumentError('Unsupported signature algorithm: $algorithm');
    }
  }

  static Pointer _createHandle(String algorithm) {
    final b = PqcBindings();
    final algPtr = algorithm.toNativeUtf8();
    final h = b.sigNew(algPtr);
    malloc.free(algPtr);
    return h;
  }

  /// Public key size in bytes.
  int get publicKeySize => _bindings.sigPublicKeySize(_handle);

  /// Secret key size in bytes.
  int get secretKeySize => _bindings.sigSecretKeySize(_handle);

  /// Maximum signature size in bytes.
  int get maxSignatureSize => _bindings.sigMaxSignatureSize(_handle);

  /// NIST security level (1-5).
  int get securityLevel => _bindings.sigSecurityLevel(_handle);

  /// Whether this is a stateful signature scheme.
  bool get isStateful => _bindings.sigIsStateful(_handle) != 0;

  /// Generate a new keypair.
  SigKeyPair keygen() {
    final pk = malloc<Uint8>(publicKeySize);
    final sk = malloc<Uint8>(secretKeySize);
    try {
      final rc = _bindings.sigKeygen(_handle, pk, sk);
      if (rc != 0) {
        throw StateError('Signature keygen failed: ${_bindings.statusString(rc)}');
      }
      return SigKeyPair(
        Uint8List.fromList(pk.asTypedList(publicKeySize)),
        Uint8List.fromList(sk.asTypedList(secretKeySize)),
      );
    } finally {
      malloc.free(pk);
      malloc.free(sk);
    }
  }

  /// Sign a message.
  Uint8List sign(Uint8List message, Uint8List secretKey) {
    if (secretKey.length != secretKeySize) {
      throw ArgumentError('Secret key must be $secretKeySize bytes');
    }
    final sigBuf = malloc<Uint8>(maxSignatureSize);
    final sigLen = malloc<IntPtr>(1);
    sigLen.value = maxSignatureSize;
    final msgPtr = malloc<Uint8>(message.length);
    msgPtr.asTypedList(message.length).setAll(0, message);
    final skPtr = malloc<Uint8>(secretKey.length);
    skPtr.asTypedList(secretKey.length).setAll(0, secretKey);
    try {
      final rc = _bindings.sigSign(_handle, sigBuf, sigLen.cast(), msgPtr, message.length, skPtr);
      if (rc != 0) {
        throw StateError('Signature sign failed: ${_bindings.statusString(rc)}');
      }
      final actualLen = sigLen.value;
      return Uint8List.fromList(sigBuf.asTypedList(actualLen));
    } finally {
      malloc.free(sigBuf);
      malloc.free(sigLen);
      malloc.free(msgPtr);
      malloc.free(skPtr);
    }
  }

  /// Verify a signature.
  bool verify(Uint8List message, Uint8List signature, Uint8List publicKey) {
    if (publicKey.length != publicKeySize) {
      throw ArgumentError('Public key must be $publicKeySize bytes');
    }
    final msgPtr = malloc<Uint8>(message.length);
    msgPtr.asTypedList(message.length).setAll(0, message);
    final sigPtr = malloc<Uint8>(signature.length);
    sigPtr.asTypedList(signature.length).setAll(0, signature);
    final pkPtr = malloc<Uint8>(publicKey.length);
    pkPtr.asTypedList(publicKey.length).setAll(0, publicKey);
    try {
      final rc = _bindings.sigVerify(_handle, msgPtr, message.length, sigPtr, signature.length, pkPtr);
      return rc == 0;
    } finally {
      malloc.free(msgPtr);
      malloc.free(sigPtr);
      malloc.free(pkPtr);
    }
  }

  /// Free the native signature context.
  void dispose() {
    _bindings.sigFree(_handle);
  }
}
