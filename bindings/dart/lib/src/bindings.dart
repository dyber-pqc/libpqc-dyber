// libpqc-dyber - Post-Quantum Cryptography Library
// Copyright (c) 2024-2026 Dyber, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT

import 'dart:ffi';
import 'dart:io' show Platform;
import 'package:ffi/ffi.dart';

/// FFI bindings to the native libpqc C library.
class PqcBindings {
  static PqcBindings? _instance;
  final DynamicLibrary _lib;

  PqcBindings._(this._lib) {
    _pqcInit();
  }

  /// Get the singleton instance.
  factory PqcBindings() {
    _instance ??= PqcBindings._(_openLibrary());
    return _instance!;
  }

  static DynamicLibrary _openLibrary() {
    if (Platform.isWindows) return DynamicLibrary.open('pqc.dll');
    if (Platform.isMacOS) return DynamicLibrary.open('libpqc.dylib');
    return DynamicLibrary.open('libpqc.so');
  }

  // Version
  late final _pqcVersion = _lib.lookupFunction<Pointer<Utf8> Function(), Pointer<Utf8> Function()>('pqc_version');
  String version() => _pqcVersion().toDartString();

  // Init / cleanup
  late final _pqcInit = _lib.lookupFunction<Int32 Function(), int Function()>('pqc_init');
  late final _pqcCleanup = _lib.lookupFunction<Void Function(), void Function()>('pqc_cleanup');
  void cleanup() => _pqcCleanup();

  // Status string
  late final _pqcStatusString = _lib.lookupFunction<Pointer<Utf8> Function(Int32), Pointer<Utf8> Function(int)>('pqc_status_string');
  String statusString(int status) => _pqcStatusString(status).toDartString();

  // KEM algorithm enumeration
  late final _kemAlgorithmCount = _lib.lookupFunction<Int32 Function(), int Function()>('pqc_kem_algorithm_count');
  late final _kemAlgorithmName = _lib.lookupFunction<Pointer<Utf8> Function(Int32), Pointer<Utf8> Function(int)>('pqc_kem_algorithm_name');

  int kemAlgorithmCount() => _kemAlgorithmCount();
  String kemAlgorithmName(int index) => _kemAlgorithmName(index).toDartString();

  List<String> kemAlgorithms() {
    final count = kemAlgorithmCount();
    return List.generate(count, kemAlgorithmName);
  }

  // Sig algorithm enumeration
  late final _sigAlgorithmCount = _lib.lookupFunction<Int32 Function(), int Function()>('pqc_sig_algorithm_count');
  late final _sigAlgorithmName = _lib.lookupFunction<Pointer<Utf8> Function(Int32), Pointer<Utf8> Function(int)>('pqc_sig_algorithm_name');

  int sigAlgorithmCount() => _sigAlgorithmCount();
  String sigAlgorithmName(int index) => _sigAlgorithmName(index).toDartString();

  List<String> sigAlgorithms() {
    final count = sigAlgorithmCount();
    return List.generate(count, sigAlgorithmName);
  }

  // KEM context
  late final kemNew = _lib.lookupFunction<Pointer Function(Pointer<Utf8>), Pointer Function(Pointer<Utf8>)>('pqc_kem_new');
  late final kemFree = _lib.lookupFunction<Void Function(Pointer), void Function(Pointer)>('pqc_kem_free');
  late final kemPublicKeySize = _lib.lookupFunction<IntPtr Function(Pointer), int Function(Pointer)>('pqc_kem_public_key_size');
  late final kemSecretKeySize = _lib.lookupFunction<IntPtr Function(Pointer), int Function(Pointer)>('pqc_kem_secret_key_size');
  late final kemCiphertextSize = _lib.lookupFunction<IntPtr Function(Pointer), int Function(Pointer)>('pqc_kem_ciphertext_size');
  late final kemSharedSecretSize = _lib.lookupFunction<IntPtr Function(Pointer), int Function(Pointer)>('pqc_kem_shared_secret_size');
  late final kemSecurityLevel = _lib.lookupFunction<Int32 Function(Pointer), int Function(Pointer)>('pqc_kem_security_level');
  late final kemKeygen = _lib.lookupFunction<Int32 Function(Pointer, Pointer<Uint8>, Pointer<Uint8>), int Function(Pointer, Pointer<Uint8>, Pointer<Uint8>)>('pqc_kem_keygen');
  late final kemEncaps = _lib.lookupFunction<Int32 Function(Pointer, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>), int Function(Pointer, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>)>('pqc_kem_encaps');
  late final kemDecaps = _lib.lookupFunction<Int32 Function(Pointer, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>), int Function(Pointer, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>)>('pqc_kem_decaps');

  // Sig context
  late final sigNew = _lib.lookupFunction<Pointer Function(Pointer<Utf8>), Pointer Function(Pointer<Utf8>)>('pqc_sig_new');
  late final sigFree = _lib.lookupFunction<Void Function(Pointer), void Function(Pointer)>('pqc_sig_free');
  late final sigPublicKeySize = _lib.lookupFunction<IntPtr Function(Pointer), int Function(Pointer)>('pqc_sig_public_key_size');
  late final sigSecretKeySize = _lib.lookupFunction<IntPtr Function(Pointer), int Function(Pointer)>('pqc_sig_secret_key_size');
  late final sigMaxSignatureSize = _lib.lookupFunction<IntPtr Function(Pointer), int Function(Pointer)>('pqc_sig_max_signature_size');
  late final sigSecurityLevel = _lib.lookupFunction<Int32 Function(Pointer), int Function(Pointer)>('pqc_sig_security_level');
  late final sigIsStateful = _lib.lookupFunction<Int32 Function(Pointer), int Function(Pointer)>('pqc_sig_is_stateful');
  late final sigKeygen = _lib.lookupFunction<Int32 Function(Pointer, Pointer<Uint8>, Pointer<Uint8>), int Function(Pointer, Pointer<Uint8>, Pointer<Uint8>)>('pqc_sig_keygen');
  late final sigSign = _lib.lookupFunction<Int32 Function(Pointer, Pointer<Uint8>, Pointer<IntPtr>, Pointer<Uint8>, IntPtr, Pointer<Uint8>), int Function(Pointer, Pointer<Uint8>, Pointer<IntPtr>, Pointer<Uint8>, int, Pointer<Uint8>)>('pqc_sig_sign');
  late final sigVerify = _lib.lookupFunction<Int32 Function(Pointer, Pointer<Uint8>, IntPtr, Pointer<Uint8>, IntPtr, Pointer<Uint8>), int Function(Pointer, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>)>('pqc_sig_verify');
}
