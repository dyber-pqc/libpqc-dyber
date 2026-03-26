// libpqc-dyber - Post-Quantum Cryptography Library
// Copyright (c) 2024-2026 Dyber, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT

import Foundation
import Cpqc

/// Key Encapsulation Mechanism (KEM) operations.
public final class KEM {

    /// KEM keypair result.
    public struct KeyPair {
        public let publicKey: Data
        public let secretKey: Data
    }

    /// KEM encapsulation result.
    public struct EncapsResult {
        public let ciphertext: Data
        public let sharedSecret: Data
    }

    private let handle: OpaquePointer

    /// Create a KEM context for the specified algorithm.
    /// - Parameter algorithm: Algorithm name, e.g. "ML-KEM-768".
    /// - Throws: `PQCError.unsupportedAlgorithm` if the algorithm is not available.
    public init(algorithm: String) throws {
        guard let h = pqc_kem_new(algorithm) else {
            throw PQCError.unsupportedAlgorithm(algorithm)
        }
        self.handle = h
    }

    deinit {
        pqc_kem_free(handle)
    }

    /// The algorithm name.
    public var algorithm: String {
        String(cString: pqc_kem_algorithm(handle))
    }

    /// Public key size in bytes.
    public var publicKeySize: Int {
        pqc_kem_public_key_size(handle)
    }

    /// Secret key size in bytes.
    public var secretKeySize: Int {
        pqc_kem_secret_key_size(handle)
    }

    /// Ciphertext size in bytes.
    public var ciphertextSize: Int {
        pqc_kem_ciphertext_size(handle)
    }

    /// Shared secret size in bytes.
    public var sharedSecretSize: Int {
        pqc_kem_shared_secret_size(handle)
    }

    /// NIST security level (1-5).
    public var securityLevel: Int {
        Int(pqc_kem_security_level(handle))
    }

    /// Generate a new keypair.
    /// - Returns: A `KeyPair` containing the public and secret keys.
    /// - Throws: `PQCError.operationFailed` on failure.
    public func keygen() throws -> KeyPair {
        var pk = Data(count: publicKeySize)
        var sk = Data(count: secretKeySize)

        let rc = pk.withUnsafeMutableBytes { pkPtr in
            sk.withUnsafeMutableBytes { skPtr in
                pqc_kem_keygen(handle,
                               pkPtr.bindMemory(to: UInt8.self).baseAddress!,
                               skPtr.bindMemory(to: UInt8.self).baseAddress!)
            }
        }
        guard rc == 0 else { throw PQCError.operationFailed(rc) }
        return KeyPair(publicKey: pk, secretKey: sk)
    }

    /// Encapsulate: generate shared secret and ciphertext from a public key.
    /// - Parameter publicKey: The recipient's public key.
    /// - Returns: An `EncapsResult` with ciphertext and shared secret.
    /// - Throws: `PQCError.operationFailed` on failure.
    public func encaps(publicKey: Data) throws -> EncapsResult {
        var ct = Data(count: ciphertextSize)
        var ss = Data(count: sharedSecretSize)

        let rc = ct.withUnsafeMutableBytes { ctPtr in
            ss.withUnsafeMutableBytes { ssPtr in
                publicKey.withUnsafeBytes { pkPtr in
                    pqc_kem_encaps(handle,
                                   ctPtr.bindMemory(to: UInt8.self).baseAddress!,
                                   ssPtr.bindMemory(to: UInt8.self).baseAddress!,
                                   pkPtr.bindMemory(to: UInt8.self).baseAddress!)
                }
            }
        }
        guard rc == 0 else { throw PQCError.operationFailed(rc) }
        return EncapsResult(ciphertext: ct, sharedSecret: ss)
    }

    /// Decapsulate: recover shared secret from ciphertext using secret key.
    /// - Parameters:
    ///   - ciphertext: The ciphertext from encapsulation.
    ///   - secretKey: The recipient's secret key.
    /// - Returns: The shared secret as `Data`.
    /// - Throws: `PQCError.operationFailed` on failure.
    public func decaps(ciphertext: Data, secretKey: Data) throws -> Data {
        var ss = Data(count: sharedSecretSize)

        let rc = ss.withUnsafeMutableBytes { ssPtr in
            ciphertext.withUnsafeBytes { ctPtr in
                secretKey.withUnsafeBytes { skPtr in
                    pqc_kem_decaps(handle,
                                   ssPtr.bindMemory(to: UInt8.self).baseAddress!,
                                   ctPtr.bindMemory(to: UInt8.self).baseAddress!,
                                   skPtr.bindMemory(to: UInt8.self).baseAddress!)
                }
            }
        }
        guard rc == 0 else { throw PQCError.operationFailed(rc) }
        return ss
    }
}

/// Errors from PQC operations.
public enum PQCError: Error, LocalizedError {
    case unsupportedAlgorithm(String)
    case operationFailed(Int32)

    public var errorDescription: String? {
        switch self {
        case .unsupportedAlgorithm(let name):
            return "Unsupported algorithm: \(name)"
        case .operationFailed(let code):
            if let ptr = pqc_status_string(code) {
                return String(cString: ptr)
            }
            return "PQC operation failed with code \(code)"
        }
    }
}
