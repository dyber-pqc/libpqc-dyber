// libpqc-dyber - Post-Quantum Cryptography Library
// Copyright (c) 2024-2026 Dyber, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT

import Foundation
import Cpqc

/// Digital signature operations.
public final class Signature {

    /// Signature keypair result.
    public struct KeyPair {
        public let publicKey: Data
        public let secretKey: Data
    }

    private let handle: OpaquePointer

    /// Create a Signature context for the specified algorithm.
    /// - Parameter algorithm: Algorithm name, e.g. "ML-DSA-65".
    /// - Throws: `PQCError.unsupportedAlgorithm` if the algorithm is not available.
    public init(algorithm: String) throws {
        guard let h = pqc_sig_new(algorithm) else {
            throw PQCError.unsupportedAlgorithm(algorithm)
        }
        self.handle = h
    }

    deinit {
        pqc_sig_free(handle)
    }

    /// The algorithm name.
    public var algorithm: String {
        String(cString: pqc_sig_algorithm(handle))
    }

    /// Public key size in bytes.
    public var publicKeySize: Int {
        pqc_sig_public_key_size(handle)
    }

    /// Secret key size in bytes.
    public var secretKeySize: Int {
        pqc_sig_secret_key_size(handle)
    }

    /// Maximum signature size in bytes.
    public var maxSignatureSize: Int {
        pqc_sig_max_signature_size(handle)
    }

    /// NIST security level (1-5).
    public var securityLevel: Int {
        Int(pqc_sig_security_level(handle))
    }

    /// Whether this is a stateful signature scheme.
    public var isStateful: Bool {
        pqc_sig_is_stateful(handle) != 0
    }

    /// Generate a new keypair.
    /// - Returns: A `KeyPair` containing the public and secret keys.
    /// - Throws: `PQCError.operationFailed` on failure.
    public func keygen() throws -> KeyPair {
        var pk = Data(count: publicKeySize)
        var sk = Data(count: secretKeySize)

        let rc = pk.withUnsafeMutableBytes { pkPtr in
            sk.withUnsafeMutableBytes { skPtr in
                pqc_sig_keygen(handle,
                               pkPtr.bindMemory(to: UInt8.self).baseAddress!,
                               skPtr.bindMemory(to: UInt8.self).baseAddress!)
            }
        }
        guard rc == 0 else { throw PQCError.operationFailed(rc) }
        return KeyPair(publicKey: pk, secretKey: sk)
    }

    /// Sign a message.
    /// - Parameters:
    ///   - message: The message to sign.
    ///   - secretKey: The signer's secret key.
    /// - Returns: The signature as `Data`.
    /// - Throws: `PQCError.operationFailed` on failure.
    public func sign(message: Data, secretKey: Data) throws -> Data {
        var sigBuf = Data(count: maxSignatureSize)
        var sigLen = maxSignatureSize

        let rc = sigBuf.withUnsafeMutableBytes { sigPtr in
            message.withUnsafeBytes { msgPtr in
                secretKey.withUnsafeBytes { skPtr in
                    pqc_sig_sign(handle,
                                 sigPtr.bindMemory(to: UInt8.self).baseAddress!,
                                 &sigLen,
                                 msgPtr.bindMemory(to: UInt8.self).baseAddress!,
                                 message.count,
                                 skPtr.bindMemory(to: UInt8.self).baseAddress!)
                }
            }
        }
        guard rc == 0 else { throw PQCError.operationFailed(rc) }
        return sigBuf.prefix(sigLen)
    }

    /// Verify a signature.
    /// - Parameters:
    ///   - message: The message that was signed.
    ///   - signature: The signature to verify.
    ///   - publicKey: The signer's public key.
    /// - Returns: `true` if the signature is valid.
    public func verify(message: Data, signature: Data, publicKey: Data) -> Bool {
        let rc = message.withUnsafeBytes { msgPtr in
            signature.withUnsafeBytes { sigPtr in
                publicKey.withUnsafeBytes { pkPtr in
                    pqc_sig_verify(handle,
                                   msgPtr.bindMemory(to: UInt8.self).baseAddress!,
                                   message.count,
                                   sigPtr.bindMemory(to: UInt8.self).baseAddress!,
                                   signature.count,
                                   pkPtr.bindMemory(to: UInt8.self).baseAddress!)
                }
            }
        }
        return rc == 0
    }
}
