// libpqc-dyber - Post-Quantum Cryptography Library
// Copyright (c) 2024-2026 Dyber, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT

import Foundation
import Cpqc

/// Post-Quantum Cryptography library namespace.
public enum PQCDyber {

    /// Library version string.
    public static var version: String {
        String(cString: pqc_version())
    }

    /// Library major version number.
    public static var versionMajor: Int {
        Int(pqc_version_major())
    }

    /// Library minor version number.
    public static var versionMinor: Int {
        Int(pqc_version_minor())
    }

    /// Library patch version number.
    public static var versionPatch: Int {
        Int(pqc_version_patch())
    }

    /// Initialize the library. Call once before using any other API.
    @discardableResult
    public static func initialize() -> Bool {
        pqc_init() == 0
    }

    /// Clean up library resources.
    public static func cleanup() {
        pqc_cleanup()
    }

    /// All available KEM algorithm names.
    public static var kemAlgorithms: [String] {
        let count = Int(pqc_kem_algorithm_count())
        return (0..<count).compactMap { i in
            guard let ptr = pqc_kem_algorithm_name(Int32(i)) else { return nil }
            return String(cString: ptr)
        }
    }

    /// All available signature algorithm names.
    public static var sigAlgorithms: [String] {
        let count = Int(pqc_sig_algorithm_count())
        return (0..<count).compactMap { i in
            guard let ptr = pqc_sig_algorithm_name(Int32(i)) else { return nil }
            return String(cString: ptr)
        }
    }
}
