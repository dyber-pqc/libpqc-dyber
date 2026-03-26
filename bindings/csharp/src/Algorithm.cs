// libpqc-dyber - Post-Quantum Cryptography Library
// Copyright (c) 2024-2026 Dyber, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Dyber.PQC
{
    /// <summary>
    /// Algorithm listing and query utilities.
    /// </summary>
    public static class Algorithm
    {
        // KEM algorithm constants
        public const string MlKem512 = "ML-KEM-512";
        public const string MlKem768 = "ML-KEM-768";
        public const string MlKem1024 = "ML-KEM-1024";
        public const string Hqc128 = "HQC-128";
        public const string Hqc192 = "HQC-192";
        public const string Hqc256 = "HQC-256";
        public const string BikeL1 = "BIKE-L1";
        public const string BikeL3 = "BIKE-L3";
        public const string BikeL5 = "BIKE-L5";

        // Signature algorithm constants
        public const string MlDsa44 = "ML-DSA-44";
        public const string MlDsa65 = "ML-DSA-65";
        public const string MlDsa87 = "ML-DSA-87";
        public const string SlhDsaSha2128s = "SLH-DSA-SHA2-128s";
        public const string SlhDsaSha2128f = "SLH-DSA-SHA2-128f";
        public const string FnDsa512 = "FN-DSA-512";
        public const string FnDsa1024 = "FN-DSA-1024";

        // Hybrid algorithm constants
        public const string MlKem768X25519 = "ML-KEM-768+X25519";
        public const string MlKem1024P256 = "ML-KEM-1024+P256";
        public const string MlDsa65Ed25519 = "ML-DSA-65+Ed25519";
        public const string MlDsa87P256 = "ML-DSA-87+P256";

        /// <summary>
        /// Returns a list of all enabled KEM algorithm names.
        /// </summary>
        public static IReadOnlyList<string> GetKemAlgorithms()
        {
            int count = NativeMethods.pqc_kem_algorithm_count();
            var list = new List<string>(count);
            for (int i = 0; i < count; i++)
            {
                IntPtr ptr = NativeMethods.pqc_kem_algorithm_name(i);
                if (ptr != IntPtr.Zero)
                    list.Add(Marshal.PtrToStringAnsi(ptr)!);
            }
            return list;
        }

        /// <summary>
        /// Returns a list of all enabled signature algorithm names.
        /// </summary>
        public static IReadOnlyList<string> GetSignatureAlgorithms()
        {
            int count = NativeMethods.pqc_sig_algorithm_count();
            var list = new List<string>(count);
            for (int i = 0; i < count; i++)
            {
                IntPtr ptr = NativeMethods.pqc_sig_algorithm_name(i);
                if (ptr != IntPtr.Zero)
                    list.Add(Marshal.PtrToStringAnsi(ptr)!);
            }
            return list;
        }

        /// <summary>
        /// Returns true if the given KEM algorithm is enabled.
        /// </summary>
        public static bool IsKemEnabled(string algorithm) =>
            NativeMethods.pqc_kem_is_enabled(algorithm) != 0;

        /// <summary>
        /// Returns true if the given signature algorithm is enabled.
        /// </summary>
        public static bool IsSignatureEnabled(string algorithm) =>
            NativeMethods.pqc_sig_is_enabled(algorithm) != 0;

        /// <summary>
        /// Returns the library version string.
        /// </summary>
        public static string GetVersion()
        {
            IntPtr ptr = NativeMethods.pqc_version();
            return Marshal.PtrToStringAnsi(ptr) ?? "unknown";
        }
    }
}
