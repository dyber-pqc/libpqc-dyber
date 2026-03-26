// libpqc-dyber - Post-Quantum Cryptography Library
// Copyright (c) 2024-2026 Dyber, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT

using System;
using System.Runtime.InteropServices;

namespace Dyber.PQC
{
    /// <summary>
    /// P/Invoke declarations for the native libpqc C library.
    /// </summary>
    internal static class NativeMethods
    {
        private const string LibName = "pqc";

        // ------------------------------------------------------------------ //
        // Library lifecycle
        // ------------------------------------------------------------------ //

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pqc_init();

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void pqc_cleanup();

        // ------------------------------------------------------------------ //
        // Version
        // ------------------------------------------------------------------ //

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr pqc_version();

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pqc_version_major();

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pqc_version_minor();

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pqc_version_patch();

        // ------------------------------------------------------------------ //
        // Status
        // ------------------------------------------------------------------ //

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr pqc_status_string(int status);

        // ------------------------------------------------------------------ //
        // Algorithm enumeration
        // ------------------------------------------------------------------ //

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pqc_kem_algorithm_count();

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr pqc_kem_algorithm_name(int index);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pqc_kem_is_enabled(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string algorithm);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pqc_sig_algorithm_count();

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr pqc_sig_algorithm_name(int index);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pqc_sig_is_enabled(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string algorithm);

        // ------------------------------------------------------------------ //
        // KEM context
        // ------------------------------------------------------------------ //

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr pqc_kem_new(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string algorithm);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void pqc_kem_free(IntPtr kem);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr pqc_kem_algorithm(IntPtr kem);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr pqc_kem_public_key_size(IntPtr kem);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr pqc_kem_secret_key_size(IntPtr kem);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr pqc_kem_ciphertext_size(IntPtr kem);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr pqc_kem_shared_secret_size(IntPtr kem);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pqc_kem_security_level(IntPtr kem);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pqc_kem_keygen(IntPtr kem, byte[] public_key, byte[] secret_key);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pqc_kem_encaps(IntPtr kem, byte[] ciphertext,
            byte[] shared_secret, byte[] public_key);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pqc_kem_decaps(IntPtr kem, byte[] shared_secret,
            byte[] ciphertext, byte[] secret_key);

        // ------------------------------------------------------------------ //
        // Signature context
        // ------------------------------------------------------------------ //

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr pqc_sig_new(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string algorithm);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void pqc_sig_free(IntPtr sig);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr pqc_sig_algorithm(IntPtr sig);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr pqc_sig_public_key_size(IntPtr sig);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr pqc_sig_secret_key_size(IntPtr sig);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr pqc_sig_max_signature_size(IntPtr sig);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pqc_sig_security_level(IntPtr sig);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pqc_sig_is_stateful(IntPtr sig);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pqc_sig_keygen(IntPtr sig, byte[] public_key, byte[] secret_key);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pqc_sig_sign(IntPtr sig, byte[] signature,
            ref UIntPtr signature_len, byte[] message, UIntPtr message_len, byte[] secret_key);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pqc_sig_verify(IntPtr sig, byte[] message,
            UIntPtr message_len, byte[] signature, UIntPtr signature_len, byte[] public_key);

        // ------------------------------------------------------------------ //
        // Secure memory
        // ------------------------------------------------------------------ //

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void pqc_memzero(byte[] ptr, UIntPtr size);
    }
}
