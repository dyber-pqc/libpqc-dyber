// libpqc-dyber - Post-Quantum Cryptography Library
// Copyright (c) 2024-2026 Dyber, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT

using System;
using System.Runtime.InteropServices;

namespace Dyber.PQC
{
    /// <summary>
    /// Key Encapsulation Mechanism (KEM) operations.
    /// </summary>
    public sealed class KEM : IDisposable
    {
        private IntPtr _handle;
        private bool _disposed;

        /// <summary>
        /// Create a KEM context for the specified algorithm.
        /// </summary>
        /// <param name="algorithm">Algorithm name, e.g. "ML-KEM-768".</param>
        /// <exception cref="ArgumentException">Thrown when the algorithm is not supported.</exception>
        public KEM(string algorithm)
        {
            _handle = NativeMethods.pqc_kem_new(algorithm);
            if (_handle == IntPtr.Zero)
                throw new ArgumentException($"Unsupported or disabled KEM algorithm: {algorithm}");
        }

        /// <summary>The algorithm name.</summary>
        public string AlgorithmName
        {
            get
            {
                ThrowIfDisposed();
                IntPtr ptr = NativeMethods.pqc_kem_algorithm(_handle);
                return Marshal.PtrToStringAnsi(ptr) ?? string.Empty;
            }
        }

        /// <summary>Public key size in bytes.</summary>
        public int PublicKeySize
        {
            get { ThrowIfDisposed(); return (int)(uint)NativeMethods.pqc_kem_public_key_size(_handle); }
        }

        /// <summary>Secret key size in bytes.</summary>
        public int SecretKeySize
        {
            get { ThrowIfDisposed(); return (int)(uint)NativeMethods.pqc_kem_secret_key_size(_handle); }
        }

        /// <summary>Ciphertext size in bytes.</summary>
        public int CiphertextSize
        {
            get { ThrowIfDisposed(); return (int)(uint)NativeMethods.pqc_kem_ciphertext_size(_handle); }
        }

        /// <summary>Shared secret size in bytes.</summary>
        public int SharedSecretSize
        {
            get { ThrowIfDisposed(); return (int)(uint)NativeMethods.pqc_kem_shared_secret_size(_handle); }
        }

        /// <summary>NIST security level (1-5).</summary>
        public int SecurityLevel
        {
            get { ThrowIfDisposed(); return NativeMethods.pqc_kem_security_level(_handle); }
        }

        /// <summary>
        /// Generate a new keypair.
        /// </summary>
        /// <returns>A tuple of (publicKey, secretKey) byte arrays.</returns>
        public (byte[] PublicKey, byte[] SecretKey) Keygen()
        {
            ThrowIfDisposed();
            byte[] pk = new byte[PublicKeySize];
            byte[] sk = new byte[SecretKeySize];
            int rc = NativeMethods.pqc_kem_keygen(_handle, pk, sk);
            if (rc != 0)
                throw new InvalidOperationException($"KEM keygen failed: {GetStatusString(rc)}");
            return (pk, sk);
        }

        /// <summary>
        /// Encapsulate: generate a shared secret and ciphertext from a public key.
        /// </summary>
        /// <param name="publicKey">Recipient's public key.</param>
        /// <returns>A tuple of (ciphertext, sharedSecret) byte arrays.</returns>
        public (byte[] Ciphertext, byte[] SharedSecret) Encaps(byte[] publicKey)
        {
            ThrowIfDisposed();
            if (publicKey == null) throw new ArgumentNullException(nameof(publicKey));
            if (publicKey.Length != PublicKeySize)
                throw new ArgumentException($"Public key must be {PublicKeySize} bytes.");

            byte[] ct = new byte[CiphertextSize];
            byte[] ss = new byte[SharedSecretSize];
            int rc = NativeMethods.pqc_kem_encaps(_handle, ct, ss, publicKey);
            if (rc != 0)
                throw new InvalidOperationException($"KEM encaps failed: {GetStatusString(rc)}");
            return (ct, ss);
        }

        /// <summary>
        /// Decapsulate: recover the shared secret from a ciphertext using the secret key.
        /// </summary>
        /// <param name="ciphertext">The ciphertext from encapsulation.</param>
        /// <param name="secretKey">The recipient's secret key.</param>
        /// <returns>The shared secret byte array.</returns>
        public byte[] Decaps(byte[] ciphertext, byte[] secretKey)
        {
            ThrowIfDisposed();
            if (ciphertext == null) throw new ArgumentNullException(nameof(ciphertext));
            if (secretKey == null) throw new ArgumentNullException(nameof(secretKey));
            if (ciphertext.Length != CiphertextSize)
                throw new ArgumentException($"Ciphertext must be {CiphertextSize} bytes.");
            if (secretKey.Length != SecretKeySize)
                throw new ArgumentException($"Secret key must be {SecretKeySize} bytes.");

            byte[] ss = new byte[SharedSecretSize];
            int rc = NativeMethods.pqc_kem_decaps(_handle, ss, ciphertext, secretKey);
            if (rc != 0)
                throw new InvalidOperationException($"KEM decaps failed: {GetStatusString(rc)}");
            return ss;
        }

        private static string GetStatusString(int status)
        {
            IntPtr ptr = NativeMethods.pqc_status_string(status);
            return ptr != IntPtr.Zero ? Marshal.PtrToStringAnsi(ptr) ?? "unknown error" : "unknown error";
        }

        private void ThrowIfDisposed()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(KEM));
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                if (_handle != IntPtr.Zero)
                {
                    NativeMethods.pqc_kem_free(_handle);
                    _handle = IntPtr.Zero;
                }
                _disposed = true;
            }
        }

        ~KEM() => Dispose();
    }
}
