// libpqc-dyber - Post-Quantum Cryptography Library
// Copyright (c) 2024-2026 Dyber, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT

using System;
using System.Runtime.InteropServices;

namespace Dyber.PQC
{
    /// <summary>
    /// Digital signature operations.
    /// </summary>
    public sealed class Signature : IDisposable
    {
        private IntPtr _handle;
        private bool _disposed;

        /// <summary>
        /// Create a Signature context for the specified algorithm.
        /// </summary>
        /// <param name="algorithm">Algorithm name, e.g. "ML-DSA-65".</param>
        /// <exception cref="ArgumentException">Thrown when the algorithm is not supported.</exception>
        public Signature(string algorithm)
        {
            _handle = NativeMethods.pqc_sig_new(algorithm);
            if (_handle == IntPtr.Zero)
                throw new ArgumentException($"Unsupported or disabled signature algorithm: {algorithm}");
        }

        /// <summary>The algorithm name.</summary>
        public string AlgorithmName
        {
            get
            {
                ThrowIfDisposed();
                IntPtr ptr = NativeMethods.pqc_sig_algorithm(_handle);
                return Marshal.PtrToStringAnsi(ptr) ?? string.Empty;
            }
        }

        /// <summary>Public key size in bytes.</summary>
        public int PublicKeySize
        {
            get { ThrowIfDisposed(); return (int)(uint)NativeMethods.pqc_sig_public_key_size(_handle); }
        }

        /// <summary>Secret key size in bytes.</summary>
        public int SecretKeySize
        {
            get { ThrowIfDisposed(); return (int)(uint)NativeMethods.pqc_sig_secret_key_size(_handle); }
        }

        /// <summary>Maximum signature size in bytes.</summary>
        public int MaxSignatureSize
        {
            get { ThrowIfDisposed(); return (int)(uint)NativeMethods.pqc_sig_max_signature_size(_handle); }
        }

        /// <summary>NIST security level (1-5).</summary>
        public int SecurityLevel
        {
            get { ThrowIfDisposed(); return NativeMethods.pqc_sig_security_level(_handle); }
        }

        /// <summary>Whether this is a stateful signature algorithm.</summary>
        public bool IsStateful
        {
            get { ThrowIfDisposed(); return NativeMethods.pqc_sig_is_stateful(_handle) != 0; }
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
            int rc = NativeMethods.pqc_sig_keygen(_handle, pk, sk);
            if (rc != 0)
                throw new InvalidOperationException($"Signature keygen failed: {GetStatusString(rc)}");
            return (pk, sk);
        }

        /// <summary>
        /// Sign a message.
        /// </summary>
        /// <param name="message">The message to sign.</param>
        /// <param name="secretKey">The signer's secret key.</param>
        /// <returns>The signature byte array (trimmed to actual length).</returns>
        public byte[] Sign(byte[] message, byte[] secretKey)
        {
            ThrowIfDisposed();
            if (message == null) throw new ArgumentNullException(nameof(message));
            if (secretKey == null) throw new ArgumentNullException(nameof(secretKey));
            if (secretKey.Length != SecretKeySize)
                throw new ArgumentException($"Secret key must be {SecretKeySize} bytes.");

            byte[] sig = new byte[MaxSignatureSize];
            UIntPtr sigLen = (UIntPtr)sig.Length;
            int rc = NativeMethods.pqc_sig_sign(_handle, sig, ref sigLen,
                message, (UIntPtr)message.Length, secretKey);
            if (rc != 0)
                throw new InvalidOperationException($"Signature sign failed: {GetStatusString(rc)}");

            int actualLen = (int)(uint)sigLen;
            if (actualLen < sig.Length)
            {
                byte[] trimmed = new byte[actualLen];
                Array.Copy(sig, trimmed, actualLen);
                return trimmed;
            }
            return sig;
        }

        /// <summary>
        /// Verify a signature.
        /// </summary>
        /// <param name="message">The message that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="publicKey">The signer's public key.</param>
        /// <returns>True if the signature is valid, false otherwise.</returns>
        public bool Verify(byte[] message, byte[] signature, byte[] publicKey)
        {
            ThrowIfDisposed();
            if (message == null) throw new ArgumentNullException(nameof(message));
            if (signature == null) throw new ArgumentNullException(nameof(signature));
            if (publicKey == null) throw new ArgumentNullException(nameof(publicKey));
            if (publicKey.Length != PublicKeySize)
                throw new ArgumentException($"Public key must be {PublicKeySize} bytes.");

            int rc = NativeMethods.pqc_sig_verify(_handle, message, (UIntPtr)message.Length,
                signature, (UIntPtr)signature.Length, publicKey);
            return rc == 0; // PQC_OK
        }

        private static string GetStatusString(int status)
        {
            IntPtr ptr = NativeMethods.pqc_status_string(status);
            return ptr != IntPtr.Zero ? Marshal.PtrToStringAnsi(ptr) ?? "unknown error" : "unknown error";
        }

        private void ThrowIfDisposed()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(Signature));
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                if (_handle != IntPtr.Zero)
                {
                    NativeMethods.pqc_sig_free(_handle);
                    _handle = IntPtr.Zero;
                }
                _disposed = true;
            }
        }

        ~Signature() => Dispose();
    }
}
