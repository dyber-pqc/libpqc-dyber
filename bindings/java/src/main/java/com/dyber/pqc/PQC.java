/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

package com.dyber.pqc;

/**
 * Entry point for the libpqc-dyber post-quantum cryptography library.
 *
 * <p>Call {@link #init()} before using any other PQC classes, and
 * {@link #cleanup()} when finished.</p>
 *
 * <pre>{@code
 * PQC.init();
 * try {
 *     KEM kem = new KEM("ML-KEM-768");
 *     // ... use kem ...
 *     kem.close();
 * } finally {
 *     PQC.cleanup();
 * }
 * }</pre>
 */
public final class PQC {

    static {
        loadNativeLibrary();
    }

    private PQC() {
        // non-instantiable
    }

    private static void loadNativeLibrary() {
        try {
            System.loadLibrary("pqc_jni");
        } catch (UnsatisfiedLinkError e) {
            // Try loading from java.library.path with platform prefix
            try {
                System.loadLibrary("libpqc_jni");
            } catch (UnsatisfiedLinkError e2) {
                throw new UnsatisfiedLinkError(
                    "Failed to load pqc_jni native library. "
                    + "Ensure it is on java.library.path: " + e.getMessage());
            }
        }
    }

    // ---- Native methods ----

    /**
     * Initialize the library. Must be called before any other operations.
     *
     * @throws PQCException if initialization fails
     */
    public static void init() throws PQCException {
        int status = nativeInit();
        if (status != 0) {
            throw new PQCException(status, nativeStatusString(status));
        }
    }

    /**
     * Clean up library resources.
     */
    public static void cleanup() {
        nativeCleanup();
    }

    /**
     * Return the version string of the underlying C library.
     */
    public static String version() {
        return nativeVersion();
    }

    /**
     * Return the major version number.
     */
    public static int versionMajor() {
        return nativeVersionMajor();
    }

    /**
     * Return the minor version number.
     */
    public static int versionMinor() {
        return nativeVersionMinor();
    }

    /**
     * Return the patch version number.
     */
    public static int versionPatch() {
        return nativeVersionPatch();
    }

    /**
     * Return the number of available KEM algorithms.
     */
    public static int kemAlgorithmCount() {
        return nativeKemAlgorithmCount();
    }

    /**
     * Return the name of the KEM algorithm at the given index.
     */
    public static String kemAlgorithmName(int index) {
        return nativeKemAlgorithmName(index);
    }

    /**
     * Return true if the named KEM algorithm is enabled.
     */
    public static boolean kemIsEnabled(String algorithm) {
        return nativeKemIsEnabled(algorithm);
    }

    /**
     * Return the number of available signature algorithms.
     */
    public static int sigAlgorithmCount() {
        return nativeSigAlgorithmCount();
    }

    /**
     * Return the name of the signature algorithm at the given index.
     */
    public static String sigAlgorithmName(int index) {
        return nativeSigAlgorithmName(index);
    }

    /**
     * Return true if the named signature algorithm is enabled.
     */
    public static boolean sigIsEnabled(String algorithm) {
        return nativeSigIsEnabled(algorithm);
    }

    /**
     * Generate cryptographically secure random bytes.
     *
     * @param length number of bytes to generate
     * @return random bytes
     * @throws PQCException if the RNG fails
     */
    public static byte[] randomBytes(int length) throws PQCException {
        return nativeRandomBytes(length);
    }

    /**
     * Convert a status code to a human-readable string.
     */
    static String statusString(int status) {
        return nativeStatusString(status);
    }

    // ---- JNI native declarations ----

    private static native int nativeInit();
    private static native void nativeCleanup();
    private static native String nativeVersion();
    private static native int nativeVersionMajor();
    private static native int nativeVersionMinor();
    private static native int nativeVersionPatch();
    private static native String nativeStatusString(int status);
    private static native int nativeKemAlgorithmCount();
    private static native String nativeKemAlgorithmName(int index);
    private static native boolean nativeKemIsEnabled(String algorithm);
    private static native int nativeSigAlgorithmCount();
    private static native String nativeSigAlgorithmName(int index);
    private static native boolean nativeSigIsEnabled(String algorithm);
    private static native byte[] nativeRandomBytes(int length);

    // KEM native methods (used by KEM class)
    static native long nativeKemNew(String algorithm);
    static native void nativeKemFree(long handle);
    static native String nativeKemAlgorithm(long handle);
    static native int nativeKemPublicKeySize(long handle);
    static native int nativeKemSecretKeySize(long handle);
    static native int nativeKemCiphertextSize(long handle);
    static native int nativeKemSharedSecretSize(long handle);
    static native int nativeKemSecurityLevel(long handle);
    static native byte[][] nativeKemKeygen(long handle);
    static native byte[][] nativeKemEncaps(long handle, byte[] publicKey);
    static native byte[] nativeKemDecaps(long handle, byte[] ciphertext, byte[] secretKey);

    // Signature native methods (used by Signature class)
    static native long nativeSigNew(String algorithm);
    static native void nativeSigFree(long handle);
    static native String nativeSigAlgorithm(long handle);
    static native int nativeSigPublicKeySize(long handle);
    static native int nativeSigSecretKeySize(long handle);
    static native int nativeSigMaxSignatureSize(long handle);
    static native int nativeSigSecurityLevel(long handle);
    static native boolean nativeSigIsStateful(long handle);
    static native byte[][] nativeSigKeygen(long handle);
    static native byte[] nativeSigSign(long handle, byte[] message, byte[] secretKey);
    static native int nativeSigVerify(long handle, byte[] message, byte[] signature, byte[] publicKey);
}
