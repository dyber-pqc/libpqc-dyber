/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

package com.dyber.pqc;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the KEM and Signature Java bindings.
 */
class KEMTest {

    @BeforeAll
    static void setUp() throws PQCException {
        PQC.init();
    }

    @AfterAll
    static void tearDown() {
        PQC.cleanup();
    }

    @Test
    void testVersion() {
        String version = PQC.version();
        assertNotNull(version);
        assertFalse(version.isEmpty());
    }

    @Test
    void testKemAlgorithmEnumeration() {
        int count = PQC.kemAlgorithmCount();
        assertTrue(count > 0, "should have at least one KEM algorithm");

        for (int i = 0; i < count; i++) {
            String name = PQC.kemAlgorithmName(i);
            assertNotNull(name);
            assertFalse(name.isEmpty());
        }
    }

    @Test
    void testSigAlgorithmEnumeration() {
        int count = PQC.sigAlgorithmCount();
        assertTrue(count > 0, "should have at least one signature algorithm");

        for (int i = 0; i < count; i++) {
            String name = PQC.sigAlgorithmName(i);
            assertNotNull(name);
            assertFalse(name.isEmpty());
        }
    }

    @Test
    void testMlKem768RoundTrip() throws PQCException {
        try (KEM kem = new KEM(Algorithm.ML_KEM_768)) {
            assertEquals("ML-KEM-768", kem.algorithm());
            assertTrue(kem.publicKeySize() > 0);
            assertTrue(kem.secretKeySize() > 0);
            assertTrue(kem.ciphertextSize() > 0);
            assertTrue(kem.sharedSecretSize() > 0);

            KEM.KeyPair kp = kem.keygen();
            assertNotNull(kp.publicKey);
            assertNotNull(kp.secretKey);
            assertEquals(kem.publicKeySize(), kp.publicKey.length);
            assertEquals(kem.secretKeySize(), kp.secretKey.length);

            KEM.EncapsResult enc = kem.encaps(kp.publicKey);
            assertNotNull(enc.ciphertext);
            assertNotNull(enc.sharedSecret);
            assertEquals(kem.ciphertextSize(), enc.ciphertext.length);
            assertEquals(kem.sharedSecretSize(), enc.sharedSecret.length);

            byte[] ss = kem.decaps(enc.ciphertext, kp.secretKey);
            assertNotNull(ss);
            assertArrayEquals(enc.sharedSecret, ss);
        }
    }

    @Test
    void testMlKem512RoundTrip() throws PQCException {
        try (KEM kem = new KEM(Algorithm.ML_KEM_512)) {
            KEM.KeyPair kp = kem.keygen();
            KEM.EncapsResult enc = kem.encaps(kp.publicKey);
            byte[] ss = kem.decaps(enc.ciphertext, kp.secretKey);
            assertArrayEquals(enc.sharedSecret, ss);
        }
    }

    @Test
    void testMlKem1024RoundTrip() throws PQCException {
        try (KEM kem = new KEM(Algorithm.ML_KEM_1024)) {
            KEM.KeyPair kp = kem.keygen();
            KEM.EncapsResult enc = kem.encaps(kp.publicKey);
            byte[] ss = kem.decaps(enc.ciphertext, kp.secretKey);
            assertArrayEquals(enc.sharedSecret, ss);
        }
    }

    @Test
    void testKemUnsupportedAlgorithm() {
        assertThrows(PQCException.class, () -> new KEM("NONEXISTENT-KEM"));
    }

    @Test
    void testKemInvalidKeySize() throws PQCException {
        try (KEM kem = new KEM(Algorithm.ML_KEM_768)) {
            assertThrows(PQCException.class, () -> kem.encaps(new byte[10]));
        }
    }

    @Test
    void testKemSecurityLevel() throws PQCException {
        try (KEM kem = new KEM(Algorithm.ML_KEM_768)) {
            int level = kem.securityLevel();
            assertTrue(level >= 1 && level <= 5);
        }
    }

    @Test
    void testMlDsa65RoundTrip() throws PQCException {
        try (Signature sig = new Signature(Algorithm.ML_DSA_65)) {
            assertEquals("ML-DSA-65", sig.algorithm());
            assertFalse(sig.isStateful());

            Signature.KeyPair kp = sig.keygen();
            assertNotNull(kp.publicKey);
            assertNotNull(kp.secretKey);
            assertEquals(sig.publicKeySize(), kp.publicKey.length);
            assertEquals(sig.secretKeySize(), kp.secretKey.length);

            byte[] message = "test message for ML-DSA-65".getBytes();
            byte[] signature = sig.sign(message, kp.secretKey);
            assertNotNull(signature);
            assertTrue(signature.length <= sig.maxSignatureSize());

            assertTrue(sig.verify(message, signature, kp.publicKey));
        }
    }

    @Test
    void testSigVerifyWrongMessage() throws PQCException {
        try (Signature sig = new Signature(Algorithm.ML_DSA_65)) {
            Signature.KeyPair kp = sig.keygen();
            byte[] signature = sig.sign("correct message".getBytes(), kp.secretKey);
            assertFalse(sig.verify("wrong message".getBytes(), signature, kp.publicKey));
        }
    }

    @Test
    void testSigUnsupportedAlgorithm() {
        assertThrows(PQCException.class, () -> new Signature("NONEXISTENT-SIG"));
    }

    @Test
    void testRandomBytes() throws PQCException {
        byte[] buf = PQC.randomBytes(32);
        assertNotNull(buf);
        assertEquals(32, buf.length);

        // Check not all zeros (extremely unlikely for 32 random bytes)
        boolean allZero = true;
        for (byte b : buf) {
            if (b != 0) { allZero = false; break; }
        }
        assertFalse(allZero, "random bytes should not be all zeros");
    }

    @Test
    void testKemClosedContext() throws PQCException {
        KEM kem = new KEM(Algorithm.ML_KEM_768);
        kem.close();
        assertThrows(IllegalStateException.class, kem::algorithm);
    }

    @Test
    void testSigClosedContext() throws PQCException {
        Signature sig = new Signature(Algorithm.ML_DSA_65);
        sig.close();
        assertThrows(IllegalStateException.class, sig::algorithm);
    }
}
