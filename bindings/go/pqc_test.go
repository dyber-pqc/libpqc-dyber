// libpqc-dyber - Post-Quantum Cryptography Library
// Copyright (c) 2024-2026 Dyber, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT

package pqc

import (
	"bytes"
	"testing"
)

func TestInit(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Cleanup()
}

func TestVersion(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Cleanup()

	v := Version()
	if v == "" {
		t.Fatal("Version() returned empty string")
	}
	t.Logf("libpqc version: %s", v)
}

func TestKEMAlgorithmEnumeration(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Cleanup()

	count := KEMAlgorithmCount()
	if count == 0 {
		t.Fatal("no KEM algorithms available")
	}

	for i := 0; i < count; i++ {
		name := KEMAlgorithmName(i)
		if name == "" {
			t.Errorf("KEM algorithm at index %d has empty name", i)
		}
	}
}

func TestSigAlgorithmEnumeration(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Cleanup()

	count := SigAlgorithmCount()
	if count == 0 {
		t.Fatal("no signature algorithms available")
	}

	for i := 0; i < count; i++ {
		name := SigAlgorithmName(i)
		if name == "" {
			t.Errorf("Sig algorithm at index %d has empty name", i)
		}
	}
}

func TestKEMRoundTrip(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Cleanup()

	algorithms := []string{"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}
	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			kem, err := NewKEM(alg)
			if err != nil {
				t.Fatalf("NewKEM(%q) failed: %v", alg, err)
			}
			defer kem.Close()

			if kem.Algorithm() != alg {
				t.Errorf("Algorithm() = %q, want %q", kem.Algorithm(), alg)
			}

			pk, sk, err := kem.Keygen()
			if err != nil {
				t.Fatalf("Keygen failed: %v", err)
			}
			if len(pk) != kem.PublicKeySize() {
				t.Errorf("pk length = %d, want %d", len(pk), kem.PublicKeySize())
			}
			if len(sk) != kem.SecretKeySize() {
				t.Errorf("sk length = %d, want %d", len(sk), kem.SecretKeySize())
			}

			ct, ssEnc, err := kem.Encaps(pk)
			if err != nil {
				t.Fatalf("Encaps failed: %v", err)
			}
			if len(ct) != kem.CiphertextSize() {
				t.Errorf("ct length = %d, want %d", len(ct), kem.CiphertextSize())
			}

			ssDec, err := kem.Decaps(ct, sk)
			if err != nil {
				t.Fatalf("Decaps failed: %v", err)
			}

			if !bytes.Equal(ssEnc, ssDec) {
				t.Fatal("shared secrets do not match")
			}
		})
	}
}

func TestKEMUnsupportedAlgorithm(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Cleanup()

	_, err := NewKEM("NONEXISTENT-KEM")
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}

func TestKEMInvalidKeySize(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Cleanup()

	kem, err := NewKEM("ML-KEM-768")
	if err != nil {
		t.Fatalf("NewKEM failed: %v", err)
	}
	defer kem.Close()

	_, _, err = kem.Encaps([]byte{0x01, 0x02, 0x03})
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}
}

func TestSigRoundTrip(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Cleanup()

	algorithms := []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}
	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			sig, err := NewSig(alg)
			if err != nil {
				t.Fatalf("NewSig(%q) failed: %v", alg, err)
			}
			defer sig.Close()

			if sig.Algorithm() != alg {
				t.Errorf("Algorithm() = %q, want %q", sig.Algorithm(), alg)
			}
			if sig.IsStateful() {
				t.Error("ML-DSA should not be stateful")
			}

			pk, sk, err := sig.Keygen()
			if err != nil {
				t.Fatalf("Keygen failed: %v", err)
			}
			if len(pk) != sig.PublicKeySize() {
				t.Errorf("pk length = %d, want %d", len(pk), sig.PublicKeySize())
			}

			message := []byte("test message for " + alg)
			signature, err := sig.Sign(message, sk)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}
			if len(signature) > sig.MaxSignatureSize() {
				t.Errorf("signature length %d exceeds max %d", len(signature), sig.MaxSignatureSize())
			}

			if err := sig.Verify(message, signature, pk); err != nil {
				t.Fatalf("Verify failed: %v", err)
			}
		})
	}
}

func TestSigVerifyWrongMessage(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Cleanup()

	sig, err := NewSig("ML-DSA-65")
	if err != nil {
		t.Fatalf("NewSig failed: %v", err)
	}
	defer sig.Close()

	pk, sk, err := sig.Keygen()
	if err != nil {
		t.Fatalf("Keygen failed: %v", err)
	}

	signature, err := sig.Sign([]byte("correct message"), sk)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if err := sig.Verify([]byte("wrong message"), signature, pk); err == nil {
		t.Fatal("expected verification to fail with wrong message")
	}
}

func TestSigUnsupportedAlgorithm(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Cleanup()

	_, err := NewSig("NONEXISTENT-SIG")
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}

func TestHybridAlgorithms(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Cleanup()

	kemAlgs := HybridKEMAlgorithms()
	t.Logf("hybrid KEM algorithms: %v", kemAlgs)

	sigAlgs := HybridSigAlgorithms()
	t.Logf("hybrid sig algorithms: %v", sigAlgs)
}

func TestRandomBytes(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Cleanup()

	buf := make([]byte, 32)
	if err := RandomBytes(buf); err != nil {
		t.Fatalf("RandomBytes failed: %v", err)
	}

	// Extremely unlikely to be all zeros
	allZero := true
	for _, b := range buf {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("RandomBytes returned all zeros")
	}
}
