// libpqc-dyber - Post-Quantum Cryptography Library
// Copyright (c) 2024-2026 Dyber, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Go binding benchmarks for all PQC algorithms.
// Run with: go test -bench=. -benchmem -timeout 30m

package pqc

import (
	"testing"
)

func BenchmarkKEM(b *testing.B) {
	for _, name := range KEMAlgorithmNames() {
		kem, err := NewKEM(name)
		if err != nil {
			continue
		}

		b.Run(name+"/keygen", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _, err := kem.Keygen()
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		pk, sk, err := kem.Keygen()
		if err != nil {
			continue
		}

		b.Run(name+"/encaps", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _, err := kem.Encaps(pk)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		ct, _, err := kem.Encaps(pk)
		if err != nil {
			continue
		}

		b.Run(name+"/decaps", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := kem.Decaps(ct, sk)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		kem.Free()
	}
}

func BenchmarkSignature(b *testing.B) {
	msg := make([]byte, 1024)
	for i := range msg {
		msg[i] = byte(i*137 + 42)
	}

	for _, name := range SigAlgorithmNames() {
		sig, err := NewSignature(name)
		if err != nil {
			continue
		}

		if sig.IsStateful() {
			sig.Free()
			continue
		}

		b.Run(name+"/keygen", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _, err := sig.Keygen()
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		pk, sk, err := sig.Keygen()
		if err != nil {
			sig.Free()
			continue
		}

		b.Run(name+"/sign_1KB", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := sig.Sign(msg, sk)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		signature, err := sig.Sign(msg, sk)
		if err != nil {
			sig.Free()
			continue
		}

		b.Run(name+"/verify_1KB", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				err := sig.Verify(msg, signature, pk)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		sig.Free()
	}
}
