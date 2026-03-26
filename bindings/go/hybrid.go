// libpqc-dyber - Post-Quantum Cryptography Library
// Copyright (c) 2024-2026 Dyber, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT

package pqc

/*
#include <pqc/pqc.h>
*/
import "C"

// HybridKEMAlgorithms returns the names of all available hybrid KEM algorithms.
// Hybrid schemes combine a post-quantum algorithm with a classical one
// (e.g., "ML-KEM-768+X25519"). Use NewKEM with the returned name to create
// a KEM context for a hybrid scheme.
func HybridKEMAlgorithms() []string {
	count := int(C.pqc_hybrid_kem_count())
	names := make([]string, 0, count)
	for i := 0; i < count; i++ {
		p := C.pqc_hybrid_kem_name(C.int(i))
		if p != nil {
			names = append(names, C.GoString(p))
		}
	}
	return names
}

// HybridSigAlgorithms returns the names of all available hybrid signature algorithms.
// Use NewSig with the returned name to create a signature context for a hybrid scheme.
func HybridSigAlgorithms() []string {
	count := int(C.pqc_hybrid_sig_count())
	names := make([]string, 0, count)
	for i := 0; i < count; i++ {
		p := C.pqc_hybrid_sig_name(C.int(i))
		if p != nil {
			names = append(names, C.GoString(p))
		}
	}
	return names
}
