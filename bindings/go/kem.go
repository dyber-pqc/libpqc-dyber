// libpqc-dyber - Post-Quantum Cryptography Library
// Copyright (c) 2024-2026 Dyber, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT

package pqc

/*
#include <pqc/pqc.h>
#include <stdlib.h>
*/
import "C"
import (
	"runtime"
	"unsafe"
)

// KEM wraps a PQC_KEM context for key encapsulation operations.
type KEM struct {
	ctx *C.PQC_KEM
}

// NewKEM creates a new KEM context for the specified algorithm.
// Returns an error if the algorithm is not supported.
func NewKEM(algorithm string) (*KEM, error) {
	cAlg := C.CString(algorithm)
	defer C.free(unsafe.Pointer(cAlg))

	ctx := C.pqc_kem_new(cAlg)
	if ctx == nil {
		return nil, &PQCError{Code: StatusNotSupported, Message: "unsupported KEM algorithm: " + algorithm}
	}

	k := &KEM{ctx: ctx}
	runtime.SetFinalizer(k, (*KEM).Close)
	return k, nil
}

// Close releases the KEM context. It is safe to call multiple times.
func (k *KEM) Close() {
	if k.ctx != nil {
		C.pqc_kem_free(k.ctx)
		k.ctx = nil
	}
}

// Algorithm returns the algorithm name.
func (k *KEM) Algorithm() string {
	return C.GoString(C.pqc_kem_algorithm(k.ctx))
}

// PublicKeySize returns the size of a public key in bytes.
func (k *KEM) PublicKeySize() int {
	return int(C.pqc_kem_public_key_size(k.ctx))
}

// SecretKeySize returns the size of a secret key in bytes.
func (k *KEM) SecretKeySize() int {
	return int(C.pqc_kem_secret_key_size(k.ctx))
}

// CiphertextSize returns the size of a ciphertext in bytes.
func (k *KEM) CiphertextSize() int {
	return int(C.pqc_kem_ciphertext_size(k.ctx))
}

// SharedSecretSize returns the size of the shared secret in bytes.
func (k *KEM) SharedSecretSize() int {
	return int(C.pqc_kem_shared_secret_size(k.ctx))
}

// SecurityLevel returns the NIST security level (1-5).
func (k *KEM) SecurityLevel() SecurityLevel {
	return SecurityLevel(C.pqc_kem_security_level(k.ctx))
}

// Keygen generates a new keypair and returns (publicKey, secretKey).
func (k *KEM) Keygen() (publicKey, secretKey []byte, err error) {
	pkLen := k.PublicKeySize()
	skLen := k.SecretKeySize()

	publicKey = make([]byte, pkLen)
	secretKey = make([]byte, skLen)

	status := C.pqc_kem_keygen(
		k.ctx,
		(*C.uint8_t)(unsafe.Pointer(&publicKey[0])),
		(*C.uint8_t)(unsafe.Pointer(&secretKey[0])),
	)
	if err = statusToError(status); err != nil {
		return nil, nil, err
	}
	return publicKey, secretKey, nil
}

// Encaps encapsulates a shared secret using the given public key.
// Returns (ciphertext, sharedSecret).
func (k *KEM) Encaps(publicKey []byte) (ciphertext, sharedSecret []byte, err error) {
	if len(publicKey) != k.PublicKeySize() {
		return nil, nil, &PQCError{Code: StatusInvalidArgument, Message: "invalid public key length"}
	}

	ctLen := k.CiphertextSize()
	ssLen := k.SharedSecretSize()

	ciphertext = make([]byte, ctLen)
	sharedSecret = make([]byte, ssLen)

	status := C.pqc_kem_encaps(
		k.ctx,
		(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])),
		(*C.uint8_t)(unsafe.Pointer(&sharedSecret[0])),
		(*C.uint8_t)(unsafe.Pointer(&publicKey[0])),
	)
	if err = statusToError(status); err != nil {
		return nil, nil, err
	}
	return ciphertext, sharedSecret, nil
}

// Decaps decapsulates a ciphertext using the given secret key to recover the
// shared secret.
func (k *KEM) Decaps(ciphertext, secretKey []byte) (sharedSecret []byte, err error) {
	if len(ciphertext) != k.CiphertextSize() {
		return nil, &PQCError{Code: StatusInvalidArgument, Message: "invalid ciphertext length"}
	}
	if len(secretKey) != k.SecretKeySize() {
		return nil, &PQCError{Code: StatusInvalidArgument, Message: "invalid secret key length"}
	}

	ssLen := k.SharedSecretSize()
	sharedSecret = make([]byte, ssLen)

	status := C.pqc_kem_decaps(
		k.ctx,
		(*C.uint8_t)(unsafe.Pointer(&sharedSecret[0])),
		(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])),
		(*C.uint8_t)(unsafe.Pointer(&secretKey[0])),
	)
	if err = statusToError(status); err != nil {
		return nil, err
	}
	return sharedSecret, nil
}
