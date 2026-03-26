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

// Sig wraps a PQC_SIG context for digital signature operations.
type Sig struct {
	ctx *C.PQC_SIG
}

// NewSig creates a new signature context for the specified algorithm.
// Returns an error if the algorithm is not supported.
func NewSig(algorithm string) (*Sig, error) {
	cAlg := C.CString(algorithm)
	defer C.free(unsafe.Pointer(cAlg))

	ctx := C.pqc_sig_new(cAlg)
	if ctx == nil {
		return nil, &PQCError{Code: StatusNotSupported, Message: "unsupported signature algorithm: " + algorithm}
	}

	s := &Sig{ctx: ctx}
	runtime.SetFinalizer(s, (*Sig).Close)
	return s, nil
}

// Close releases the signature context. It is safe to call multiple times.
func (s *Sig) Close() {
	if s.ctx != nil {
		C.pqc_sig_free(s.ctx)
		s.ctx = nil
	}
}

// Algorithm returns the algorithm name.
func (s *Sig) Algorithm() string {
	return C.GoString(C.pqc_sig_algorithm(s.ctx))
}

// PublicKeySize returns the size of a public key in bytes.
func (s *Sig) PublicKeySize() int {
	return int(C.pqc_sig_public_key_size(s.ctx))
}

// SecretKeySize returns the size of a secret key in bytes.
func (s *Sig) SecretKeySize() int {
	return int(C.pqc_sig_secret_key_size(s.ctx))
}

// MaxSignatureSize returns the maximum possible signature size in bytes.
func (s *Sig) MaxSignatureSize() int {
	return int(C.pqc_sig_max_signature_size(s.ctx))
}

// SecurityLevel returns the NIST security level (1-5).
func (s *Sig) SecurityLevel() SecurityLevel {
	return SecurityLevel(C.pqc_sig_security_level(s.ctx))
}

// IsStateful returns true if this is a stateful signature scheme (e.g., LMS, XMSS).
func (s *Sig) IsStateful() bool {
	return C.pqc_sig_is_stateful(s.ctx) != 0
}

// Keygen generates a new keypair and returns (publicKey, secretKey).
func (s *Sig) Keygen() (publicKey, secretKey []byte, err error) {
	pkLen := s.PublicKeySize()
	skLen := s.SecretKeySize()

	publicKey = make([]byte, pkLen)
	secretKey = make([]byte, skLen)

	status := C.pqc_sig_keygen(
		s.ctx,
		(*C.uint8_t)(unsafe.Pointer(&publicKey[0])),
		(*C.uint8_t)(unsafe.Pointer(&secretKey[0])),
	)
	if err = statusToError(status); err != nil {
		return nil, nil, err
	}
	return publicKey, secretKey, nil
}

// Sign signs a message using the given secret key.
// Returns the signature bytes.
func (s *Sig) Sign(message, secretKey []byte) (signature []byte, err error) {
	if len(secretKey) != s.SecretKeySize() {
		return nil, &PQCError{Code: StatusInvalidArgument, Message: "invalid secret key length"}
	}

	maxSig := s.MaxSignatureSize()
	signature = make([]byte, maxSig)
	var sigLen C.size_t

	var msgPtr *C.uint8_t
	if len(message) > 0 {
		msgPtr = (*C.uint8_t)(unsafe.Pointer(&message[0]))
	}

	status := C.pqc_sig_sign(
		s.ctx,
		(*C.uint8_t)(unsafe.Pointer(&signature[0])),
		&sigLen,
		msgPtr,
		C.size_t(len(message)),
		(*C.uint8_t)(unsafe.Pointer(&secretKey[0])),
	)
	if err = statusToError(status); err != nil {
		return nil, err
	}
	return signature[:sigLen], nil
}

// Verify verifies a signature on a message using the given public key.
// Returns nil if the signature is valid, or an error otherwise.
func (s *Sig) Verify(message, signature, publicKey []byte) error {
	if len(publicKey) != s.PublicKeySize() {
		return &PQCError{Code: StatusInvalidArgument, Message: "invalid public key length"}
	}

	var msgPtr *C.uint8_t
	if len(message) > 0 {
		msgPtr = (*C.uint8_t)(unsafe.Pointer(&message[0]))
	}

	status := C.pqc_sig_verify(
		s.ctx,
		msgPtr,
		C.size_t(len(message)),
		(*C.uint8_t)(unsafe.Pointer(&signature[0])),
		C.size_t(len(signature)),
		(*C.uint8_t)(unsafe.Pointer(&publicKey[0])),
	)
	return statusToError(status)
}

// SignStateful signs a message using a stateful secret key. The secretKey
// slice is modified in-place to advance the internal state.
// Only valid for stateful algorithms (LMS, XMSS).
func (s *Sig) SignStateful(message, secretKey []byte) (signature []byte, err error) {
	if len(secretKey) != s.SecretKeySize() {
		return nil, &PQCError{Code: StatusInvalidArgument, Message: "invalid secret key length"}
	}

	maxSig := s.MaxSignatureSize()
	signature = make([]byte, maxSig)
	var sigLen C.size_t

	var msgPtr *C.uint8_t
	if len(message) > 0 {
		msgPtr = (*C.uint8_t)(unsafe.Pointer(&message[0]))
	}

	status := C.pqc_sig_sign_stateful(
		s.ctx,
		(*C.uint8_t)(unsafe.Pointer(&signature[0])),
		&sigLen,
		msgPtr,
		C.size_t(len(message)),
		(*C.uint8_t)(unsafe.Pointer(&secretKey[0])),
	)
	if err = statusToError(status); err != nil {
		return nil, err
	}
	return signature[:sigLen], nil
}
