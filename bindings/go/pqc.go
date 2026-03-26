// libpqc-dyber - Post-Quantum Cryptography Library
// Copyright (c) 2024-2026 Dyber, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT

// Package pqc provides Go bindings for the libpqc-dyber post-quantum
// cryptography library.
//
// Call Init() before using any other functions, and Cleanup() when done.
package pqc

/*
#cgo LDFLAGS: -lpqc
#cgo pkg-config: libpqc
#include <pqc/pqc.h>
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// StatusCode represents a pqc_status_t error code.
type StatusCode int

const (
	StatusOK                   StatusCode = 0
	StatusError                StatusCode = -1
	StatusInvalidArgument      StatusCode = -2
	StatusAlloc                StatusCode = -3
	StatusNotSupported         StatusCode = -4
	StatusInvalidKey           StatusCode = -5
	StatusVerificationFailed   StatusCode = -6
	StatusDecapsulationFailed  StatusCode = -7
	StatusRNGFailed            StatusCode = -8
	StatusBufferTooSmall       StatusCode = -9
	StatusInternal             StatusCode = -10
	StatusStateExhausted       StatusCode = -11
)

// PQCError wraps a non-OK status code from the C library.
type PQCError struct {
	Code    StatusCode
	Message string
}

func (e *PQCError) Error() string {
	return fmt.Sprintf("pqc: %s (code %d)", e.Message, e.Code)
}

// statusToError converts a pqc_status_t into a Go error. Returns nil for PQC_OK.
func statusToError(status C.pqc_status_t) error {
	if status == C.PQC_OK {
		return nil
	}
	msg := C.GoString(C.pqc_status_string(status))
	return &PQCError{
		Code:    StatusCode(status),
		Message: msg,
	}
}

// Init initializes the libpqc library. Must be called before any other
// operations.
func Init() error {
	return statusToError(C.pqc_init())
}

// Cleanup releases library resources. Should be called when done.
func Cleanup() {
	C.pqc_cleanup()
}

// Version returns the version string of the underlying C library.
func Version() string {
	return C.GoString(C.pqc_version())
}

// VersionMajor returns the major version number.
func VersionMajor() int {
	return int(C.pqc_version_major())
}

// VersionMinor returns the minor version number.
func VersionMinor() int {
	return int(C.pqc_version_minor())
}

// VersionPatch returns the patch version number.
func VersionPatch() int {
	return int(C.pqc_version_patch())
}

// SecurityLevel represents a NIST security category (1-5).
type SecurityLevel int

const (
	SecurityLevel1 SecurityLevel = 1
	SecurityLevel2 SecurityLevel = 2
	SecurityLevel3 SecurityLevel = 3
	SecurityLevel4 SecurityLevel = 4
	SecurityLevel5 SecurityLevel = 5
)

// KEMAlgorithmCount returns the number of available KEM algorithms.
func KEMAlgorithmCount() int {
	return int(C.pqc_kem_algorithm_count())
}

// KEMAlgorithmName returns the name of the KEM algorithm at the given index.
func KEMAlgorithmName(index int) string {
	p := C.pqc_kem_algorithm_name(C.int(index))
	if p == nil {
		return ""
	}
	return C.GoString(p)
}

// KEMIsEnabled returns true if the named KEM algorithm is enabled.
func KEMIsEnabled(algorithm string) bool {
	cAlg := C.CString(algorithm)
	defer C.free(unsafe.Pointer(cAlg))
	return C.pqc_kem_is_enabled(cAlg) != 0
}

// SigAlgorithmCount returns the number of available signature algorithms.
func SigAlgorithmCount() int {
	return int(C.pqc_sig_algorithm_count())
}

// SigAlgorithmName returns the name of the signature algorithm at the given index.
func SigAlgorithmName(index int) string {
	p := C.pqc_sig_algorithm_name(C.int(index))
	if p == nil {
		return ""
	}
	return C.GoString(p)
}

// SigIsEnabled returns true if the named signature algorithm is enabled.
func SigIsEnabled(algorithm string) bool {
	cAlg := C.CString(algorithm)
	defer C.free(unsafe.Pointer(cAlg))
	return C.pqc_sig_is_enabled(cAlg) != 0
}

// RandomBytes fills buf with cryptographically secure random bytes.
func RandomBytes(buf []byte) error {
	if len(buf) == 0 {
		return nil
	}
	return statusToError(C.pqc_randombytes((*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf))))
}
