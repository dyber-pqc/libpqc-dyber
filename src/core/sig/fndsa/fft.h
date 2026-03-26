/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * FN-DSA (FIPS 206) -- FFT over complex numbers (double precision).
 *
 * Representation: polynomials of degree < n = 2^logn are stored as
 * arrays of n doubles.  In the FFT domain the representation is
 * "half-complex":  for a real polynomial f of degree < n, the FFT
 * representation stores n/2 complex values as
 *     f[0..n/2-1]   = real parts
 *     f[n/2..n-1]   = imaginary parts
 * This is the standard Falcon "fpr" layout.
 */

#ifndef PQC_FNDSA_FFT_H
#define PQC_FNDSA_FFT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Forward split-radix FFT.
 * Input: polynomial f of degree < n stored in f[0..n-1] (real coefficients).
 * Output: f is replaced by its FFT representation (half-complex layout).
 */
void fndsa_fft_forward(double *f, unsigned logn);

/*
 * Inverse FFT.
 * Input: f in FFT (half-complex) representation.
 * Output: f[0..n-1] contains the real polynomial coefficients.
 */
void fndsa_fft_inverse(double *f, unsigned logn);

/*
 * Pointwise complex multiply: a[i] *= b[i] in FFT domain.
 */
void fndsa_fft_mul(double *a, const double *b, unsigned logn);

/*
 * Pointwise add: a[i] += b[i].
 */
void fndsa_fft_add(double *a, const double *b, unsigned logn);

/*
 * Pointwise sub: a[i] -= b[i].
 */
void fndsa_fft_sub(double *a, const double *b, unsigned logn);

/*
 * Pointwise negate: a[i] = -a[i].
 */
void fndsa_fft_neg(double *a, unsigned logn);

/*
 * Complex conjugate of each FFT coefficient: a[i] = conj(a[i]).
 * In the half-complex layout this means negating the imaginary half.
 */
void fndsa_fft_adj(double *a, unsigned logn);

/*
 * Pointwise multiply by conjugate of b:  a[i] *= conj(b[i]).
 */
void fndsa_fft_mul_adj(double *a, const double *b, unsigned logn);

/*
 * Pointwise multiply a by its own conjugate (self-adjoint product):
 *     a[i] = |a[i]|^2     (result is real, imag part set to 0).
 */
void fndsa_fft_mul_selfadj(double *a, unsigned logn);

/*
 * Pointwise multiply in FFT domain (same as fndsa_fft_mul, second name
 * kept for clarity in call-sites that emphasise "both operands are in FFT
 * domain").
 */
void fndsa_fft_mul_fft(double *a, const double *b, unsigned logn);

/*
 * Compute the squared Euclidean norm of a polynomial in FFT domain.
 * This is sum of |a[i]|^2 over all n/2 complex entries (then doubled
 * because of the half-complex representation).
 */
double fndsa_fft_norm(const double *a, unsigned logn);

/*
 * Pointwise inverse: a[i] = 1/a[i] in FFT domain.
 */
void fndsa_fft_inv(double *a, unsigned logn);

/*
 * Pointwise divide: a[i] /= b[i] in FFT domain.
 */
void fndsa_fft_div(double *a, const double *b, unsigned logn);

/*
 * Scale (multiply by real scalar): a[i] *= s.
 */
void fndsa_fft_scale(double *a, double s, unsigned logn);

#ifdef __cplusplus
}
#endif

#endif /* PQC_FNDSA_FFT_H */
