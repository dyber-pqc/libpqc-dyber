/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * FN-DSA (FIPS 206) -- FFT over complex numbers (double precision).
 *
 * This implements the FFT for the ring Z[x]/(x^n + 1) with n a power
 * of two.  The evaluation points are w_k = exp(i*pi*(2k+1)/n) for
 * k = 0..n/2-1.
 *
 * Half-complex layout: for a polynomial of degree < n, the FFT
 * representation stores n/2 complex values as:
 *   f[0..n/2-1]   = real parts
 *   f[n/2..n-1]   = imaginary parts
 *
 * Implementation: direct evaluation and interpolation.
 * For the small sizes used in Falcon (n <= 1024) this is efficient
 * enough and avoids complex butterfly logic or deep recursion.
 */

#include <math.h>
#include <string.h>
#include "fft.h"
#include "fndsa_params.h"

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* ------------------------------------------------------------------ */
/* Forward FFT: direct evaluation at the roots of x^n + 1              */
/* ------------------------------------------------------------------ */

/*
 * Evaluate the polynomial f(x) = sum_{j=0}^{n-1} f[j] * x^j
 * at the n/2 roots  w_k = exp(i*pi*(2k+1)/n), k = 0..n/2-1.
 *
 * Store in half-complex layout:
 *   f[k]      = Re( f(w_k) )
 *   f[k+n/2]  = Im( f(w_k) )
 */
void
fndsa_fft_forward(double *f, unsigned logn)
{
    size_t n = (size_t)1 << logn;
    size_t hn = n >> 1;
    size_t i, j;
    double out_re[FNDSA_MAX_N / 2];
    double out_im[FNDSA_MAX_N / 2];

    if (logn == 0)
        return;

    /*
     * For each evaluation point w_k, compute f(w_k) using Horner's method.
     * w_k = exp(i*pi*(2k+1)/n).
     */
    for (i = 0; i < hn; i++) {
        double angle = M_PI * (double)(2 * i + 1) / (double)n;
        double w_re = cos(angle);
        double w_im = sin(angle);

        /* Horner: start from the highest coefficient. */
        double acc_re = f[n - 1];
        double acc_im = 0.0;
        for (j = n - 1; j > 0; j--) {
            /* acc = acc * w + f[j-1] */
            double new_re = acc_re * w_re - acc_im * w_im + f[j - 1];
            double new_im = acc_re * w_im + acc_im * w_re;
            acc_re = new_re;
            acc_im = new_im;
        }

        out_re[i] = acc_re;
        out_im[i] = acc_im;
    }

    for (i = 0; i < hn; i++) {
        f[i]      = out_re[i];
        f[i + hn] = out_im[i];
    }
}

/* ------------------------------------------------------------------ */
/* Inverse FFT: interpolation from the evaluation points               */
/* ------------------------------------------------------------------ */

/*
 * Given the evaluations F[k] = f(w_k) in half-complex layout,
 * recover the polynomial coefficients f[0..n-1].
 *
 * The inverse is:
 *   f[j] = (1/n) * sum_{k=0}^{n/2-1}  2 * Re( F[k] * conj(w_k^j) )
 *
 * Actually, since f is real and we evaluate at the n/2 roots of x^n+1
 * that are in the upper half-plane (with their conjugates being the
 * other n/2 roots), the reconstruction is:
 *
 *   f[j] = (2/(n)) * sum_{k=0}^{n/2-1} Re( F[k] * w_k^{-j} )
 *
 * But we need to be careful about the exact formulation.  Using the
 * orthogonality of roots of x^n+1:
 *
 *   f[j] = (2/n) * sum_{k=0}^{n/2-1} Re( F[k] * conj(w_k)^j )
 *
 * where conj(w_k)^j = exp(-i*pi*j*(2k+1)/n).
 *
 * However the simplest correct approach: solve the system directly.
 * For the small sizes we use (n <= 1024), direct computation works.
 */
void
fndsa_fft_inverse(double *f, unsigned logn)
{
    size_t n = (size_t)1 << logn;
    size_t hn = n >> 1;
    size_t i, j;
    double coeffs[FNDSA_MAX_N];
    double inv_hn = 1.0 / (double)hn;

    if (logn == 0)
        return;

    /*
     * Reconstruct f[j] from the evaluations.
     * Using the fact that  sum_{k=0}^{hn-1} w_k^m = 0  for m not
     * divisible by n, and = hn * (-1)^{m/n}  for m divisible by n:
     *
     *   f[j] = (1/hn) * sum_{k=0}^{hn-1} Re(F[k] * w_k^{-j})
     *
     * where F[k] = f[k] + i*f[k+hn]  and  w_k^{-j} = exp(-i*pi*j*(2k+1)/n).
     *
     * Since f[j] is real, we have:
     *   f[j] = (1/hn) * sum_k [ Re(F[k]) * cos(theta) + Im(F[k]) * sin(theta) ]
     * where theta = -pi * j * (2k+1) / n = pi * j * (2k+1) / n  (with sign from conj).
     *
     * Actually: w_k^{-j} = exp(-i * pi * j * (2k+1) / n)
     *   Re(F * w^{-j}) = Re(F) * cos(theta) + Im(F) * sin(theta)
     *   where theta = pi * j * (2k+1) / n
     */
    for (j = 0; j < n; j++) {
        double sum = 0.0;
        for (i = 0; i < hn; i++) {
            double F_re = f[i];
            double F_im = f[i + hn];
            double theta = M_PI * (double)j * (double)(2 * i + 1) / (double)n;
            double c = cos(theta);
            double s = sin(theta);
            sum += F_re * c + F_im * s;
        }
        coeffs[j] = sum * inv_hn;
    }

    memcpy(f, coeffs, n * sizeof(double));
}

/* ------------------------------------------------------------------ */
/* Pointwise arithmetic in the half-complex FFT domain                  */
/* ------------------------------------------------------------------ */

void
fndsa_fft_add(double *a, const double *b, unsigned logn)
{
    size_t n = (size_t)1 << logn;
    size_t i;
    for (i = 0; i < n; i++)
        a[i] += b[i];
}

void
fndsa_fft_sub(double *a, const double *b, unsigned logn)
{
    size_t n = (size_t)1 << logn;
    size_t i;
    for (i = 0; i < n; i++)
        a[i] -= b[i];
}

void
fndsa_fft_neg(double *a, unsigned logn)
{
    size_t n = (size_t)1 << logn;
    size_t i;
    for (i = 0; i < n; i++)
        a[i] = -a[i];
}

void
fndsa_fft_adj(double *a, unsigned logn)
{
    size_t n = (size_t)1 << logn;
    size_t hn = n >> 1;
    size_t i;
    /* Negate imaginary parts = conjugate. */
    for (i = hn; i < n; i++)
        a[i] = -a[i];
}

void
fndsa_fft_mul(double *a, const double *b, unsigned logn)
{
    size_t n = (size_t)1 << logn;
    size_t hn = n >> 1;
    size_t i;
    for (i = 0; i < hn; i++) {
        double a_re = a[i];
        double a_im = a[i + hn];
        double b_re = b[i];
        double b_im = b[i + hn];
        a[i]      = a_re * b_re - a_im * b_im;
        a[i + hn] = a_re * b_im + a_im * b_re;
    }
}

void
fndsa_fft_mul_fft(double *a, const double *b, unsigned logn)
{
    fndsa_fft_mul(a, b, logn);
}

void
fndsa_fft_mul_adj(double *a, const double *b, unsigned logn)
{
    size_t n = (size_t)1 << logn;
    size_t hn = n >> 1;
    size_t i;
    for (i = 0; i < hn; i++) {
        double a_re = a[i];
        double a_im = a[i + hn];
        double b_re = b[i];
        double b_im = b[i + hn];
        a[i]      = a_re * b_re + a_im * b_im;
        a[i + hn] = a_im * b_re - a_re * b_im;
    }
}

void
fndsa_fft_mul_selfadj(double *a, unsigned logn)
{
    size_t n = (size_t)1 << logn;
    size_t hn = n >> 1;
    size_t i;
    for (i = 0; i < hn; i++) {
        double re = a[i];
        double im = a[i + hn];
        a[i]      = re * re + im * im;
        a[i + hn] = 0.0;
    }
}

double
fndsa_fft_norm(const double *a, unsigned logn)
{
    size_t n = (size_t)1 << logn;
    size_t hn = n >> 1;
    size_t i;
    double s = 0.0;
    for (i = 0; i < hn; i++) {
        double re = a[i];
        double im = a[i + hn];
        s += re * re + im * im;
    }
    return s * 2.0;
}

void
fndsa_fft_inv(double *a, unsigned logn)
{
    size_t n = (size_t)1 << logn;
    size_t hn = n >> 1;
    size_t i;
    for (i = 0; i < hn; i++) {
        double re = a[i];
        double im = a[i + hn];
        double d  = re * re + im * im;
        double id = 1.0 / d;
        a[i]      = re * id;
        a[i + hn] = -im * id;
    }
}

void
fndsa_fft_div(double *a, const double *b, unsigned logn)
{
    size_t n = (size_t)1 << logn;
    size_t hn = n >> 1;
    size_t i;
    for (i = 0; i < hn; i++) {
        double a_re = a[i];
        double a_im = a[i + hn];
        double b_re = b[i];
        double b_im = b[i + hn];
        double d    = b_re * b_re + b_im * b_im;
        double id   = 1.0 / d;
        a[i]        = (a_re * b_re + a_im * b_im) * id;
        a[i + hn]   = (a_im * b_re - a_re * b_im) * id;
    }
}

void
fndsa_fft_scale(double *a, double s, unsigned logn)
{
    size_t n = (size_t)1 << logn;
    size_t i;
    for (i = 0; i < n; i++)
        a[i] *= s;
}
