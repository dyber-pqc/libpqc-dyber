/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * FN-DSA (FIPS 206) -- FFT over complex numbers (double precision).
 *
 * This implements the split-radix FFT used in Falcon / FN-DSA.
 * The ring is Z[x]/(x^n + 1) with n a power of two.  The n-th
 * roots of -1 in C are  w_k = exp(i*pi*(2k+1)/n)  for k=0..n-1.
 *
 * Polynomials in the "FFT domain" are stored in the half-complex
 * layout: the first n/2 doubles hold real parts, the last n/2
 * hold imaginary parts.
 */

#include <math.h>
#include <string.h>
#include "fft.h"
#include "fndsa_params.h"

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* ------------------------------------------------------------------ */
/* Forward FFT                                                          */
/* ------------------------------------------------------------------ */

void
fndsa_fft_forward(double *f, unsigned logn)
{
    size_t n = (size_t)1 << logn;
    size_t hn = n >> 1;
    unsigned level;

    if (logn == 0)
        return;

    /*
     * First pass: convert the real polynomial into half-complex form.
     * We pair coefficients:  f_even[k] = f[2k], f_odd[k] = f[2k+1].
     * Then each complex entry becomes
     *     F[k] = f_even[k] + w_k * f_odd[k]
     * with w_k = exp(i*pi*(2k+1)/n).
     *
     * We perform the split-radix butterfly in-place, working from
     * the bottom (pairs of real values) upward.
     */

    /*
     * Step 1: rearrange into even/odd halves.
     * After this, f[0..hn-1] = even coefficients, f[hn..n-1] = odd.
     */
    {
        double tmp[FNDSA_MAX_N];
        size_t i;
        for (i = 0; i < hn; i++) {
            tmp[i]      = f[2 * i];
            tmp[i + hn] = f[2 * i + 1];
        }
        memcpy(f, tmp, n * sizeof(double));
    }

    /*
     * Step 2: recursive split-radix butterflies.
     * At each level we process blocks of size m (starting m=1, going
     * up to hn) where each block corresponds to a sub-FFT on n/(2m)
     * points.
     *
     * The butterfly merges two half-size sub-FFTs (stored as interleaved
     * real/imag blocks) into one full-size sub-FFT.
     */
    for (level = 0; level < logn; level++) {
        size_t m  = (size_t)1 << level;       /* half-block size */
        size_t dm = m << 1;                    /* full block size */
        size_t blocks = hn >> level;           /* number of blocks */
        size_t j;

        if (level == 0) {
            /*
             * Base level: merge pairs of real values into complex.
             * Each pair (a, b) becomes (a + w*b, a - w*b) with w =
             * exp(i*pi*(2k+1)/n) for the appropriate k.
             */
            for (j = 0; j < hn; j++) {
                double a_re = f[j];
                double b_re = f[j + hn];
                double angle = M_PI * (double)(2 * j + 1) / (double)n;
                double w_re = cos(angle);
                double w_im = sin(angle);
                /*
                 * In the half-complex layout the first hn doubles are
                 * real parts, the second hn are imaginary parts.
                 * At this first level we are constructing the complex
                 * values F[j] = a_re + w * b_re  (b is purely real).
                 */
                f[j]      = a_re + w_re * b_re;   /* real */
                f[j + hn] = w_im * b_re;           /* imag */
            }
        } else {
            /*
             * Higher levels: standard complex butterfly.
             * We split f into sub-blocks of size dm (in the real-part
             * half and the imag-part half), and merge adjacent sub-blocks.
             */
            size_t half_blocks = blocks >> 1;
            size_t blk;

            for (blk = 0; blk < half_blocks; blk++) {
                size_t base0 = blk * dm;
                size_t k;
                for (k = 0; k < m; k++) {
                    size_t i0 = base0 + k;
                    size_t i1 = i0 + m;

                    double a_re = f[i0];
                    double a_im = f[i0 + hn];
                    double b_re = f[i1];
                    double b_im = f[i1 + hn];

                    /*
                     * Twiddle factor: w = exp(i * pi * (2*(base0+k)+1) /
                     * (dm))  -- but we need the correct twiddle for the
                     * current level.  The exact twiddle is:
                     *   w = exp(i * pi * (2*k + 1) / (2*m))
                     */
                    double angle = M_PI * (double)(2 * k + 1) / (double)(2 * m);
                    double w_re = cos(angle);
                    double w_im = sin(angle);

                    /* Multiply b by w. */
                    double t_re = b_re * w_re - b_im * w_im;
                    double t_im = b_re * w_im + b_im * w_re;

                    f[i0]      = a_re + t_re;
                    f[i0 + hn] = a_im + t_im;
                    f[i1]      = a_re - t_re;
                    f[i1 + hn] = a_im - t_im;
                }
            }
        }
    }

    /*
     * At this point f[] is in the half-complex FFT layout:
     *   f[0..hn-1]   real parts of the n/2 complex FFT coefficients
     *   f[hn..n-1]   imaginary parts
     *
     * However, the standard Falcon FFT layout is slightly different:
     * it uses a recursive split where even-indexed outputs go to the
     * first half, odd-indexed to the second half at each recursion
     * depth.  We now reorder to match that standard layout (bit-reversal
     * of the index within the half-size arrays).
     */
    if (logn > 1) {
        double tmp_re[FNDSA_MAX_N / 2];
        double tmp_im[FNDSA_MAX_N / 2];
        unsigned bits = logn - 1;
        size_t i;

        for (i = 0; i < hn; i++) {
            /* Bit-reverse i within `bits` bits. */
            size_t ri = 0;
            unsigned b;
            size_t v = i;
            for (b = 0; b < bits; b++) {
                ri = (ri << 1) | (v & 1);
                v >>= 1;
            }
            tmp_re[ri] = f[i];
            tmp_im[ri] = f[i + hn];
        }
        for (i = 0; i < hn; i++) {
            f[i]      = tmp_re[i];
            f[i + hn] = tmp_im[i];
        }
    }
}

/* ------------------------------------------------------------------ */
/* Inverse FFT                                                          */
/* ------------------------------------------------------------------ */

void
fndsa_fft_inverse(double *f, unsigned logn)
{
    size_t n = (size_t)1 << logn;
    size_t hn = n >> 1;
    unsigned level;

    if (logn == 0)
        return;

    /*
     * Undo bit-reversal permutation.
     */
    if (logn > 1) {
        double tmp_re[FNDSA_MAX_N / 2];
        double tmp_im[FNDSA_MAX_N / 2];
        unsigned bits = logn - 1;
        size_t i;

        for (i = 0; i < hn; i++) {
            size_t ri = 0;
            unsigned b;
            size_t v = i;
            for (b = 0; b < bits; b++) {
                ri = (ri << 1) | (v & 1);
                v >>= 1;
            }
            tmp_re[ri] = f[i];
            tmp_im[ri] = f[i + hn];
        }
        for (i = 0; i < hn; i++) {
            f[i]      = tmp_re[i];
            f[i + hn] = tmp_im[i];
        }
    }

    /*
     * Inverse butterflies -- walk levels downward.
     */
    for (level = logn; level-- > 0; ) {
        size_t m = (size_t)1 << level;
        size_t dm = m << 1;

        if (level == 0) {
            size_t j;
            /* Reconstruct real polynomial from complex values. */
            for (j = 0; j < hn; j++) {
                double angle = M_PI * (double)(2 * j + 1) / (double)n;
                double w_re = cos(angle);
                double w_im = -sin(angle);  /* conjugate twiddle */

                double c_re = f[j];
                double c_im = f[j + hn];

                /*
                 * c = a + w*b  where a,b are real.
                 * Therefore b = Im(c) / Im(w) and a = Re(c) - Re(w)*b.
                 */
                double b_re = c_im / w_im;   /* w_im != 0 for all j */
                double a_re = c_re - w_re * b_re;

                f[j]      = a_re;
                f[j + hn] = b_re;
            }
        } else {
            size_t half_blocks = (hn >> level) >> 1;
            size_t blk;

            for (blk = 0; blk < half_blocks; blk++) {
                size_t base0 = blk * dm;
                size_t k;
                for (k = 0; k < m; k++) {
                    size_t i0 = base0 + k;
                    size_t i1 = i0 + m;

                    double a_re = f[i0];
                    double a_im = f[i0 + hn];
                    double b_re = f[i1];
                    double b_im = f[i1 + hn];

                    /* Inverse butterfly: recover (u, v) from (u+wv, u-wv). */
                    double u_re = (a_re + b_re) * 0.5;
                    double u_im = (a_im + b_im) * 0.5;
                    double d_re = (a_re - b_re) * 0.5;
                    double d_im = (a_im - b_im) * 0.5;

                    double angle = M_PI * (double)(2 * k + 1) / (double)(2 * m);
                    double w_re = cos(angle);
                    double w_im = -sin(angle);  /* conjugate twiddle */

                    /* v = d / w  =>  v = d * conj(w) / |w|^2.  |w|=1. */
                    double v_re = d_re * w_re - d_im * w_im;
                    double v_im = d_re * w_im + d_im * w_re;

                    f[i0]      = u_re;
                    f[i0 + hn] = u_im;
                    f[i1]      = v_re;
                    f[i1 + hn] = v_im;
                }
            }
        }
    }

    /*
     * Un-deinterleave: even-indexed values are in first half,
     * odd-indexed in second half -- reassemble.
     */
    {
        double tmp[FNDSA_MAX_N];
        size_t i;
        for (i = 0; i < hn; i++) {
            tmp[2 * i]     = f[i];
            tmp[2 * i + 1] = f[i + hn];
        }
        memcpy(f, tmp, n * sizeof(double));
    }

    /*
     * Scale by 1/n (the FFT is unnormalized).
     */
    {
        double inv_n = 1.0 / (double)n;
        size_t i;
        for (i = 0; i < n; i++)
            f[i] *= inv_n;
    }
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
    /* Negate imaginary parts. */
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
    /* Multiply a by conj(b). */
    for (i = 0; i < hn; i++) {
        double a_re = a[i];
        double a_im = a[i + hn];
        double b_re = b[i];
        double b_im = b[i + hn];   /* conjugate => -b_im */
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
    /* Factor 2 because half-complex stores n/2 of the n values;
     * by symmetry the other n/2 contribute equally. */
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
