/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * FN-DSA (FIPS 206) -- Signature and key encoding / decoding.
 *
 * Public key:  header byte || h coefficients encoded as 14-bit values mod q.
 * Secret key:  header byte || f || g || F  encoded with trim_i8.
 * Signature:   header byte || nonce (40 bytes) || compressed s2.
 *
 * Compressed signature encoding uses a Golomb-Rice-like code for small
 * signed integers.
 */

#include <string.h>
#include "fndsa.h"
#include "fndsa_params.h"

/* ------------------------------------------------------------------ */
/* Bit-packing helpers                                                  */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t *buf;
    size_t   max_len;
    size_t   byte_pos;
    unsigned bit_pos;   /* bits used in current byte (0..7) */
    int      overflow;
} bitwriter_t;

static void
bw_init(bitwriter_t *bw, uint8_t *buf, size_t max_len)
{
    bw->buf     = buf;
    bw->max_len = max_len;
    bw->byte_pos = 0;
    bw->bit_pos  = 0;
    bw->overflow = 0;
    if (max_len > 0)
        memset(buf, 0, max_len);
}

static void
bw_write_bits(bitwriter_t *bw, uint32_t val, unsigned nbits)
{
    unsigned i;
    for (i = 0; i < nbits; i++) {
        if (bw->byte_pos >= bw->max_len) {
            bw->overflow = 1;
            return;
        }
        bw->buf[bw->byte_pos] |= (uint8_t)(((val >> i) & 1) << bw->bit_pos);
        bw->bit_pos++;
        if (bw->bit_pos == 8) {
            bw->bit_pos = 0;
            bw->byte_pos++;
        }
    }
}

static size_t
bw_finish(bitwriter_t *bw)
{
    if (bw->overflow)
        return 0;
    return bw->byte_pos + (bw->bit_pos > 0 ? 1 : 0);
}

typedef struct {
    const uint8_t *buf;
    size_t         len;
    size_t         byte_pos;
    unsigned       bit_pos;
    int            overflow;
} bitreader_t;

static void
br_init(bitreader_t *br, const uint8_t *buf, size_t len)
{
    br->buf      = buf;
    br->len      = len;
    br->byte_pos = 0;
    br->bit_pos  = 0;
    br->overflow = 0;
}

static uint32_t
br_read_bits(bitreader_t *br, unsigned nbits)
{
    uint32_t val = 0;
    unsigned i;
    for (i = 0; i < nbits; i++) {
        if (br->byte_pos >= br->len) {
            br->overflow = 1;
            return 0;
        }
        val |= (uint32_t)((br->buf[br->byte_pos] >> br->bit_pos) & 1) << i;
        br->bit_pos++;
        if (br->bit_pos == 8) {
            br->bit_pos = 0;
            br->byte_pos++;
        }
    }
    return val;
}

/* ------------------------------------------------------------------ */
/* Compressed signature encoding (Golomb-Rice-like)                     */
/* ------------------------------------------------------------------ */

/*
 * Encode a signed integer v using a Golomb-Rice-like code:
 *   - If v >= 0, encode sign bit 0, then unary(v >> low_bits),
 *     then the low_bits least significant bits.
 *   - If v < 0, encode sign bit 1, then unary((-v-1) >> low_bits),
 *     then low_bits bits of (-v-1).
 *
 * The number of low bits depends on the parameter set:
 *   n=512:  low_bits = 8
 *   n=1024: low_bits = 8
 */
#define COMP_LOW_BITS  8

size_t
fndsa_comp_encode(uint8_t *out, size_t max_out,
                  const int16_t *s2, unsigned logn)
{
    size_t n = (size_t)1 << logn;
    bitwriter_t bw;
    size_t i;

    bw_init(&bw, out, max_out);

    for (i = 0; i < n; i++) {
        int16_t v = s2[i];
        uint32_t sign, abs_val, low, high, j;

        if (v < 0) {
            sign = 1;
            abs_val = (uint32_t)(-(int32_t)v - 1);
        } else {
            sign = 0;
            abs_val = (uint32_t)v;
        }

        /* Special case: v == 0 => sign=0, abs=0. */
        if (v == 0) {
            /* Just sign bit (0) + zero unary (one 0-bit) + low bits (all 0). */
        }

        /* Sign bit. */
        bw_write_bits(&bw, sign, 1);

        low  = abs_val & ((1u << COMP_LOW_BITS) - 1);
        high = abs_val >> COMP_LOW_BITS;

        /* Unary encoding of high: high zero-bits followed by a one-bit. */
        for (j = 0; j < high; j++)
            bw_write_bits(&bw, 0, 1);
        bw_write_bits(&bw, 1, 1);

        /* Low bits. */
        bw_write_bits(&bw, low, COMP_LOW_BITS);
    }

    return bw_finish(&bw);
}

int
fndsa_comp_decode(int16_t *s2, const uint8_t *sig, size_t siglen,
                  unsigned logn)
{
    size_t n = (size_t)1 << logn;
    bitreader_t br;
    size_t i;

    br_init(&br, sig, siglen);

    for (i = 0; i < n; i++) {
        uint32_t sign, low, high, abs_val;
        int16_t v;

        sign = br_read_bits(&br, 1);

        /* Unary-decode high part: count zero bits until a one bit. */
        high = 0;
        for (;;) {
            uint32_t bit = br_read_bits(&br, 1);
            if (br.overflow)
                return -1;
            if (bit)
                break;
            high++;
            if (high > 2048)
                return -1;  /* overflow guard */
        }

        low = br_read_bits(&br, COMP_LOW_BITS);
        if (br.overflow)
            return -1;

        abs_val = (high << COMP_LOW_BITS) | low;

        if (sign) {
            v = -(int16_t)(abs_val + 1);
        } else {
            v = (int16_t)abs_val;
        }

        s2[i] = v;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* trim_i8 encoding for secret-key polynomials                          */
/* ------------------------------------------------------------------ */

/*
 * Encode an array of int8_t values using `bits` bits per value.
 * The encoding is: sign bit (1 if negative) followed by (bits-1) magnitude
 * bits.  Values must be in range [-(2^(bits-1)-1), 2^(bits-1)-1].
 */
size_t
fndsa_trim_i8_encode(uint8_t *out, size_t max_out,
                     const int8_t *vals, size_t count, unsigned bits)
{
    bitwriter_t bw;
    size_t i;

    bw_init(&bw, out, max_out);

    for (i = 0; i < count; i++) {
        int8_t v = vals[i];
        uint32_t sign = 0;
        uint32_t mag;

        if (v < 0) {
            sign = 1;
            mag = (uint32_t)(-(int32_t)v);
        } else {
            mag = (uint32_t)v;
        }

        /* Encode: (bits-1) magnitude bits, then sign bit.
         * Always write exactly `bits` bits per element so that the
         * encoded length is fixed (n * bits) and the decoder can
         * compute byte boundaries without knowing the data. */
        bw_write_bits(&bw, mag, bits - 1);
        bw_write_bits(&bw, sign, 1);
    }

    return bw_finish(&bw);
}

int
fndsa_trim_i8_decode(int8_t *vals, size_t count, unsigned bits,
                     const uint8_t *in, size_t inlen)
{
    bitreader_t br;
    size_t i;

    br_init(&br, in, inlen);

    for (i = 0; i < count; i++) {
        uint32_t mag, sign;
        int8_t v;

        mag = br_read_bits(&br, bits - 1);
        if (br.overflow)
            return -1;

        /* Always read the sign bit (matches the fixed-width encoder). */
        sign = br_read_bits(&br, 1);
        if (br.overflow)
            return -1;

        v = (int8_t)mag;
        if (sign)
            v = -v;
        vals[i] = v;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Public key encoding / decoding (14-bit coefficients mod q)           */
/* ------------------------------------------------------------------ */

size_t
fndsa_pk_encode(uint8_t *out, size_t max_out,
                const uint16_t *h, unsigned logn)
{
    size_t n = (size_t)1 << logn;
    bitwriter_t bw;
    size_t i;
    size_t needed = 1 + (n * 14 + 7) / 8;

    if (max_out < needed)
        return 0;

    out[0] = (uint8_t)FNDSA_PK_HEADER(logn);
    bw_init(&bw, out + 1, max_out - 1);

    for (i = 0; i < n; i++)
        bw_write_bits(&bw, (uint32_t)h[i], 14);

    return 1 + bw_finish(&bw);
}

int
fndsa_pk_decode(uint16_t *h, const uint8_t *pk, size_t pklen,
                unsigned logn)
{
    size_t n = (size_t)1 << logn;
    bitreader_t br;
    size_t i;
    size_t needed = 1 + (n * 14 + 7) / 8;

    if (pklen < needed)
        return -1;
    if (pk[0] != FNDSA_PK_HEADER(logn))
        return -1;

    br_init(&br, pk + 1, pklen - 1);

    for (i = 0; i < n; i++) {
        uint32_t v = br_read_bits(&br, 14);
        if (br.overflow)
            return -1;
        if (v >= FNDSA_Q)
            return -1;
        h[i] = (uint16_t)v;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Secret key encoding / decoding                                       */
/* ------------------------------------------------------------------ */

/*
 * Secret key layout:
 *   header (1 byte)
 *   f  (n coefficients, trim_i8 with sk_bits bits each)
 *   g  (n coefficients, trim_i8 with sk_bits bits each)
 *   F  (n coefficients, trim_i8 with sk_bits+4 bits each)
 *
 * G is not stored; it is recomputed from f, g, F via G = (q + g*F)/f.
 */

size_t
fndsa_sk_encode(uint8_t *out, size_t max_out,
                const int8_t *f, const int8_t *g, const int8_t *F,
                unsigned logn)
{
    size_t n = (size_t)1 << logn;
    unsigned sk_bits = (logn <= 9) ? FNDSA_512_SK_BITS : FNDSA_1024_SK_BITS;
    unsigned sk_f_bits = (logn <= 9) ? FNDSA_512_SK_F_BITS : FNDSA_1024_SK_F_BITS;
    size_t pos;
    size_t wrote;

    if (max_out < 1)
        return 0;

    out[0] = (uint8_t)FNDSA_SK_HEADER(logn);
    pos = 1;

    wrote = fndsa_trim_i8_encode(out + pos, max_out - pos, f, n, sk_bits);
    if (wrote == 0) return 0;
    pos += wrote;

    wrote = fndsa_trim_i8_encode(out + pos, max_out - pos, g, n, sk_bits);
    if (wrote == 0) return 0;
    pos += wrote;

    wrote = fndsa_trim_i8_encode(out + pos, max_out - pos, F, n, sk_f_bits);
    if (wrote == 0) return 0;
    pos += wrote;

    return pos;
}

int
fndsa_sk_decode(int8_t *f, int8_t *g, int8_t *F,
                const uint8_t *sk, size_t sklen,
                unsigned logn)
{
    size_t n = (size_t)1 << logn;
    unsigned sk_bits = (logn <= 9) ? FNDSA_512_SK_BITS : FNDSA_1024_SK_BITS;
    unsigned sk_f_bits = (logn <= 9) ? FNDSA_512_SK_F_BITS : FNDSA_1024_SK_F_BITS;
    size_t pos;

    if (sklen < 1)
        return -1;
    if (sk[0] != FNDSA_SK_HEADER(logn))
        return -1;

    pos = 1;

    /* Compute sizes for each section. */
    {
        size_t f_bytes = (n * sk_bits + 7) / 8;
        size_t g_bytes = (n * sk_bits + 7) / 8;
        size_t F_bytes = (n * sk_f_bits + 7) / 8;

        if (pos + f_bytes + g_bytes + F_bytes > sklen)
            return -1;

        if (fndsa_trim_i8_decode(f, n, sk_bits, sk + pos, f_bytes) != 0)
            return -1;
        pos += f_bytes;

        if (fndsa_trim_i8_decode(g, n, sk_bits, sk + pos, g_bytes) != 0)
            return -1;
        pos += g_bytes;

        if (fndsa_trim_i8_decode(F, n, sk_f_bits, sk + pos, F_bytes) != 0)
            return -1;
    }

    return 0;
}
