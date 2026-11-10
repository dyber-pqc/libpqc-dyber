/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Known-answer tests for the classical half of the hybrid schemes:
 * X25519, Ed25519, ECDH P-256 and ECDSA P-256.
 *
 * Every expected value here comes from a published source (RFC 7748,
 * RFC 8032, RFC 6979, NIST CAVP) or is fixed by the mathematics, never
 * from this library's own output. That is the point: a primitive that
 * is wrong on both sides of an exchange still round-trips, so
 * round-trip tests cannot tell X25519 from a ladder on some other
 * curve. Before these tests existed, none of the four primitives
 * matched its specification.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "pqc/pqc.h"

/* Internal headers: the primitives are not part of the public API. */
#include "core/common/hash/sha2.h"
#include "core/hybrid/field25519.h"
#include "core/hybrid/x25519.h"
#include "core/hybrid/ed25519.h"
#include "core/hybrid/field_p256.h"
#include "core/hybrid/ecdh_p256.h"
#include "core/hybrid/ecdsa_p256.h"

static int g_failures = 0;
static int g_checks = 0;

static void check(int cond, const char *what)
{
    g_checks++;
    if (cond) {
        printf("  PASS  %s\n", what);
    } else {
        printf("  FAIL  %s\n", what);
        g_failures++;
    }
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode a hex string into out; returns the number of bytes written. */
static size_t unhex(uint8_t *out, size_t cap, const char *hex)
{
    size_t n = strlen(hex) / 2;
    if (n > cap) {
        fprintf(stderr, "unhex: buffer too small\n");
        exit(2);
    }
    for (size_t i = 0; i < n; i++) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            fprintf(stderr, "unhex: bad digit in \"%s\"\n", hex);
            exit(2);
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}

/* Compare got against a hex string; prints both on mismatch. */
static void check_hex(const uint8_t *got, const char *want_hex, const char *what)
{
    uint8_t want[256];
    size_t n = unhex(want, sizeof(want), want_hex);
    int ok = (memcmp(got, want, n) == 0);
    check(ok, what);
    if (!ok) {
        printf("        got  ");
        for (size_t i = 0; i < n; i++) printf("%02x", got[i]);
        printf("\n        want %s\n", want_hex);
    }
}

/*
 * Deterministic RNG for the keygen checks: hands out the bytes it was
 * given and fails once they run out, so a keygen that draws more
 * randomness than expected is caught rather than fed zeros.
 */
typedef struct {
    const uint8_t *data;
    size_t len;
    size_t pos;
} fixed_rng_t;

static pqc_status_t fixed_rng(uint8_t *buf, size_t len, void *ctx)
{
    fixed_rng_t *r = (fixed_rng_t *)ctx;
    if (r->len - r->pos < len)
        return PQC_ERROR_RNG_FAILED;
    memcpy(buf, r->data + r->pos, len);
    r->pos += len;
    return PQC_OK;
}

/* ------------------------------------------------------------------ */
/* 1. Curve25519 field encoding                                         */
/* ------------------------------------------------------------------ */

static void test_fe25519(void)
{
    printf("\nCurve25519 field arithmetic\n");

    fe25519 f, g, h;
    uint8_t in[32], out[32];

    /*
     * Decode then encode must return the input for any value below p.
     * The patterns set every bit position in turn, including bits
     * 48-50, 99-101, 150-152 and 201-203, which the limb extraction
     * used to drop.
     */
    int ok = 1;
    for (int bit = 0; bit < 255; bit++) {
        memset(in, 0, 32);
        in[bit / 8] = (uint8_t)(1u << (bit % 8));
        fe25519_frombytes(f, in);
        fe25519_tobytes(out, f);
        if (memcmp(in, out, 32) != 0) ok = 0;
    }
    check(ok, "frombytes/tobytes preserves each of bits 0..254");

    for (int i = 0; i < 32; i++) in[i] = (uint8_t)(0xA5 ^ (i * 29));
    in[31] &= 0x7F;
    fe25519_frombytes(f, in);
    fe25519_tobytes(out, f);
    check(memcmp(in, out, 32) == 0, "frombytes/tobytes preserves a dense pattern");

    /* Bit 255 is not part of the field element (RFC 7748 section 5) */
    in[31] |= 0x80;
    fe25519_frombytes(g, in);
    fe25519_tobytes(out, g);
    in[31] &= 0x7F;
    check(memcmp(in, out, 32) == 0, "frombytes ignores bit 255");

    /* Values in [p, 2^255) must be reduced on output */
    unhex(in, 32, "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    fe25519_frombytes(f, in);
    fe25519_tobytes(out, f);
    check_hex(out, "0000000000000000000000000000000000000000000000000000000000000000",
              "tobytes reduces p to 0");
    check(fe25519_iszero(f) == 1, "iszero(p) is true");

    unhex(in, 32, "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    fe25519_frombytes(f, in);
    fe25519_tobytes(out, f);
    check_hex(out, "0100000000000000000000000000000000000000000000000000000000000000",
              "tobytes reduces p + 1 to 1");

    unhex(in, 32, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    fe25519_frombytes(f, in);
    fe25519_tobytes(out, f);
    check_hex(out, "1200000000000000000000000000000000000000000000000000000000000000",
              "tobytes reduces 2^255 - 1 to 18");

    /* x - x is zero whatever representative the subtraction lands on */
    for (int i = 0; i < 32; i++) in[i] = (uint8_t)(i * 7 + 3);
    in[31] &= 0x7F;
    fe25519_frombytes(f, in);
    fe25519_sub(h, f, f);
    check(fe25519_iszero(h) == 1, "x - x is zero");

    /* 0 - 1 = p - 1, and the difference of two differences stays in range */
    fe25519_0(f);
    fe25519_1(g);
    fe25519_sub(h, f, g);
    fe25519_tobytes(out, h);
    check_hex(out, "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
              "0 - 1 = p - 1");
    fe25519_sub(h, f, h);       /* 0 - (0 - 1) = 1 */
    fe25519_tobytes(out, h);
    check_hex(out, "0100000000000000000000000000000000000000000000000000000000000000",
              "0 - (0 - 1) = 1");

    /* 121666 * (p - 1) = p - 121666: every limb of the operand is full */
    unhex(in, 32, "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    fe25519_frombytes(f, in);
    fe25519_mul121666(h, f);
    fe25519_tobytes(out, h);
    check_hex(out, "ab24feffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
              "121666 * (p - 1) = p - 121666");

    /* (p - 1)^2 = 1 */
    fe25519_sq(h, f);
    fe25519_tobytes(out, h);
    check_hex(out, "0100000000000000000000000000000000000000000000000000000000000000",
              "(p - 1)^2 = 1");
}

/* ------------------------------------------------------------------ */
/* 2. X25519 (RFC 7748)                                                 */
/* ------------------------------------------------------------------ */

static void test_x25519(void)
{
    printf("\nX25519 (RFC 7748)\n");

    uint8_t k[32], u[32], out[32], pk[32], sk[32];

    /* Section 5.2, first vector */
    unhex(k, 32, "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    unhex(u, 32, "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    check(x25519_shared_secret(out, u, k) == 0, "5.2 vector 1 returns success");
    check_hex(out, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
              "5.2 vector 1");

    /* Section 5.2, second vector. Its u-coordinate has bit 255 set. */
    unhex(k, 32, "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
    unhex(u, 32, "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
    check(x25519_shared_secret(out, u, k) == 0, "5.2 vector 2 returns success");
    check_hex(out, "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
              "5.2 vector 2 (bit 255 of u masked)");

    /* Section 5.2, iterated: k = u = 9, then (k, u) <- (X25519(k, u), k) */
    long iterations = 1000;
    if (getenv("PQC_TEST_SLOW") != NULL)
        iterations = 1000000;   /* about a minute in a release build */

    memset(k, 0, 32);
    k[0] = 9;
    memcpy(u, k, 32);
    for (long i = 1; i <= iterations; i++) {
        x25519_shared_secret(out, u, k);
        memcpy(u, k, 32);
        memcpy(k, out, 32);
        if (i == 1)
            check_hex(k, "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
                      "5.2 after 1 iteration");
        if (i == 1000)
            check_hex(k, "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
                      "5.2 after 1,000 iterations");
        if (i == 1000000)
            check_hex(k, "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424",
                      "5.2 after 1,000,000 iterations");
    }

    /* Section 6.1 Diffie-Hellman */
    static const char *alice_sk = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    static const char *alice_pk = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    static const char *bob_sk   = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    static const char *bob_pk   = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    static const char *shared   = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
    uint8_t base[32] = { 9 };

    unhex(k, 32, alice_sk);
    x25519_shared_secret(out, base, k);
    check_hex(out, alice_pk, "6.1 Alice's public key");
    unhex(u, 32, bob_pk);
    check(x25519_shared_secret(out, u, k) == 0, "6.1 Alice's side returns success");
    check_hex(out, shared, "6.1 shared secret, Alice's side");

    unhex(k, 32, bob_sk);
    x25519_shared_secret(out, base, k);
    check_hex(out, bob_pk, "6.1 Bob's public key");
    unhex(u, 32, alice_pk);
    x25519_shared_secret(out, u, k);
    check_hex(out, shared, "6.1 shared secret, Bob's side");

    /* x25519_keygen must produce the same public key from the same bytes */
    uint8_t seed[32];
    unhex(seed, 32, alice_sk);
    fixed_rng_t rng = { seed, 32, 0 };
    pqc_set_rng(fixed_rng, &rng);
    int rc = x25519_keygen(pk, sk);
    pqc_set_rng(NULL, NULL);
    check(rc == 0 && memcmp(sk, seed, 32) == 0, "keygen stores the secret it drew");
    check_hex(pk, alice_pk, "keygen derives the RFC 7748 public key");

    /* Low-order inputs give an all-zero output, which must be reported */
    unhex(k, 32, alice_sk);
    memset(u, 0, 32);
    check(x25519_shared_secret(out, u, k) != 0, "u = 0 is rejected (all-zero output)");
    u[0] = 1;
    check(x25519_shared_secret(out, u, k) != 0, "u = 1 is rejected (all-zero output)");
    unhex(u, 32, "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800");
    check(x25519_shared_secret(out, u, k) != 0, "order-8 point is rejected (all-zero output)");
}

/* ------------------------------------------------------------------ */
/* 3. Ed25519 (RFC 8032 section 7.1)                                    */
/* ------------------------------------------------------------------ */

typedef struct {
    const char *name;
    const char *sk;
    const char *pk;
    const char *msg;
    const char *sig;
} ed25519_vector_t;

/*
 * RFC 8032 section 7.1: TEST 1, TEST 2, TEST 3 and TEST SHA(abc).
 * (TEST 1024, with its 1023-byte message, is left out for size.)
 */
static const ed25519_vector_t ed25519_vectors[] = {
    {
        "TEST 1",
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    },
    {
        "TEST 2",
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    },
    {
        "TEST 3",
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    },
    {
        "TEST SHA(abc)",
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589"
        "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
    },
};

static void test_ed25519(void)
{
    printf("\nEd25519 (RFC 8032 section 7.1)\n");

    char label[96];
    size_t count = sizeof(ed25519_vectors) / sizeof(ed25519_vectors[0]);

    for (size_t v = 0; v < count; v++) {
        const ed25519_vector_t *t = &ed25519_vectors[v];
        uint8_t seed[32], pk_want[32], pk[32], sk[32], msg[80], sig_want[64], sig[64];
        size_t msglen;

        unhex(seed, 32, t->sk);
        unhex(pk_want, 32, t->pk);
        msglen = unhex(msg, sizeof(msg) - 1, t->msg);
        unhex(sig_want, 64, t->sig);

        fixed_rng_t rng = { seed, 32, 0 };
        pqc_set_rng(fixed_rng, &rng);
        int rc = ed25519_keygen(pk, sk);
        pqc_set_rng(NULL, NULL);
        snprintf(label, sizeof(label), "%s: public key", t->name);
        check(rc == 0, "keygen succeeds");
        check_hex(pk, t->pk, label);

        memset(sig, 0, sizeof(sig));
        rc = ed25519_sign(sig, msg, msglen, seed);
        snprintf(label, sizeof(label), "%s: signature", t->name);
        check(rc == 0, "sign succeeds");
        check_hex(sig, t->sig, label);

        snprintf(label, sizeof(label), "%s: published signature verifies", t->name);
        check(ed25519_verify(msg, msglen, sig_want, pk_want) == 0, label);

        /* One more byte of message */
        msg[msglen] = 0x00;
        snprintf(label, sizeof(label), "%s: rejects extended message", t->name);
        check(ed25519_verify(msg, msglen + 1, sig_want, pk_want) != 0, label);

        /* A flipped bit in R, and in S */
        memcpy(sig, sig_want, 64);
        sig[3] ^= 0x10;
        snprintf(label, sizeof(label), "%s: rejects modified R", t->name);
        check(ed25519_verify(msg, msglen, sig, pk_want) != 0, label);
        memcpy(sig, sig_want, 64);
        sig[40] ^= 0x01;
        snprintf(label, sizeof(label), "%s: rejects modified S", t->name);
        check(ed25519_verify(msg, msglen, sig, pk_want) != 0, label);

        /* Another vector's key */
        unhex(pk, 32, ed25519_vectors[(v + 1) % count].pk);
        snprintf(label, sizeof(label), "%s: rejects wrong public key", t->name);
        check(ed25519_verify(msg, msglen, sig_want, pk) != 0, label);

        /*
         * Malleability: S + l is the same scalar mod l, so without the
         * range check of RFC 8032 section 5.1.7 it verifies too.
         */
        static const uint8_t L[32] = {
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
            0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
        };
        unsigned carry = 0;
        memcpy(sig, sig_want, 64);
        for (int i = 0; i < 32; i++) {
            carry += (unsigned)sig[32 + i] + L[i];
            sig[32 + i] = (uint8_t)carry;
            carry >>= 8;
        }
        snprintf(label, sizeof(label), "%s: rejects S + l", t->name);
        check(carry == 0 && ed25519_verify(msg, msglen, sig, pk_want) != 0, label);
    }

    /*
     * Encodings RFC 8032 section 5.1.3 says must fail to decode. With the
     * neutral element as public key, (R, S) = (neutral, 0) satisfies the
     * verification equation for every message, so these would verify if
     * the decoder accepted them.
     */
    uint8_t sig[64], pk[32];
    const uint8_t msg[1] = { 0x61 };

    memset(sig, 0, sizeof(sig));
    sig[0] = 0x01;          /* R = (0, 1), S = 0 */

    /* y = p + 1, a non-canonical encoding of y = 1 */
    unhex(pk, 32, "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    check(ed25519_verify(msg, 1, sig, pk) != 0, "rejects public key with y >= p");

    /* y = 1, x = 0, but the sign bit of x set */
    unhex(pk, 32, "0100000000000000000000000000000000000000000000000000000000000080");
    check(ed25519_verify(msg, 1, sig, pk) != 0, "rejects x = 0 with the sign bit set");

    /* y = 2 is not the y-coordinate of any point on the curve */
    unhex(pk, 32, "0200000000000000000000000000000000000000000000000000000000000000");
    check(ed25519_verify(msg, 1, sig, pk) != 0, "rejects public key not on the curve");
}

/* ------------------------------------------------------------------ */
/* 4. NIST P-256 field and scalar arithmetic                            */
/* ------------------------------------------------------------------ */

static void p256_check_mul(const char *a_hex, const char *b_hex,
                           const char *want_hex, const char *what)
{
    uint8_t a[32], b[32], out[32];
    p256_fe fa, fb, fr;

    unhex(a, 32, a_hex);
    unhex(b, 32, b_hex);
    p256_fe_frombytes(fa, a);
    p256_fe_frombytes(fb, b);
    p256_fe_mul(fr, fa, fb);
    p256_fe_tobytes(out, fr);
    check_hex(out, want_hex, what);
}

static void test_p256_arith(void)
{
    printf("\nP-256 field and scalar arithmetic\n");

    static const char *p_minus_1 = "ffffffff00000001000000000000000000000000fffffffffffffffffffffffe";
    static const char *n_minus_1 = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550";
    static const char *one       = "0000000000000000000000000000000000000000000000000000000000000001";

    p256_check_mul(p_minus_1, p_minus_1, one, "(p - 1)^2 = 1 mod p");

    /*
     * Operands for which the Solinas reduction leaves a carry after its
     * second pass. That carry used to be dropped, giving a result off by
     * a multiple of 2^256. Expected values are a * b mod p computed with
     * arbitrary-precision integers.
     */
    p256_check_mul("00000000fffffffe0000000000000001fffffffe7fffffffb5b02c7d00000000",
                   p_minus_1,
                   "fffffffe00000002fffffffffffffffe00000002800000004a4fd382ffffffff",
                   "field multiplication: late carry, case 1");
    p256_check_mul("00000000f691a0b7000000027fffffff000000013e921ff5ec15041d00000002",
                   p_minus_1,
                   "fffffffe096e5f49fffffffd80000000ffffffffc16de00a13eafbe2fffffffd",
                   "field multiplication: late carry, case 2");

    /* Field inversion: a * a^-1 = 1 */
    uint8_t a[32], out[32];
    p256_fe fa, fi, fr;
    for (int i = 0; i < 32; i++) a[i] = (uint8_t)(0x3C ^ (i * 37));
    a[0] &= 0x7F;
    p256_fe_frombytes(fa, a);
    p256_fe_inv(fi, fa);
    p256_fe_mul(fr, fa, fi);
    p256_fe_tobytes(out, fr);
    check_hex(out, one, "a * a^-1 = 1 mod p");

    /* Scalars: products must be reduced mod n, not truncated */
    uint8_t b[32];
    p256_fe sa, sb, sr;
    unhex(a, 32, n_minus_1);
    p256_scalar_frombytes(sa, a);
    p256_scalar_mul(sr, sa, sa);
    p256_scalar_tobytes(out, sr);
    check_hex(out, one, "(n - 1)^2 = 1 mod n");

    /* 2^255 * 2 = 2^256 = 2^256 - n mod n */
    memset(a, 0, 32); a[0] = 0x80;
    memset(b, 0, 32); b[31] = 0x02;
    p256_scalar_frombytes(sa, a);
    p256_scalar_frombytes(sb, b);
    p256_scalar_mul(sr, sa, sb);
    p256_scalar_tobytes(out, sr);
    check_hex(out, "00000000ffffffff00000000000000004319055258e8617b0c46353d039cdaaf",
              "2^255 * 2 = 2^256 - n mod n");

    /* Unreduced operands: (2^256 - 1)^2 mod n */
    memset(a, 0xFF, 32);
    p256_scalar_frombytes(sa, a);
    p256_scalar_mul(sr, sa, sa);
    p256_scalar_tobytes(out, sr);
    check_hex(out, "66e12d92f3d956222845b2392b6bec58c0676ef797ecacb06a97e21bb7403945",
              "(2^256 - 1)^2 mod n");

    /* Scalar inversion: a * a^-1 = 1 */
    for (int i = 0; i < 32; i++) a[i] = (uint8_t)(0x51 + i * 11);
    a[0] &= 0x7F;
    p256_scalar_frombytes(sa, a);
    p256_scalar_inv(sb, sa);
    p256_scalar_mul(sr, sa, sb);
    p256_scalar_tobytes(out, sr);
    check_hex(out, one, "a * a^-1 = 1 mod n");
}

/* ------------------------------------------------------------------ */
/* 5. ECDH P-256 (NIST CAVP, ECC CDH primitive, P-256 COUNT = 0)        */
/* ------------------------------------------------------------------ */

static void test_ecdh_p256(void)
{
    printf("\nECDH P-256 (NIST CAVP KAS ECC CDH)\n");

    static const char *d_iut  = "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534";
    static const char *q_iut  = "04"
        "ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230"
        "28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141";
    static const char *q_cavs = "04"
        "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287"
        "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac";
    static const char *z_iut  = "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b";

    uint8_t d[32], pk[65], peer[65], z[32], want[32], ss[32], sk[32];

    unhex(d, 32, d_iut);
    unhex(peer, 65, q_cavs);
    unhex(z, 32, z_iut);

    /* Public key from the private scalar */
    p256_point Q;
    p256_point_scalar_mult_base(&Q, d);
    p256_point_encode(pk, &Q);
    check_hex(pk, q_iut, "d * G matches QIUT");

    /* The raw shared x-coordinate */
    p256_point P, S;
    uint8_t x[32], y[32];
    check(p256_point_decode(&P, peer) == 0, "QCAVS decodes");
    p256_point_scalar_mult(&S, d, &P);
    p256_point_to_affine(x, y, &S);
    check_hex(x, z_iut, "d * QCAVS has x = ZIUT");

    /* ecdh_p256_shared_secret() returns SHA-256 of that x-coordinate */
    pqc_sha256(want, z, 32);
    check(ecdh_p256_shared_secret(ss, peer, d) == 0, "shared secret returns success");
    check(memcmp(ss, want, 32) == 0, "shared secret = SHA-256(ZIUT)");

    /* Keygen from the same scalar */
    fixed_rng_t rng = { d, 32, 0 };
    pqc_set_rng(fixed_rng, &rng);
    int rc = ecdh_p256_keygen(pk, sk);
    pqc_set_rng(NULL, NULL);
    check(rc == 0 && memcmp(sk, d, 32) == 0, "keygen stores the scalar it drew");
    check_hex(pk, q_iut, "keygen derives QIUT");

    /* Invalid public keys */
    uint8_t bad[65];
    memcpy(bad, peer, 65);
    bad[64] ^= 0x01;
    check(ecdh_p256_shared_secret(ss, bad, d) != 0, "rejects a point off the curve");

    memcpy(bad, peer, 65);
    bad[0] = 0x02;
    check(ecdh_p256_shared_secret(ss, bad, d) != 0, "rejects a non-uncompressed prefix");

    memset(bad, 0, 65);
    bad[0] = 0x04;
    check(ecdh_p256_shared_secret(ss, bad, d) != 0, "rejects (0, 0)");

    /*
     * (5, y) is on the curve. x = 5 + p names the same point with a
     * coordinate that is not a field element, and must not be accepted.
     */
    unhex(bad, 65, "04"
        "0000000000000000000000000000000000000000000000000000000000000005"
        "459243b9aa581806fe913bce99817ade11ca503c64d9a3c533415c083248fbcc");
    check(ecdh_p256_shared_secret(ss, bad, d) == 0, "accepts the point with x = 5");
    unhex(bad, 65, "04"
        "ffffffff00000001000000000000000000000001000000000000000000000004"
        "459243b9aa581806fe913bce99817ade11ca503c64d9a3c533415c083248fbcc");
    check(ecdh_p256_shared_secret(ss, bad, d) != 0, "rejects x = 5 + p");

    /* Invalid private scalars */
    uint8_t s[32];
    memset(s, 0, 32);
    check(ecdh_p256_shared_secret(ss, peer, s) != 0, "rejects private scalar 0");
    unhex(s, 32, "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    check(ecdh_p256_shared_secret(ss, peer, s) != 0, "rejects private scalar n");
}

/* ------------------------------------------------------------------ */
/* 6. ECDSA P-256 with SHA-256 (RFC 6979 appendix A.2.5)                */
/* ------------------------------------------------------------------ */

static void test_ecdsa_p256(void)
{
    printf("\nECDSA P-256 / SHA-256 (RFC 6979 A.2.5)\n");

    static const char *x_hex  = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
    static const char *ux_hex = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6";
    static const char *uy_hex = "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
    static const struct { const char *msg; const char *r; const char *s; } vec[] = {
        { "sample",
          "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
          "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8" },
        { "test",
          "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367",
          "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083" },
    };

    uint8_t x[32], pk_want[64], pk[64], sk[64], sig[64], sig_want[64];
    char label[96];

    unhex(x, 32, x_hex);
    unhex(pk_want, 32, ux_hex);
    unhex(pk_want + 32, 32, uy_hex);

    /* Keygen from the RFC's private key: pk = Ux || Uy, sk = x || Ux */
    fixed_rng_t rng = { x, 32, 0 };
    pqc_set_rng(fixed_rng, &rng);
    int rc = ecdsa_p256_keygen(pk, sk);
    pqc_set_rng(NULL, NULL);
    check(rc == 0, "keygen succeeds");
    check(memcmp(pk, pk_want, 64) == 0, "keygen derives the RFC 6979 public key");
    check(memcmp(sk, x, 32) == 0 && memcmp(sk + 32, pk_want, 32) == 0,
          "secret key is scalar || public x");

    for (size_t v = 0; v < sizeof(vec) / sizeof(vec[0]); v++) {
        const uint8_t *msg = (const uint8_t *)vec[v].msg;
        size_t msglen = strlen(vec[v].msg);

        unhex(sig_want, 32, vec[v].r);
        unhex(sig_want + 32, 32, vec[v].s);

        /* Signing is deterministic, so the signature itself is a KAT */
        memset(sig, 0, sizeof(sig));
        rc = ecdsa_p256_sign(sig, msg, msglen, sk);
        snprintf(label, sizeof(label), "\"%s\": r", vec[v].msg);
        check(rc == 0, "sign succeeds");
        check_hex(sig, vec[v].r, label);
        snprintf(label, sizeof(label), "\"%s\": s", vec[v].msg);
        check_hex(sig + 32, vec[v].s, label);

        snprintf(label, sizeof(label), "\"%s\": published signature verifies", vec[v].msg);
        check(ecdsa_p256_verify(msg, msglen, sig_want, pk_want) == 0, label);

        snprintf(label, sizeof(label), "\"%s\": rejects truncated message", vec[v].msg);
        check(ecdsa_p256_verify(msg, msglen - 1, sig_want, pk_want) != 0, label);

        memcpy(sig, sig_want, 64);
        sig[5] ^= 0x04;
        snprintf(label, sizeof(label), "\"%s\": rejects modified r", vec[v].msg);
        check(ecdsa_p256_verify(msg, msglen, sig, pk_want) != 0, label);

        memcpy(sig, sig_want, 64);
        sig[60] ^= 0x80;
        snprintf(label, sizeof(label), "\"%s\": rejects modified s", vec[v].msg);
        check(ecdsa_p256_verify(msg, msglen, sig, pk_want) != 0, label);

        memcpy(sig, sig_want, 64);
        memset(sig, 0, 32);
        snprintf(label, sizeof(label), "\"%s\": rejects r = 0", vec[v].msg);
        check(ecdsa_p256_verify(msg, msglen, sig, pk_want) != 0, label);

        memcpy(sig, sig_want, 64);
        memset(sig + 32, 0, 32);
        snprintf(label, sizeof(label), "\"%s\": rejects s = 0", vec[v].msg);
        check(ecdsa_p256_verify(msg, msglen, sig, pk_want) != 0, label);

        memcpy(sig, sig_want, 64);
        unhex(sig + 32, 32, "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
        snprintf(label, sizeof(label), "\"%s\": rejects s = n", vec[v].msg);
        check(ecdsa_p256_verify(msg, msglen, sig, pk_want) != 0, label);

        memcpy(pk, pk_want, 64);
        pk[63] ^= 0x01;
        snprintf(label, sizeof(label), "\"%s\": rejects public key off the curve", vec[v].msg);
        check(ecdsa_p256_verify(msg, msglen, sig_want, pk) != 0, label);
    }

    /* A private scalar outside [1, n-1] must not be signed with */
    memset(sk, 0, 64);
    check(ecdsa_p256_sign(sig, (const uint8_t *)"m", 1, sk) != 0, "sign rejects private scalar 0");
    unhex(sk, 32, "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    check(ecdsa_p256_sign(sig, (const uint8_t *)"m", 1, sk) != 0, "sign rejects private scalar n");
}

/* ------------------------------------------------------------------ */
/* 7. The hybrid schemes end to end, through the public API             */
/* ------------------------------------------------------------------ */

static void test_hybrid_kem(const char *name, size_t pq_ct_len)
{
    char label[128];
    PQC_KEM *kem = pqc_kem_new(name);

    snprintf(label, sizeof(label), "%s: available", name);
    check(kem != NULL, label);
    if (!kem) return;

    size_t pk_len = pqc_kem_public_key_size(kem);
    size_t sk_len = pqc_kem_secret_key_size(kem);
    size_t ct_len = pqc_kem_ciphertext_size(kem);
    size_t ss_len = pqc_kem_shared_secret_size(kem);

    uint8_t *pk = calloc(1, pk_len);
    uint8_t *sk = calloc(1, sk_len);
    uint8_t *ct = calloc(1, ct_len);
    uint8_t *ss1 = calloc(1, ss_len);
    uint8_t *ss2 = calloc(1, ss_len);
    if (!pk || !sk || !ct || !ss1 || !ss2) {
        check(0, "allocation");
        goto done;
    }

    int ok = 1;
    for (int i = 0; i < 8 && ok; i++) {
        ok = pqc_kem_keygen(kem, pk, sk) == PQC_OK
          && pqc_kem_encaps(kem, ct, ss1, pk) == PQC_OK
          && pqc_kem_decaps(kem, ss2, ct, sk) == PQC_OK
          && memcmp(ss1, ss2, ss_len) == 0;
    }
    snprintf(label, sizeof(label), "%s: encaps and decaps agree (8 fresh keys)", name);
    check(ok, label);

    /*
     * Disturb only the classical share of the ciphertext. Decapsulation
     * must not arrive at the sender's secret: either it fails or it
     * derives a different one.
     */
    ct[pq_ct_len + 7] ^= 0x20;
    pqc_status_t rc = pqc_kem_decaps(kem, ss2, ct, sk);
    snprintf(label, sizeof(label), "%s: a modified classical share changes the secret", name);
    check(rc != PQC_OK || memcmp(ss1, ss2, ss_len) != 0, label);

done:
    free(pk); free(sk); free(ct); free(ss1); free(ss2);
    pqc_kem_free(kem);
}

static void test_hybrid_sig(const char *name, size_t pq_pk_len)
{
    char label[128];
    PQC_SIG *sig = pqc_sig_new(name);

    snprintf(label, sizeof(label), "%s: available", name);
    check(sig != NULL, label);
    if (!sig) return;

    size_t pk_len = pqc_sig_public_key_size(sig);
    size_t sk_len = pqc_sig_secret_key_size(sig);
    size_t max_len = pqc_sig_max_signature_size(sig);

    uint8_t *pk = calloc(1, pk_len);
    uint8_t *sk = calloc(1, sk_len);
    uint8_t *s = calloc(1, max_len);
    uint8_t msg[48];
    size_t slen = 0;
    if (!pk || !sk || !s) {
        check(0, "allocation");
        goto done;
    }

    int ok = 1;
    for (int i = 0; i < 8 && ok; i++) {
        memset(msg, 0x40 + i, sizeof(msg));
        ok = pqc_sig_keygen(sig, pk, sk) == PQC_OK
          && pqc_sig_sign(sig, s, &slen, msg, sizeof(msg), sk) == PQC_OK
          && slen <= max_len
          && pqc_sig_verify(sig, msg, sizeof(msg), s, slen, pk) == PQC_OK;
    }
    snprintf(label, sizeof(label), "%s: sign and verify agree (8 fresh keys)", name);
    check(ok, label);
    if (!ok) goto done;

    /* The classical signature is the tail of the hybrid signature */
    s[slen - 1] ^= 0x01;
    snprintf(label, sizeof(label), "%s: rejects a modified classical signature", name);
    check(pqc_sig_verify(sig, msg, sizeof(msg), s, slen, pk) != PQC_OK, label);
    s[slen - 1] ^= 0x01;

    /* ...and the post-quantum one is the head */
    s[10] ^= 0x01;
    snprintf(label, sizeof(label), "%s: rejects a modified post-quantum signature", name);
    check(pqc_sig_verify(sig, msg, sizeof(msg), s, slen, pk) != PQC_OK, label);
    s[10] ^= 0x01;

    msg[0] ^= 0x01;
    snprintf(label, sizeof(label), "%s: rejects a modified message", name);
    check(pqc_sig_verify(sig, msg, sizeof(msg), s, slen, pk) != PQC_OK, label);
    msg[0] ^= 0x01;

    /* The classical public key follows the post-quantum one */
    pk[pq_pk_len + 3] ^= 0x01;
    snprintf(label, sizeof(label), "%s: rejects a modified classical public key", name);
    check(pqc_sig_verify(sig, msg, sizeof(msg), s, slen, pk) != PQC_OK, label);

done:
    free(pk); free(sk); free(s);
    pqc_sig_free(sig);
}

static void test_hybrids(void)
{
    printf("\nHybrid schemes through the public API\n");

    test_hybrid_kem(PQC_KEM_HYBRID_MLKEM768_X25519, 1088);
    test_hybrid_kem(PQC_KEM_HYBRID_MLKEM1024_P256, 1568);
    test_hybrid_sig(PQC_SIG_HYBRID_MLDSA65_ED25519, 1952);
    test_hybrid_sig(PQC_SIG_HYBRID_MLDSA87_P256, 2592);
}

/* ------------------------------------------------------------------ */

int main(void)
{
    if (pqc_init() != PQC_OK) {
        fprintf(stderr, "pqc_init failed\n");
        return 1;
    }

    printf("libpqc-dyber classical primitive known-answer tests\n");
    printf("===================================================\n");

    test_fe25519();
    test_x25519();
    test_ed25519();
    test_p256_arith();
    test_ecdh_p256();
    test_ecdsa_p256();
    test_hybrids();

    printf("\n%d checks, %d failures\n", g_checks, g_failures);

    pqc_cleanup();
    return g_failures > 0 ? 1 : 0;
}
