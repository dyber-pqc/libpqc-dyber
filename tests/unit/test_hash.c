/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Hash function tests against known test vectors.
 */

#include <stdio.h>
#include <string.h>
#include "core/common/hash/sha2.h"
#include "core/common/hash/sha3.h"

static int hex_to_bytes(const char *hex, uint8_t *out, size_t outlen) {
    for (size_t i = 0; i < outlen; i++) {
        unsigned int val;
        if (sscanf(hex + 2 * i, "%2x", &val) != 1) return -1;
        out[i] = (uint8_t)val;
    }
    return 0;
}

static void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
}

static int test_sha256(void) {
    /* Test vector: SHA-256("abc") */
    const uint8_t msg[] = "abc";
    uint8_t hash[32];
    uint8_t expected[32];

    hex_to_bytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                 expected, 32);

    pqc_sha256(hash, msg, 3);

    if (memcmp(hash, expected, 32) != 0) {
        printf("  FAIL: SHA-256(\"abc\")\n    got:      ");
        print_hex(hash, 32);
        printf("\n    expected: ");
        print_hex(expected, 32);
        printf("\n");
        return 1;
    }
    printf("  PASS: SHA-256\n");
    return 0;
}

static int test_sha512(void) {
    /* Test vector: SHA-512("abc") */
    const uint8_t msg[] = "abc";
    uint8_t hash[64];
    uint8_t expected[64];

    hex_to_bytes("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                 "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                 expected, 64);

    pqc_sha512(hash, msg, 3);

    if (memcmp(hash, expected, 64) != 0) {
        printf("  FAIL: SHA-512(\"abc\")\n");
        return 1;
    }
    printf("  PASS: SHA-512\n");
    return 0;
}

static int test_sha3_256(void) {
    /* Test vector: SHA3-256("abc") */
    const uint8_t msg[] = "abc";
    uint8_t hash[32];
    uint8_t expected[32];

    hex_to_bytes("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
                 expected, 32);

    pqc_sha3_256(hash, msg, 3);

    if (memcmp(hash, expected, 32) != 0) {
        printf("  FAIL: SHA3-256(\"abc\")\n    got:      ");
        print_hex(hash, 32);
        printf("\n    expected: ");
        print_hex(expected, 32);
        printf("\n");
        return 1;
    }
    printf("  PASS: SHA3-256\n");
    return 0;
}

static int test_sha3_512(void) {
    /* Test vector: SHA3-512("abc") */
    const uint8_t msg[] = "abc";
    uint8_t hash[64];
    uint8_t expected[64];

    hex_to_bytes("b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
                 "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
                 expected, 64);

    pqc_sha3_512(hash, msg, 3);

    if (memcmp(hash, expected, 64) != 0) {
        printf("  FAIL: SHA3-512(\"abc\")\n");
        return 1;
    }
    printf("  PASS: SHA3-512\n");
    return 0;
}

static int test_shake128(void) {
    /* SHAKE128("") first 32 bytes */
    uint8_t hash[32];
    uint8_t expected[32];

    hex_to_bytes("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
                 expected, 32);

    pqc_shake128(hash, 32, (const uint8_t *)"", 0);

    if (memcmp(hash, expected, 32) != 0) {
        printf("  FAIL: SHAKE-128(\"\")\n    got:      ");
        print_hex(hash, 32);
        printf("\n    expected: ");
        print_hex(expected, 32);
        printf("\n");
        return 1;
    }
    printf("  PASS: SHAKE-128\n");
    return 0;
}

static int test_shake256(void) {
    /* SHAKE256("") first 32 bytes */
    uint8_t hash[32];
    uint8_t expected[32];

    hex_to_bytes("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
                 expected, 32);

    pqc_shake256(hash, 32, (const uint8_t *)"", 0);

    if (memcmp(hash, expected, 32) != 0) {
        printf("  FAIL: SHAKE-256(\"\")\n    got:      ");
        print_hex(hash, 32);
        printf("\n    expected: ");
        print_hex(expected, 32);
        printf("\n");
        return 1;
    }
    printf("  PASS: SHAKE-256\n");
    return 0;
}

int main(void) {
    printf("libpqc-dyber Hash Tests\n");
    printf("=======================\n\n");

    int failures = 0;
    failures += test_sha256();
    failures += test_sha512();
    failures += test_sha3_256();
    failures += test_sha3_512();
    failures += test_shake128();
    failures += test_shake256();

    printf("\n%d failures\n", failures);
    return failures > 0 ? 1 : 0;
}
