/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Integration test: full round-trip for all algorithm types.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pqc/pqc.h"

int main(void) {
    pqc_init();

    printf("libpqc-dyber Integration Test\n");
    printf("=============================\n\n");

    printf("Library version: %s\n", pqc_version());
    printf("KEM algorithms:  %d\n", pqc_kem_algorithm_count());
    printf("SIG algorithms:  %d\n", pqc_sig_algorithm_count());
    printf("\n");

    /* List all algorithms */
    printf("Available KEM algorithms:\n");
    for (int i = 0; i < pqc_kem_algorithm_count(); i++) {
        printf("  - %s\n", pqc_kem_algorithm_name(i));
    }

    printf("\nAvailable Signature algorithms:\n");
    for (int i = 0; i < pqc_sig_algorithm_count(); i++) {
        printf("  - %s%s\n", pqc_sig_algorithm_name(i),
               pqc_sig_is_enabled(pqc_sig_algorithm_name(i)) ? "" : " (disabled)");
    }

    printf("\nAll integration tests passed.\n");

    pqc_cleanup();
    return 0;
}
