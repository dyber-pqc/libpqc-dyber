/*
 * Quick test for FN-DSA keygen.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pqc/pqc.h"

int main(void) {
    pqc_status_t rc;
    PQC_SIG *sig;
    uint8_t *pk, *sk;
    size_t pk_len, sk_len;

    printf("Initializing library...\n");
    fflush(stdout);
    rc = pqc_init();
    if (rc != PQC_OK) {
        printf("pqc_init failed: %d\n", rc);
        return 1;
    }

    printf("Creating FN-DSA-512 context...\n");
    fflush(stdout);
    sig = pqc_sig_new("FN-DSA-512");
    if (!sig) {
        printf("FN-DSA-512 not available\n");
        return 1;
    }

    pk_len = pqc_sig_public_key_size(sig);
    sk_len = pqc_sig_secret_key_size(sig);
    printf("pk_len=%zu sk_len=%zu\n", pk_len, sk_len);
    fflush(stdout);

    pk = (uint8_t *)calloc(1, pk_len);
    sk = (uint8_t *)calloc(1, sk_len);
    if (!pk || !sk) {
        printf("alloc failed\n");
        return 1;
    }

    printf("Running keygen...\n");
    fflush(stdout);
    rc = pqc_sig_keygen(sig, pk, sk);
    printf("keygen returned: %d\n", rc);
    fflush(stdout);

    if (rc == PQC_OK) {
        printf("SUCCESS: FN-DSA-512 keygen works!\n");

        /* Try sign/verify */
        uint8_t msg[] = "test message";
        size_t sig_max = pqc_sig_max_signature_size(sig);
        uint8_t *signature = calloc(1, sig_max);
        size_t sig_len = 0;

        printf("Signing...\n");
        fflush(stdout);
        rc = pqc_sig_sign(sig, signature, &sig_len, msg, sizeof(msg), sk);
        printf("sign returned: %d (sig_len=%zu)\n", rc, sig_len);
        fflush(stdout);

        if (rc == PQC_OK) {
            printf("Verifying...\n");
            fflush(stdout);
            rc = pqc_sig_verify(sig, msg, sizeof(msg), signature, sig_len, pk);
            printf("verify returned: %d\n", rc);
            if (rc == PQC_OK)
                printf("SUCCESS: Full FN-DSA-512 roundtrip works!\n");
            else
                printf("FAIL: verify failed\n");
        }

        free(signature);
    } else {
        printf("FAIL: keygen returned %d (%s)\n", rc, pqc_status_string(rc));
    }

    free(pk);
    free(sk);
    pqc_sig_free(sig);
    pqc_cleanup();
    return (rc == PQC_OK) ? 0 : 1;
}
