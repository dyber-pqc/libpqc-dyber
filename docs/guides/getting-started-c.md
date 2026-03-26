# Getting Started with libpqc-dyber (C)

## Installation

### From Source

```bash
git clone https://github.com/dyber-pqc/libpqc-dyber.git
cd libpqc-dyber
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
sudo cmake --install build
```

### Linking

```bash
# With pkg-config
gcc myapp.c -o myapp $(pkg-config --cflags --libs libpqc)

# Direct
gcc myapp.c -o myapp -lpqc
```

## Key Encapsulation (KEM)

```c
#include <pqc/pqc.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    pqc_init();

    PQC_KEM *kem = pqc_kem_new("ML-KEM-768");
    if (!kem) { fprintf(stderr, "Algorithm not available\n"); return 1; }

    uint8_t *pk = malloc(pqc_kem_public_key_size(kem));
    uint8_t *sk = malloc(pqc_kem_secret_key_size(kem));
    uint8_t *ct = malloc(pqc_kem_ciphertext_size(kem));
    uint8_t *ss_enc = malloc(pqc_kem_shared_secret_size(kem));
    uint8_t *ss_dec = malloc(pqc_kem_shared_secret_size(kem));

    // Alice generates a keypair
    pqc_kem_keygen(kem, pk, sk);

    // Bob encapsulates using Alice's public key
    pqc_kem_encaps(kem, ct, ss_enc, pk);

    // Alice decapsulates using her secret key
    pqc_kem_decaps(kem, ss_dec, ct, sk);

    // ss_enc and ss_dec are now identical 32-byte shared secrets

    free(pk); free(sk); free(ct); free(ss_enc); free(ss_dec);
    pqc_kem_free(kem);
    pqc_cleanup();
    return 0;
}
```

## Digital Signatures

```c
#include <pqc/pqc.h>

int main() {
    pqc_init();

    PQC_SIG *sig = pqc_sig_new("ML-DSA-65");

    uint8_t *pk = malloc(pqc_sig_public_key_size(sig));
    uint8_t *sk = malloc(pqc_sig_secret_key_size(sig));
    uint8_t *signature = malloc(pqc_sig_max_signature_size(sig));
    size_t sig_len;

    // Generate keypair
    pqc_sig_keygen(sig, pk, sk);

    // Sign a message
    const uint8_t msg[] = "Important document";
    pqc_sig_sign(sig, signature, &sig_len, msg, sizeof(msg), sk);

    // Verify the signature
    pqc_status_t rc = pqc_sig_verify(sig, msg, sizeof(msg),
                                      signature, sig_len, pk);
    if (rc == PQC_OK) {
        printf("Valid signature!\n");
    }

    free(pk); free(sk); free(signature);
    pqc_sig_free(sig);
    pqc_cleanup();
    return 0;
}
```

## Listing Available Algorithms

```c
#include <pqc/pqc.h>
#include <stdio.h>

int main() {
    pqc_init();

    printf("KEM algorithms:\n");
    for (int i = 0; i < pqc_kem_algorithm_count(); i++) {
        printf("  %s\n", pqc_kem_algorithm_name(i));
    }

    printf("\nSignature algorithms:\n");
    for (int i = 0; i < pqc_sig_algorithm_count(); i++) {
        printf("  %s\n", pqc_sig_algorithm_name(i));
    }

    pqc_cleanup();
    return 0;
}
```
