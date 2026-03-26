/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Command-line interface for libpqc.
 *
 * Usage:
 *   pqc-cli version
 *   pqc-cli algorithms
 *   pqc-cli keygen <algorithm> --pk <file> --sk <file>
 *   pqc-cli encaps <algorithm> --pk <file> --ct <file> --ss <file>
 *   pqc-cli decaps <algorithm> --sk <file> --ct <file> --ss <file>
 *   pqc-cli sign   <algorithm> --sk <file> --msg <file> --sig <file>
 *   pqc-cli verify <algorithm> --pk <file> --msg <file> --sig <file>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pqc/pqc.h>

/* -------------------------------------------------------------------------- */
/* File I/O helpers                                                            */
/* -------------------------------------------------------------------------- */

static int write_file(const char *path, const uint8_t *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "Error: cannot open '%s' for writing\n", path);
        return -1;
    }
    if (fwrite(data, 1, len, f) != len) {
        fprintf(stderr, "Error: write to '%s' failed\n", path);
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

static uint8_t *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "Error: cannot open '%s' for reading\n", path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) {
        fclose(f);
        return NULL;
    }
    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        fprintf(stderr, "Error: read from '%s' failed\n", path);
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *out_len = (size_t)sz;
    return buf;
}

/* -------------------------------------------------------------------------- */
/* Argument parsing helper                                                     */
/* -------------------------------------------------------------------------- */

static const char *find_arg(int argc, char **argv, const char *flag) {
    for (int i = 0; i < argc - 1; i++) {
        if (strcmp(argv[i], flag) == 0) {
            return argv[i + 1];
        }
    }
    return NULL;
}

/* -------------------------------------------------------------------------- */
/* Commands                                                                    */
/* -------------------------------------------------------------------------- */

static int cmd_version(void) {
    printf("libpqc-dyber %s\n", pqc_version());
    return 0;
}

static int cmd_algorithms(void) {
    int count, i;

    printf("KEM algorithms:\n");
    count = pqc_kem_algorithm_count();
    for (i = 0; i < count; i++) {
        printf("  %s\n", pqc_kem_algorithm_name(i));
    }

    printf("\nSignature algorithms:\n");
    count = pqc_sig_algorithm_count();
    for (i = 0; i < count; i++) {
        printf("  %s\n", pqc_sig_algorithm_name(i));
    }

    return 0;
}

static int cmd_keygen(const char *algorithm, int argc, char **argv) {
    const char *pk_path = find_arg(argc, argv, "--pk");
    const char *sk_path = find_arg(argc, argv, "--sk");
    if (!pk_path || !sk_path) {
        fprintf(stderr, "Usage: pqc-cli keygen <algorithm> --pk <file> --sk <file>\n");
        return 1;
    }

    /* Try KEM first, then signature */
    PQC_KEM *kem = pqc_kem_new(algorithm);
    if (kem) {
        size_t pk_size = pqc_kem_public_key_size(kem);
        size_t sk_size = pqc_kem_secret_key_size(kem);
        uint8_t *pk = (uint8_t *)malloc(pk_size);
        uint8_t *sk = (uint8_t *)malloc(sk_size);

        pqc_status_t rc = pqc_kem_keygen(kem, pk, sk);
        if (rc != PQC_OK) {
            fprintf(stderr, "Error: keygen failed: %s\n", pqc_status_string(rc));
            free(pk); free(sk); pqc_kem_free(kem);
            return 1;
        }

        int ret = 0;
        if (write_file(pk_path, pk, pk_size) < 0) ret = 1;
        if (write_file(sk_path, sk, sk_size) < 0) ret = 1;

        if (ret == 0) {
            printf("KEM keypair generated (%s)\n", algorithm);
            printf("  Public key:  %s (%zu bytes)\n", pk_path, pk_size);
            printf("  Secret key:  %s (%zu bytes)\n", sk_path, sk_size);
        }

        free(pk); free(sk); pqc_kem_free(kem);
        return ret;
    }

    PQC_SIG *sig = pqc_sig_new(algorithm);
    if (sig) {
        size_t pk_size = pqc_sig_public_key_size(sig);
        size_t sk_size = pqc_sig_secret_key_size(sig);
        uint8_t *pk = (uint8_t *)malloc(pk_size);
        uint8_t *sk = (uint8_t *)malloc(sk_size);

        pqc_status_t rc = pqc_sig_keygen(sig, pk, sk);
        if (rc != PQC_OK) {
            fprintf(stderr, "Error: keygen failed: %s\n", pqc_status_string(rc));
            free(pk); free(sk); pqc_sig_free(sig);
            return 1;
        }

        int ret = 0;
        if (write_file(pk_path, pk, pk_size) < 0) ret = 1;
        if (write_file(sk_path, sk, sk_size) < 0) ret = 1;

        if (ret == 0) {
            printf("Signature keypair generated (%s)\n", algorithm);
            printf("  Public key:  %s (%zu bytes)\n", pk_path, pk_size);
            printf("  Secret key:  %s (%zu bytes)\n", sk_path, sk_size);
        }

        free(pk); free(sk); pqc_sig_free(sig);
        return ret;
    }

    fprintf(stderr, "Error: unknown algorithm '%s'\n", algorithm);
    return 1;
}

static int cmd_encaps(const char *algorithm, int argc, char **argv) {
    const char *pk_path = find_arg(argc, argv, "--pk");
    const char *ct_path = find_arg(argc, argv, "--ct");
    const char *ss_path = find_arg(argc, argv, "--ss");
    if (!pk_path || !ct_path || !ss_path) {
        fprintf(stderr, "Usage: pqc-cli encaps <algorithm> --pk <file> --ct <file> --ss <file>\n");
        return 1;
    }

    PQC_KEM *kem = pqc_kem_new(algorithm);
    if (!kem) {
        fprintf(stderr, "Error: unsupported KEM algorithm '%s'\n", algorithm);
        return 1;
    }

    size_t pk_len;
    uint8_t *pk = read_file(pk_path, &pk_len);
    if (!pk) { pqc_kem_free(kem); return 1; }

    size_t ct_size = pqc_kem_ciphertext_size(kem);
    size_t ss_size = pqc_kem_shared_secret_size(kem);
    uint8_t *ct = (uint8_t *)malloc(ct_size);
    uint8_t *ss = (uint8_t *)malloc(ss_size);

    pqc_status_t rc = pqc_kem_encaps(kem, ct, ss, pk);
    if (rc != PQC_OK) {
        fprintf(stderr, "Error: encaps failed: %s\n", pqc_status_string(rc));
        free(pk); free(ct); free(ss); pqc_kem_free(kem);
        return 1;
    }

    int ret = 0;
    if (write_file(ct_path, ct, ct_size) < 0) ret = 1;
    if (write_file(ss_path, ss, ss_size) < 0) ret = 1;

    if (ret == 0) {
        printf("Encapsulation complete (%s)\n", algorithm);
        printf("  Ciphertext:    %s (%zu bytes)\n", ct_path, ct_size);
        printf("  Shared secret: %s (%zu bytes)\n", ss_path, ss_size);
    }

    free(pk); free(ct); free(ss); pqc_kem_free(kem);
    return ret;
}

static int cmd_decaps(const char *algorithm, int argc, char **argv) {
    const char *sk_path = find_arg(argc, argv, "--sk");
    const char *ct_path = find_arg(argc, argv, "--ct");
    const char *ss_path = find_arg(argc, argv, "--ss");
    if (!sk_path || !ct_path || !ss_path) {
        fprintf(stderr, "Usage: pqc-cli decaps <algorithm> --sk <file> --ct <file> --ss <file>\n");
        return 1;
    }

    PQC_KEM *kem = pqc_kem_new(algorithm);
    if (!kem) {
        fprintf(stderr, "Error: unsupported KEM algorithm '%s'\n", algorithm);
        return 1;
    }

    size_t sk_len, ct_len;
    uint8_t *sk = read_file(sk_path, &sk_len);
    if (!sk) { pqc_kem_free(kem); return 1; }
    uint8_t *ct = read_file(ct_path, &ct_len);
    if (!ct) { free(sk); pqc_kem_free(kem); return 1; }

    size_t ss_size = pqc_kem_shared_secret_size(kem);
    uint8_t *ss = (uint8_t *)malloc(ss_size);

    pqc_status_t rc = pqc_kem_decaps(kem, ss, ct, sk);
    if (rc != PQC_OK) {
        fprintf(stderr, "Error: decaps failed: %s\n", pqc_status_string(rc));
        free(sk); free(ct); free(ss); pqc_kem_free(kem);
        return 1;
    }

    int ret = write_file(ss_path, ss, ss_size);
    if (ret == 0) {
        printf("Decapsulation complete (%s)\n", algorithm);
        printf("  Shared secret: %s (%zu bytes)\n", ss_path, ss_size);
    }

    free(sk); free(ct); free(ss); pqc_kem_free(kem);
    return ret < 0 ? 1 : 0;
}

static int cmd_sign(const char *algorithm, int argc, char **argv) {
    const char *sk_path  = find_arg(argc, argv, "--sk");
    const char *msg_path = find_arg(argc, argv, "--msg");
    const char *sig_path = find_arg(argc, argv, "--sig");
    if (!sk_path || !msg_path || !sig_path) {
        fprintf(stderr, "Usage: pqc-cli sign <algorithm> --sk <file> --msg <file> --sig <file>\n");
        return 1;
    }

    PQC_SIG *sig = pqc_sig_new(algorithm);
    if (!sig) {
        fprintf(stderr, "Error: unsupported signature algorithm '%s'\n", algorithm);
        return 1;
    }

    size_t sk_len, msg_len;
    uint8_t *sk = read_file(sk_path, &sk_len);
    if (!sk) { pqc_sig_free(sig); return 1; }
    uint8_t *msg = read_file(msg_path, &msg_len);
    if (!msg) { free(sk); pqc_sig_free(sig); return 1; }

    size_t max_sig_size = pqc_sig_max_signature_size(sig);
    uint8_t *sig_buf = (uint8_t *)malloc(max_sig_size);
    size_t sig_len = max_sig_size;

    pqc_status_t rc = pqc_sig_sign(sig, sig_buf, &sig_len, msg, msg_len, sk);
    if (rc != PQC_OK) {
        fprintf(stderr, "Error: sign failed: %s\n", pqc_status_string(rc));
        free(sk); free(msg); free(sig_buf); pqc_sig_free(sig);
        return 1;
    }

    int ret = write_file(sig_path, sig_buf, sig_len);
    if (ret == 0) {
        printf("Signature created (%s)\n", algorithm);
        printf("  Signature: %s (%zu bytes)\n", sig_path, sig_len);
    }

    free(sk); free(msg); free(sig_buf); pqc_sig_free(sig);
    return ret < 0 ? 1 : 0;
}

static int cmd_verify(const char *algorithm, int argc, char **argv) {
    const char *pk_path  = find_arg(argc, argv, "--pk");
    const char *msg_path = find_arg(argc, argv, "--msg");
    const char *sig_path = find_arg(argc, argv, "--sig");
    if (!pk_path || !msg_path || !sig_path) {
        fprintf(stderr, "Usage: pqc-cli verify <algorithm> --pk <file> --msg <file> --sig <file>\n");
        return 1;
    }

    PQC_SIG *sig = pqc_sig_new(algorithm);
    if (!sig) {
        fprintf(stderr, "Error: unsupported signature algorithm '%s'\n", algorithm);
        return 1;
    }

    size_t pk_len, msg_len, sig_len;
    uint8_t *pk = read_file(pk_path, &pk_len);
    if (!pk) { pqc_sig_free(sig); return 1; }
    uint8_t *msg = read_file(msg_path, &msg_len);
    if (!msg) { free(pk); pqc_sig_free(sig); return 1; }
    uint8_t *sig_data = read_file(sig_path, &sig_len);
    if (!sig_data) { free(pk); free(msg); pqc_sig_free(sig); return 1; }

    pqc_status_t rc = pqc_sig_verify(sig, msg, msg_len, sig_data, sig_len, pk);
    if (rc == PQC_OK) {
        printf("Signature VALID (%s)\n", algorithm);
    } else {
        printf("Signature INVALID (%s): %s\n", algorithm, pqc_status_string(rc));
    }

    free(pk); free(msg); free(sig_data); pqc_sig_free(sig);
    return (rc == PQC_OK) ? 0 : 1;
}

/* -------------------------------------------------------------------------- */
/* Usage                                                                       */
/* -------------------------------------------------------------------------- */

static void print_usage(void) {
    fprintf(stderr,
        "Usage: pqc-cli <command> [options]\n"
        "\n"
        "Commands:\n"
        "  version                              Show library version\n"
        "  algorithms                           List available algorithms\n"
        "  keygen <alg> --pk <f> --sk <f>       Generate a keypair\n"
        "  encaps <alg> --pk <f> --ct <f> --ss <f>\n"
        "                                       KEM encapsulation\n"
        "  decaps <alg> --sk <f> --ct <f> --ss <f>\n"
        "                                       KEM decapsulation\n"
        "  sign   <alg> --sk <f> --msg <f> --sig <f>\n"
        "                                       Sign a message\n"
        "  verify <alg> --pk <f> --msg <f> --sig <f>\n"
        "                                       Verify a signature\n"
    );
}

/* -------------------------------------------------------------------------- */
/* Main                                                                        */
/* -------------------------------------------------------------------------- */

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    pqc_status_t init_rc = pqc_init();
    if (init_rc != PQC_OK) {
        fprintf(stderr, "Error: failed to initialize libpqc\n");
        return 1;
    }

    const char *cmd = argv[1];
    int ret = 0;

    if (strcmp(cmd, "version") == 0) {
        ret = cmd_version();
    } else if (strcmp(cmd, "algorithms") == 0) {
        ret = cmd_algorithms();
    } else if (strcmp(cmd, "keygen") == 0) {
        if (argc < 3) { fprintf(stderr, "Error: algorithm required\n"); ret = 1; }
        else ret = cmd_keygen(argv[2], argc, argv);
    } else if (strcmp(cmd, "encaps") == 0) {
        if (argc < 3) { fprintf(stderr, "Error: algorithm required\n"); ret = 1; }
        else ret = cmd_encaps(argv[2], argc, argv);
    } else if (strcmp(cmd, "decaps") == 0) {
        if (argc < 3) { fprintf(stderr, "Error: algorithm required\n"); ret = 1; }
        else ret = cmd_decaps(argv[2], argc, argv);
    } else if (strcmp(cmd, "sign") == 0) {
        if (argc < 3) { fprintf(stderr, "Error: algorithm required\n"); ret = 1; }
        else ret = cmd_sign(argv[2], argc, argv);
    } else if (strcmp(cmd, "verify") == 0) {
        if (argc < 3) { fprintf(stderr, "Error: algorithm required\n"); ret = 1; }
        else ret = cmd_verify(argv[2], argc, argv);
    } else if (strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
        print_usage();
    } else {
        fprintf(stderr, "Error: unknown command '%s'\n", cmd);
        print_usage();
        ret = 1;
    }

    pqc_cleanup();
    return ret;
}
