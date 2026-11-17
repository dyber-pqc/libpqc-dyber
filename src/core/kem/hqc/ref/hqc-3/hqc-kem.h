/*
 * Vendored from the HQC reference implementation, v5.1.0
 * (https://gitlab.com/pqc-hqc/hqc, tag v5.1.0, commit 06567ccbad10),
 * which is in the public domain. Changes for libpqc-dyber: the
 * unused <immintrin.h> includes are removed so the portable code
 * builds on every architecture, BITMASK shifts a 64-bit one (1UL is
 * 32 bits on Windows, which broke HQC-5 there), and SHA-3/SHAKE and
 * the RNG come from the library (fips202.h, randombytes.h); vector.c
 * marks the key sampler's accept bit public for ctgrind.
 * See ../README.md.
 */
/**
 * @file hqc-kem.h
 * @brief NIST KEM API used by the HQC-KEM IND-CCA2 scheme
 */

#ifndef HQC_KEM_H
#define HQC_KEM_H

#include <stdint.h>

#define CRYPTO_ALGNAME "HQC-3"

#define CRYPTO_SECRETKEYBYTES  32U
#define CRYPTO_PUBLICKEYBYTES  4514U
#define CRYPTO_BYTES           32U
#define CRYPTO_CIPHERTEXTBYTES 8978U

/**
 * @brief Generate a KEM keypair.
 *
 * @param[out] ek_kem Encapsulation key buffer (size CRYPTO_PUBLICKEYBYTES).
 * @param[out] dk_kem Decapsulation key buffer (size CRYPTO_SECRETKEYBYTES).
 *
 * @details The encapsulation key is the PKE public key.
 *          The decapsulation key is the KEM master seed `seed_kem`, from which
 *          `seed_pke` and `sigma` are re-derived via the HQC XOF whenever needed:
 *          - seed_pke: seed used to regenerate the PKE keypair (`ek_pke`, `dk_pke`)
 *          - sigma: implicit rejection value used during decapsulation
 *
 * @return 0 on success, -1 on randombytes failure.
 */
int8_t hqc_kem_keygen(uint8_t *ek_kem, uint8_t *dk_kem);

/**
 * @brief Encapsulate a shared secret using the public key.
 *
 * @param[out] K     Shared secret buffer (size CRYPTO_BYTES).
 * @param[out] c_kem Ciphertext buffer (size CRYPTO_CIPHERTEXTBYTES).
 * @param[in]  ek_kem Encapsulation key buffer (size CRYPTO_PUBLICKEYBYTES).
 *
 * @details The encapsulation key is the PKE public key.
 *
 * @return 0 on success, -1 on randombytes failure.
 */
int8_t hqc_kem_encaps(uint8_t *K, uint8_t *c_kem, const uint8_t *ek_kem);

/**
 * @brief Decapsulate a shared secret using the secret key.
 *
 * @param[out] K_prime Shared secret buffer (size CRYPTO_BYTES).
 * @param[in]  dk_kem  Decapsulation key buffer (size CRYPTO_SECRETKEYBYTES).
 * @param[in]  c_kem   Ciphertext buffer (size CRYPTO_CIPHERTEXTBYTES).
 *
 * @details The decapsulation key is the KEM master seed `seed_kem`, from which
 *          `seed_pke` and `sigma` are re-derived via the HQC XOF whenever needed:
 *          - seed_pke: seed used to regenerate the PKE keypair (`ek_pke`, `dk_pke`)
 *          - sigma: implicit rejection value used during decapsulation
 *
 * @return 0 on success.
 */
int8_t hqc_kem_decaps(uint8_t *K_prime, const uint8_t *dk_kem, const uint8_t *c_kem);

#endif  // HQC_KEM_H
