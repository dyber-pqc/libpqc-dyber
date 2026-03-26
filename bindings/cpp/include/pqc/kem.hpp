/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * RAII C++ wrapper for the KEM API.
 */

#ifndef PQC_KEM_HPP
#define PQC_KEM_HPP

#include <string>
#include <utility>

#include <pqc/kem.h>

#include "pqc/bytes.hpp"
#include "pqc/error.hpp"

namespace pqc {

/**
 * RAII wrapper for a KEM context.
 *
 * Manages the lifetime of a PQC_KEM* handle and exposes type-safe
 * C++ methods for key generation, encapsulation, and decapsulation.
 *
 * Example:
 * @code
 *   pqc::KEM kem("ML-KEM-768");
 *   auto [pk, sk] = kem.keygen();
 *   auto [ct, ss_enc] = kem.encaps(pk);
 *   auto ss_dec = kem.decaps(ct, sk);
 *   // ss_enc == ss_dec
 * @endcode
 */
class KEM {
public:
    /**
     * Create a KEM context for the specified algorithm.
     *
     * @param algorithm  Algorithm name (e.g. "ML-KEM-768").
     * @throws pqc::Error if the algorithm is not supported or not enabled.
     */
    explicit KEM(const std::string& algorithm)
        : ctx_(pqc_kem_new(algorithm.c_str()))
    {
        if (!ctx_) {
            throw Error(PQC_ERROR_NOT_SUPPORTED,
                        "pqc_kem_new(" + algorithm + ")");
        }
    }

    ~KEM() {
        if (ctx_) {
            pqc_kem_free(ctx_);
        }
    }

    // Non-copyable
    KEM(const KEM&) = delete;
    KEM& operator=(const KEM&) = delete;

    // Movable
    KEM(KEM&& other) noexcept : ctx_(other.ctx_) {
        other.ctx_ = nullptr;
    }

    KEM& operator=(KEM&& other) noexcept {
        if (this != &other) {
            if (ctx_) {
                pqc_kem_free(ctx_);
            }
            ctx_ = other.ctx_;
            other.ctx_ = nullptr;
        }
        return *this;
    }

    /** Return the algorithm name. */
    std::string algorithm() const {
        return pqc_kem_algorithm(ctx_);
    }

    /** Return the public key size in bytes. */
    std::size_t public_key_size() const {
        return pqc_kem_public_key_size(ctx_);
    }

    /** Return the secret key size in bytes. */
    std::size_t secret_key_size() const {
        return pqc_kem_secret_key_size(ctx_);
    }

    /** Return the ciphertext size in bytes. */
    std::size_t ciphertext_size() const {
        return pqc_kem_ciphertext_size(ctx_);
    }

    /** Return the shared secret size in bytes. */
    std::size_t shared_secret_size() const {
        return pqc_kem_shared_secret_size(ctx_);
    }

    /**
     * Generate a key pair.
     *
     * @return (public_key, secret_key)
     * @throws pqc::Error on failure.
     */
    std::pair<Bytes, Bytes> keygen() const {
        Bytes pk(public_key_size());
        Bytes sk(secret_key_size());
        Error::check(pqc_kem_keygen(ctx_, pk.data(), sk.data()), "keygen");
        return {std::move(pk), std::move(sk)};
    }

    /**
     * Encapsulate: produce a ciphertext and shared secret from a public key.
     *
     * @param pk  The recipient's public key.
     * @return (ciphertext, shared_secret)
     * @throws pqc::Error on failure.
     */
    std::pair<Bytes, Bytes> encaps(const Bytes& pk) const {
        Bytes ct(ciphertext_size());
        Bytes ss(shared_secret_size());
        Error::check(
            pqc_kem_encaps(ctx_, ct.data(), ss.data(), pk.data()),
            "encaps");
        return {std::move(ct), std::move(ss)};
    }

    /**
     * Decapsulate: recover the shared secret from ciphertext and secret key.
     *
     * @param ct  The ciphertext from encapsulation.
     * @param sk  The recipient's secret key.
     * @return The shared secret.
     * @throws pqc::Error on failure.
     */
    Bytes decaps(const Bytes& ct, const Bytes& sk) const {
        Bytes ss(shared_secret_size());
        Error::check(
            pqc_kem_decaps(ctx_, ss.data(), ct.data(), sk.data()),
            "decaps");
        return ss;
    }

    /** Access the underlying C handle (advanced use). */
    PQC_KEM* handle() noexcept { return ctx_; }
    const PQC_KEM* handle() const noexcept { return ctx_; }

private:
    PQC_KEM* ctx_;
};

} // namespace pqc

#endif // PQC_KEM_HPP
