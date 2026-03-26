/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * RAII C++ wrapper for the Signature API.
 */

#ifndef PQC_SIG_HPP
#define PQC_SIG_HPP

#include <string>
#include <utility>

#include <pqc/sig.h>

#include "pqc/bytes.hpp"
#include "pqc/error.hpp"

namespace pqc {

/**
 * RAII wrapper for a digital signature context.
 *
 * Manages the lifetime of a PQC_SIG* handle and exposes type-safe
 * C++ methods for key generation, signing, and verification.
 *
 * Example:
 * @code
 *   pqc::Signature sig("ML-DSA-65");
 *   auto [pk, sk] = sig.keygen();
 *   auto signature = sig.sign(message, sk);
 *   bool ok = sig.verify(message, signature, pk);
 * @endcode
 */
class Signature {
public:
    /**
     * Create a signature context for the specified algorithm.
     *
     * @param algorithm  Algorithm name (e.g. "ML-DSA-65").
     * @throws pqc::Error if the algorithm is not supported or not enabled.
     */
    explicit Signature(const std::string& algorithm)
        : ctx_(pqc_sig_new(algorithm.c_str()))
    {
        if (!ctx_) {
            throw Error(PQC_ERROR_NOT_SUPPORTED,
                        "pqc_sig_new(" + algorithm + ")");
        }
    }

    ~Signature() {
        if (ctx_) {
            pqc_sig_free(ctx_);
        }
    }

    // Non-copyable
    Signature(const Signature&) = delete;
    Signature& operator=(const Signature&) = delete;

    // Movable
    Signature(Signature&& other) noexcept : ctx_(other.ctx_) {
        other.ctx_ = nullptr;
    }

    Signature& operator=(Signature&& other) noexcept {
        if (this != &other) {
            if (ctx_) {
                pqc_sig_free(ctx_);
            }
            ctx_ = other.ctx_;
            other.ctx_ = nullptr;
        }
        return *this;
    }

    /** Return the algorithm name. */
    std::string algorithm() const {
        return pqc_sig_algorithm(ctx_);
    }

    /** Return the public key size in bytes. */
    std::size_t public_key_size() const {
        return pqc_sig_public_key_size(ctx_);
    }

    /** Return the secret key size in bytes. */
    std::size_t secret_key_size() const {
        return pqc_sig_secret_key_size(ctx_);
    }

    /** Return the maximum signature size in bytes. */
    std::size_t max_signature_size() const {
        return pqc_sig_max_signature_size(ctx_);
    }

    /** Return whether this is a stateful signature scheme. */
    bool is_stateful() const {
        return pqc_sig_is_stateful(ctx_) != 0;
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
        Error::check(pqc_sig_keygen(ctx_, pk.data(), sk.data()), "keygen");
        return {std::move(pk), std::move(sk)};
    }

    /**
     * Sign a message.
     *
     * @param message  The message to sign.
     * @param sk       The signer's secret key.
     * @return The signature bytes (trimmed to actual length).
     * @throws pqc::Error on failure.
     */
    Bytes sign(const Bytes& message, const Bytes& sk) const {
        Bytes sig_buf(max_signature_size());
        std::size_t sig_len = 0;
        Error::check(
            pqc_sig_sign(ctx_, sig_buf.data(), &sig_len,
                         message.data(), message.size(),
                         sk.data()),
            "sign");
        sig_buf.resize(sig_len);
        return sig_buf;
    }

    /**
     * Sign a message with raw data pointers.
     *
     * @param message      Pointer to the message bytes.
     * @param message_len  Length of the message.
     * @param sk           The signer's secret key.
     * @return The signature bytes.
     * @throws pqc::Error on failure.
     */
    Bytes sign(const uint8_t* message, std::size_t message_len,
               const Bytes& sk) const {
        Bytes sig_buf(max_signature_size());
        std::size_t sig_len = 0;
        Error::check(
            pqc_sig_sign(ctx_, sig_buf.data(), &sig_len,
                         message, message_len,
                         sk.data()),
            "sign");
        sig_buf.resize(sig_len);
        return sig_buf;
    }

    /**
     * Verify a signature.
     *
     * @param message    The message that was signed.
     * @param signature  The signature to verify.
     * @param pk         The signer's public key.
     * @return true if the signature is valid, false otherwise.
     */
    bool verify(const Bytes& message, const Bytes& signature,
                const Bytes& pk) const {
        pqc_status_t status = pqc_sig_verify(
            ctx_,
            message.data(), message.size(),
            signature.data(), signature.size(),
            pk.data());
        if (status == PQC_OK) {
            return true;
        }
        if (status == PQC_ERROR_VERIFICATION_FAILED) {
            return false;
        }
        throw Error(status, "verify");
    }

    /**
     * Verify a signature with raw data pointers.
     */
    bool verify(const uint8_t* message, std::size_t message_len,
                const Bytes& signature, const Bytes& pk) const {
        pqc_status_t status = pqc_sig_verify(
            ctx_,
            message, message_len,
            signature.data(), signature.size(),
            pk.data());
        if (status == PQC_OK) {
            return true;
        }
        if (status == PQC_ERROR_VERIFICATION_FAILED) {
            return false;
        }
        throw Error(status, "verify");
    }

    /**
     * Sign with a stateful scheme (modifies the secret key in-place).
     *
     * Only valid for stateful algorithms (LMS, XMSS). The secret key
     * is updated to advance internal state.
     *
     * @param message  The message to sign.
     * @param sk       The signer's secret key (modified in-place).
     * @return The signature bytes.
     * @throws pqc::Error on failure or if the scheme is not stateful.
     */
    Bytes sign_stateful(const Bytes& message, Bytes& sk) const {
        Bytes sig_buf(max_signature_size());
        std::size_t sig_len = 0;
        Error::check(
            pqc_sig_sign_stateful(ctx_, sig_buf.data(), &sig_len,
                                  message.data(), message.size(),
                                  sk.data()),
            "sign_stateful");
        sig_buf.resize(sig_len);
        return sig_buf;
    }

    /** Access the underlying C handle (advanced use). */
    PQC_SIG* handle() noexcept { return ctx_; }
    const PQC_SIG* handle() const noexcept { return ctx_; }

private:
    PQC_SIG* ctx_;
};

} // namespace pqc

#endif // PQC_SIG_HPP
