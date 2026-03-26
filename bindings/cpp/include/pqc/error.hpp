/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * C++ exception class for PQC errors.
 */

#ifndef PQC_ERROR_HPP
#define PQC_ERROR_HPP

#include <stdexcept>
#include <string>

#include <pqc/common.h>

namespace pqc {

/**
 * Exception class for all PQC library errors.
 *
 * Wraps a pqc_status_t error code with a human-readable message
 * obtained from pqc_status_string().
 */
class Error : public std::runtime_error {
public:
    /**
     * Construct from a status code.
     */
    explicit Error(pqc_status_t status)
        : std::runtime_error(build_message(status))
        , status_(status) {}

    /**
     * Construct from a status code and a contextual prefix message.
     */
    Error(pqc_status_t status, const std::string& context)
        : std::runtime_error(context + ": " + pqc_status_string(status))
        , status_(status) {}

    /**
     * Return the underlying PQC status code.
     */
    pqc_status_t status() const noexcept { return status_; }

    /**
     * Check a status code and throw if it indicates an error.
     */
    static void check(pqc_status_t status) {
        if (status != PQC_OK) {
            throw Error(status);
        }
    }

    /**
     * Check a status code with additional context and throw on error.
     */
    static void check(pqc_status_t status, const std::string& context) {
        if (status != PQC_OK) {
            throw Error(status, context);
        }
    }

private:
    pqc_status_t status_;

    static std::string build_message(pqc_status_t status) {
        const char* msg = pqc_status_string(status);
        return msg ? std::string(msg)
                   : "PQC error code " + std::to_string(static_cast<int>(status));
    }
};

} // namespace pqc

#endif // PQC_ERROR_HPP
