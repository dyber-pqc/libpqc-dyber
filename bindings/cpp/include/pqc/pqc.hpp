/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Master C++ header -- includes all public C++ API headers.
 */

#ifndef PQC_PQC_HPP
#define PQC_PQC_HPP

#include "pqc/error.hpp"
#include "pqc/bytes.hpp"
#include "pqc/algorithm.hpp"
#include "pqc/kem.hpp"
#include "pqc/sig.hpp"

namespace pqc {

/**
 * Initialize the PQC library. Call once before using any PQC functions.
 * @throws pqc::Error on failure.
 */
inline void init() {
    Error::check(pqc_init(), "pqc_init");
}

/**
 * Clean up the PQC library. Call once when done.
 */
inline void cleanup() noexcept {
    pqc_cleanup();
}

/**
 * RAII guard that calls pqc_init() on construction and pqc_cleanup()
 * on destruction.
 *
 * Example:
 * @code
 *   int main() {
 *       pqc::LibraryGuard guard;
 *       // ... use pqc::KEM, pqc::Signature, etc.
 *   }
 * @endcode
 */
class LibraryGuard {
public:
    LibraryGuard()  { init(); }
    ~LibraryGuard() { cleanup(); }

    LibraryGuard(const LibraryGuard&) = delete;
    LibraryGuard& operator=(const LibraryGuard&) = delete;
};

/**
 * Return the library version string.
 */
inline std::string version() {
    return pqc_version();
}

} // namespace pqc

#endif // PQC_PQC_HPP
