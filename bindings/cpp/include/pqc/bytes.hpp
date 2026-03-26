/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Secure byte container with automatic zeroization.
 */

#ifndef PQC_BYTES_HPP
#define PQC_BYTES_HPP

#include <cstdint>
#include <cstring>
#include <vector>

#include <pqc/common.h>

namespace pqc {

/**
 * Custom allocator that zeroizes memory before deallocation.
 *
 * Uses pqc_memzero() for secure erasure of sensitive cryptographic
 * material (keys, shared secrets) when the container is destroyed.
 */
template <typename T>
class SecureAllocator {
public:
    using value_type = T;

    SecureAllocator() noexcept = default;

    template <typename U>
    SecureAllocator(const SecureAllocator<U>&) noexcept {}

    T* allocate(std::size_t n) {
        return static_cast<T*>(::operator new(n * sizeof(T)));
    }

    void deallocate(T* ptr, std::size_t n) noexcept {
        if (ptr && n > 0) {
            pqc_memzero(ptr, n * sizeof(T));
        }
        ::operator delete(ptr);
    }

    template <typename U>
    bool operator==(const SecureAllocator<U>&) const noexcept { return true; }

    template <typename U>
    bool operator!=(const SecureAllocator<U>&) const noexcept { return false; }
};

/**
 * Byte container with secure zeroization on destruction.
 *
 * Drop-in replacement for std::vector<uint8_t> that automatically
 * wipes memory when the vector is destroyed or reallocated.
 */
using Bytes = std::vector<uint8_t, SecureAllocator<uint8_t>>;

/**
 * Create a Bytes container from raw data.
 */
inline Bytes make_bytes(const uint8_t* data, std::size_t len) {
    return Bytes(data, data + len);
}

/**
 * Create a Bytes container of a given size, zero-initialized.
 */
inline Bytes make_bytes(std::size_t len) {
    return Bytes(len, 0);
}

} // namespace pqc

#endif // PQC_BYTES_HPP
