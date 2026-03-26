/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Algorithm enumeration helpers for C++.
 */

#ifndef PQC_ALGORITHM_HPP
#define PQC_ALGORITHM_HPP

#include <string>
#include <vector>

#include <pqc/algorithms.h>
#include <pqc/common.h>

#include "pqc/error.hpp"

namespace pqc {

/**
 * NIST security level.
 */
enum class SecurityLevel : int {
    Level1 = PQC_SECURITY_LEVEL_1,
    Level2 = PQC_SECURITY_LEVEL_2,
    Level3 = PQC_SECURITY_LEVEL_3,
    Level4 = PQC_SECURITY_LEVEL_4,
    Level5 = PQC_SECURITY_LEVEL_5,
};

/**
 * Algorithm type classification.
 */
enum class AlgorithmType : int {
    KEM           = PQC_ALG_TYPE_KEM,
    Signature     = PQC_ALG_TYPE_SIG,
    StatefulSig   = PQC_ALG_TYPE_SIG_STATEFUL,
    HybridKEM     = PQC_ALG_TYPE_HYBRID_KEM,
    HybridSig     = PQC_ALG_TYPE_HYBRID_SIG,
};

/**
 * Detailed information about an algorithm.
 */
struct AlgorithmInfo {
    std::string name;
    AlgorithmType type;
    SecurityLevel security_level;
    std::string nist_standard;
    bool enabled;
};

/**
 * Retrieve detailed info about a named algorithm.
 */
inline AlgorithmInfo algorithm_info(const std::string& name) {
    pqc_algorithm_info_t info{};
    Error::check(pqc_algorithm_info(name.c_str(), &info),
                 "pqc_algorithm_info(" + name + ")");
    return AlgorithmInfo{
        info.name,
        static_cast<AlgorithmType>(info.type),
        static_cast<SecurityLevel>(info.security_level),
        info.nist_standard ? info.nist_standard : "",
        info.enabled != 0,
    };
}

/**
 * Return all enabled KEM algorithm names.
 */
inline std::vector<std::string> kem_algorithms() {
    std::vector<std::string> result;
    int count = pqc_kem_algorithm_count();
    result.reserve(static_cast<std::size_t>(count));
    for (int i = 0; i < count; ++i) {
        const char* name = pqc_kem_algorithm_name(i);
        if (name) {
            result.emplace_back(name);
        }
    }
    return result;
}

/**
 * Return all enabled signature algorithm names.
 */
inline std::vector<std::string> sig_algorithms() {
    std::vector<std::string> result;
    int count = pqc_sig_algorithm_count();
    result.reserve(static_cast<std::size_t>(count));
    for (int i = 0; i < count; ++i) {
        const char* name = pqc_sig_algorithm_name(i);
        if (name) {
            result.emplace_back(name);
        }
    }
    return result;
}

/**
 * Check if a KEM algorithm is enabled in this build.
 */
inline bool kem_is_enabled(const std::string& algorithm) {
    return pqc_kem_is_enabled(algorithm.c_str()) != 0;
}

/**
 * Check if a signature algorithm is enabled in this build.
 */
inline bool sig_is_enabled(const std::string& algorithm) {
    return pqc_sig_is_enabled(algorithm.c_str()) != 0;
}

} // namespace pqc

#endif // PQC_ALGORITHM_HPP
