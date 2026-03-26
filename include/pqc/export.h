/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#ifndef PQC_EXPORT_H
#define PQC_EXPORT_H

#if defined(_WIN32) || defined(__CYGWIN__)
    #if defined(PQC_DLL_EXPORT)
        #define PQC_API __declspec(dllexport)
    #elif defined(PQC_SHARED)
        #define PQC_API __declspec(dllimport)
    #else
        #define PQC_API
    #endif
#elif defined(__GNUC__) && __GNUC__ >= 4
    #define PQC_API __attribute__((visibility("default")))
#else
    #define PQC_API
#endif

#endif /* PQC_EXPORT_H */
