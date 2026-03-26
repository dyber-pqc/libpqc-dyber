/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

package com.dyber.pqc;

/**
 * Registry of well-known algorithm name constants.
 *
 * <p>These match the C-level {@code PQC_KEM_*} and {@code PQC_SIG_*} defines.
 * You may also pass any algorithm name string directly.</p>
 */
public final class Algorithm {

    private Algorithm() {
        // non-instantiable
    }

    // ---- KEM algorithms ----

    public static final String ML_KEM_512 = "ML-KEM-512";
    public static final String ML_KEM_768 = "ML-KEM-768";
    public static final String ML_KEM_1024 = "ML-KEM-1024";

    public static final String HQC_128 = "HQC-128";
    public static final String HQC_192 = "HQC-192";
    public static final String HQC_256 = "HQC-256";

    public static final String BIKE_L1 = "BIKE-L1";
    public static final String BIKE_L3 = "BIKE-L3";
    public static final String BIKE_L5 = "BIKE-L5";

    public static final String FRODO_640_AES = "FrodoKEM-640-AES";
    public static final String FRODO_640_SHAKE = "FrodoKEM-640-SHAKE";
    public static final String FRODO_976_AES = "FrodoKEM-976-AES";
    public static final String FRODO_976_SHAKE = "FrodoKEM-976-SHAKE";
    public static final String FRODO_1344_AES = "FrodoKEM-1344-AES";
    public static final String FRODO_1344_SHAKE = "FrodoKEM-1344-SHAKE";

    // Hybrid KEM
    public static final String ML_KEM_768_X25519 = "ML-KEM-768+X25519";
    public static final String ML_KEM_1024_P256 = "ML-KEM-1024+P256";

    // ---- Signature algorithms ----

    public static final String ML_DSA_44 = "ML-DSA-44";
    public static final String ML_DSA_65 = "ML-DSA-65";
    public static final String ML_DSA_87 = "ML-DSA-87";

    public static final String SLH_DSA_SHA2_128S = "SLH-DSA-SHA2-128s";
    public static final String SLH_DSA_SHA2_128F = "SLH-DSA-SHA2-128f";
    public static final String SLH_DSA_SHA2_192S = "SLH-DSA-SHA2-192s";
    public static final String SLH_DSA_SHA2_192F = "SLH-DSA-SHA2-192f";
    public static final String SLH_DSA_SHA2_256S = "SLH-DSA-SHA2-256s";
    public static final String SLH_DSA_SHA2_256F = "SLH-DSA-SHA2-256f";

    public static final String FN_DSA_512 = "FN-DSA-512";
    public static final String FN_DSA_1024 = "FN-DSA-1024";

    public static final String MAYO_1 = "MAYO-1";
    public static final String MAYO_2 = "MAYO-2";
    public static final String MAYO_3 = "MAYO-3";
    public static final String MAYO_5 = "MAYO-5";

    // Stateful signatures
    public static final String LMS_SHA256_H10 = "LMS-SHA256-H10";
    public static final String LMS_SHA256_H15 = "LMS-SHA256-H15";
    public static final String LMS_SHA256_H20 = "LMS-SHA256-H20";
    public static final String LMS_SHA256_H25 = "LMS-SHA256-H25";

    public static final String XMSS_SHA2_10_256 = "XMSS-SHA2-10-256";
    public static final String XMSS_SHA2_16_256 = "XMSS-SHA2-16-256";
    public static final String XMSS_SHA2_20_256 = "XMSS-SHA2-20-256";

    // Hybrid signatures
    public static final String ML_DSA_65_ED25519 = "ML-DSA-65+Ed25519";
    public static final String ML_DSA_87_P256 = "ML-DSA-87+P256";
}
