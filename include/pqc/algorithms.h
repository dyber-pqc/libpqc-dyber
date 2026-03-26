/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Algorithm name constants and enumeration.
 */

#ifndef PQC_ALGORITHMS_H
#define PQC_ALGORITHMS_H

#include "pqc/common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------- */
/* KEM algorithm names                                                         */
/* -------------------------------------------------------------------------- */

#define PQC_KEM_ML_KEM_512      "ML-KEM-512"
#define PQC_KEM_ML_KEM_768      "ML-KEM-768"
#define PQC_KEM_ML_KEM_1024     "ML-KEM-1024"

#define PQC_KEM_HQC_128         "HQC-128"
#define PQC_KEM_HQC_192         "HQC-192"
#define PQC_KEM_HQC_256         "HQC-256"

#define PQC_KEM_BIKE_L1         "BIKE-L1"
#define PQC_KEM_BIKE_L3         "BIKE-L3"
#define PQC_KEM_BIKE_L5         "BIKE-L5"

#define PQC_KEM_MCELIECE_348864     "Classic-McEliece-348864"
#define PQC_KEM_MCELIECE_460896     "Classic-McEliece-460896"
#define PQC_KEM_MCELIECE_6688128    "Classic-McEliece-6688128"
#define PQC_KEM_MCELIECE_6960119    "Classic-McEliece-6960119"
#define PQC_KEM_MCELIECE_8192128    "Classic-McEliece-8192128"

#define PQC_KEM_FRODO_640_AES       "FrodoKEM-640-AES"
#define PQC_KEM_FRODO_640_SHAKE     "FrodoKEM-640-SHAKE"
#define PQC_KEM_FRODO_976_AES       "FrodoKEM-976-AES"
#define PQC_KEM_FRODO_976_SHAKE     "FrodoKEM-976-SHAKE"
#define PQC_KEM_FRODO_1344_AES      "FrodoKEM-1344-AES"
#define PQC_KEM_FRODO_1344_SHAKE    "FrodoKEM-1344-SHAKE"

#define PQC_KEM_NTRU_HPS_2048_509   "NTRU-HPS-2048-509"
#define PQC_KEM_NTRU_HPS_2048_677   "NTRU-HPS-2048-677"
#define PQC_KEM_NTRU_HPS_4096_821   "NTRU-HPS-4096-821"
#define PQC_KEM_NTRU_HRSS_701       "NTRU-HRSS-701"

#define PQC_KEM_NTRUPRIME_SNTRUP761     "sntrup761"
#define PQC_KEM_NTRUPRIME_SNTRUP857     "sntrup857"
#define PQC_KEM_NTRUPRIME_SNTRUP953     "sntrup953"
#define PQC_KEM_NTRUPRIME_SNTRUP1013    "sntrup1013"
#define PQC_KEM_NTRUPRIME_SNTRUP1277    "sntrup1277"

/* Hybrid KEM names */
#define PQC_KEM_HYBRID_MLKEM768_X25519  "ML-KEM-768+X25519"
#define PQC_KEM_HYBRID_MLKEM1024_P256   "ML-KEM-1024+P256"

/* -------------------------------------------------------------------------- */
/* Signature algorithm names                                                   */
/* -------------------------------------------------------------------------- */

#define PQC_SIG_ML_DSA_44       "ML-DSA-44"
#define PQC_SIG_ML_DSA_65       "ML-DSA-65"
#define PQC_SIG_ML_DSA_87       "ML-DSA-87"

#define PQC_SIG_SLH_DSA_SHA2_128S   "SLH-DSA-SHA2-128s"
#define PQC_SIG_SLH_DSA_SHA2_128F   "SLH-DSA-SHA2-128f"
#define PQC_SIG_SLH_DSA_SHA2_192S   "SLH-DSA-SHA2-192s"
#define PQC_SIG_SLH_DSA_SHA2_192F   "SLH-DSA-SHA2-192f"
#define PQC_SIG_SLH_DSA_SHA2_256S   "SLH-DSA-SHA2-256s"
#define PQC_SIG_SLH_DSA_SHA2_256F   "SLH-DSA-SHA2-256f"
#define PQC_SIG_SLH_DSA_SHAKE_128S  "SLH-DSA-SHAKE-128s"
#define PQC_SIG_SLH_DSA_SHAKE_128F  "SLH-DSA-SHAKE-128f"
#define PQC_SIG_SLH_DSA_SHAKE_192S  "SLH-DSA-SHAKE-192s"
#define PQC_SIG_SLH_DSA_SHAKE_192F  "SLH-DSA-SHAKE-192f"
#define PQC_SIG_SLH_DSA_SHAKE_256S  "SLH-DSA-SHAKE-256s"
#define PQC_SIG_SLH_DSA_SHAKE_256F  "SLH-DSA-SHAKE-256f"

#define PQC_SIG_FN_DSA_512      "FN-DSA-512"
#define PQC_SIG_FN_DSA_1024     "FN-DSA-1024"

#define PQC_SIG_SPHINCS_SHA2_128S    "SPHINCS+-SHA2-128s"
#define PQC_SIG_SPHINCS_SHA2_128F    "SPHINCS+-SHA2-128f"
#define PQC_SIG_SPHINCS_SHA2_192S    "SPHINCS+-SHA2-192s"
#define PQC_SIG_SPHINCS_SHA2_192F    "SPHINCS+-SHA2-192f"
#define PQC_SIG_SPHINCS_SHA2_256S    "SPHINCS+-SHA2-256s"
#define PQC_SIG_SPHINCS_SHA2_256F    "SPHINCS+-SHA2-256f"
#define PQC_SIG_SPHINCS_SHAKE_128S   "SPHINCS+-SHAKE-128s"
#define PQC_SIG_SPHINCS_SHAKE_128F   "SPHINCS+-SHAKE-128f"
#define PQC_SIG_SPHINCS_SHAKE_192S   "SPHINCS+-SHAKE-192s"
#define PQC_SIG_SPHINCS_SHAKE_192F   "SPHINCS+-SHAKE-192f"
#define PQC_SIG_SPHINCS_SHAKE_256S   "SPHINCS+-SHAKE-256s"
#define PQC_SIG_SPHINCS_SHAKE_256F   "SPHINCS+-SHAKE-256f"

#define PQC_SIG_MAYO_1          "MAYO-1"
#define PQC_SIG_MAYO_2          "MAYO-2"
#define PQC_SIG_MAYO_3          "MAYO-3"
#define PQC_SIG_MAYO_5          "MAYO-5"

#define PQC_SIG_UOV_I           "UOV-Is"
#define PQC_SIG_UOV_III         "UOV-IIIs"
#define PQC_SIG_UOV_V           "UOV-Vs"

#define PQC_SIG_SNOVA_24_5_4    "SNOVA-24-5-4"
#define PQC_SIG_SNOVA_25_8_3    "SNOVA-25-8-3"
#define PQC_SIG_SNOVA_28_17_3   "SNOVA-28-17-3"

#define PQC_SIG_CROSS_RSDP_128_FAST     "CROSS-RSDP-128-fast"
#define PQC_SIG_CROSS_RSDP_128_SMALL    "CROSS-RSDP-128-small"
#define PQC_SIG_CROSS_RSDP_192_FAST     "CROSS-RSDP-192-fast"
#define PQC_SIG_CROSS_RSDP_192_SMALL    "CROSS-RSDP-192-small"
#define PQC_SIG_CROSS_RSDP_256_FAST     "CROSS-RSDP-256-fast"
#define PQC_SIG_CROSS_RSDP_256_SMALL    "CROSS-RSDP-256-small"

/* Stateful signatures */
#define PQC_SIG_LMS_SHA256_H10      "LMS-SHA256-H10"
#define PQC_SIG_LMS_SHA256_H15      "LMS-SHA256-H15"
#define PQC_SIG_LMS_SHA256_H20      "LMS-SHA256-H20"
#define PQC_SIG_LMS_SHA256_H25      "LMS-SHA256-H25"

#define PQC_SIG_XMSS_SHA2_10_256    "XMSS-SHA2-10-256"
#define PQC_SIG_XMSS_SHA2_16_256    "XMSS-SHA2-16-256"
#define PQC_SIG_XMSS_SHA2_20_256    "XMSS-SHA2-20-256"

/* Hybrid signature names */
#define PQC_SIG_HYBRID_MLDSA65_ED25519  "ML-DSA-65+Ed25519"
#define PQC_SIG_HYBRID_MLDSA87_P256     "ML-DSA-87+P256"

/* -------------------------------------------------------------------------- */
/* Algorithm enumeration                                                       */
/* -------------------------------------------------------------------------- */

typedef struct {
    const char *name;
    pqc_alg_type_t type;
    pqc_security_level_t security_level;
    const char *nist_standard;
    int enabled;
} pqc_algorithm_info_t;

/* Get list of all enabled KEM algorithms */
PQC_API int pqc_kem_algorithm_count(void);
PQC_API const char *pqc_kem_algorithm_name(int index);
PQC_API int pqc_kem_is_enabled(const char *algorithm);

/* Get list of all enabled signature algorithms */
PQC_API int pqc_sig_algorithm_count(void);
PQC_API const char *pqc_sig_algorithm_name(int index);
PQC_API int pqc_sig_is_enabled(const char *algorithm);

/* Get detailed algorithm info */
PQC_API pqc_status_t pqc_algorithm_info(const char *name, pqc_algorithm_info_t *info);

#ifdef __cplusplus
}
#endif

#endif /* PQC_ALGORITHMS_H */
