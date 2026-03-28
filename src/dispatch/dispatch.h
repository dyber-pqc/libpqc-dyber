/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Runtime CPU feature detection and dispatch.
 */

#ifndef PQC_DISPATCH_H
#define PQC_DISPATCH_H

/* Re-use the canonical type from platform.h to avoid duplicate definitions */
#include "core/common/platform.h"

void pqc_detect_cpu_features(pqc_cpu_features_t *f);
const pqc_cpu_features_t *pqc_get_cpu_features(void);

#endif /* PQC_DISPATCH_H */
