/* Selects the per-level hqc-kem.h (libpqc-dyber). */
#ifndef PQC_HQC_SELECT_KEM_H
#define PQC_HQC_SELECT_KEM_H
#if HQC_LEVEL == 1
#include "hqc-1/hqc-kem.h"
#elif HQC_LEVEL == 3
#include "hqc-3/hqc-kem.h"
#elif HQC_LEVEL == 5
#include "hqc-5/hqc-kem.h"
#else
#error "HQC_LEVEL must be 1, 3 or 5"
#endif
#endif
