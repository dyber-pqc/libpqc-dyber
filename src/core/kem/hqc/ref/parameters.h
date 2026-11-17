/* Selects the per-level parameters.h (libpqc-dyber). */
#ifndef PQC_HQC_SELECT_PARAMETERS_H
#define PQC_HQC_SELECT_PARAMETERS_H
#if HQC_LEVEL == 1
#include "hqc-1/parameters.h"
#elif HQC_LEVEL == 3
#include "hqc-3/parameters.h"
#elif HQC_LEVEL == 5
#include "hqc-5/parameters.h"
#else
#error "HQC_LEVEL must be 1, 3 or 5"
#endif
#endif
