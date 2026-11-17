/* Selects the per-level reed_solomon.h (libpqc-dyber). */
#ifndef PQC_HQC_SELECT_REED_SOLOMON_H
#define PQC_HQC_SELECT_REED_SOLOMON_H
#if HQC_LEVEL == 1
#include "hqc-1/reed_solomon.h"
#elif HQC_LEVEL == 3
#include "hqc-3/reed_solomon.h"
#elif HQC_LEVEL == 5
#include "hqc-5/reed_solomon.h"
#else
#error "HQC_LEVEL must be 1, 3 or 5"
#endif
#endif
