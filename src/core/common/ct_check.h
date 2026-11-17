/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Annotations for constant-time verification with Valgrind ("ctgrind").
 *
 * tests/ct/test_ct.c marks every byte the library draws from its RNG as
 * undefined. Memcheck then propagates that through the computation and
 * reports any conditional branch or memory address that depends on it --
 * which is exactly a secret-dependent branch or table lookup.
 *
 * Some values are computed from secrets but are public by definition: a
 * public key, a ciphertext, a signature, or the seed FIPS 203 / FIPS 204
 * expand the public matrix from. Branching on those is not a leak.
 * PQC_CT_DECLASSIFY() marks such a value public at the point the
 * specification makes it public, so that memcheck stops tracking it.
 * Every use must say why the value is public. Declassifying a value that
 * is in fact secret silences a real finding, so these are reviewed like
 * any other security-relevant change.
 *
 * Outside a PQC_CT_TESTING build both macros compile to nothing.
 */

#ifndef PQC_CT_CHECK_H
#define PQC_CT_CHECK_H

#if defined(PQC_CT_TESTING) && PQC_CT_TESTING
#  include <valgrind/memcheck.h>
#  define PQC_CT_DECLASSIFY(p, n) \
       ((void)VALGRIND_MAKE_MEM_DEFINED((p), (n)))
#  define PQC_CT_POISON(p, n) \
       ((void)VALGRIND_MAKE_MEM_UNDEFINED((p), (n)))
#else
#  define PQC_CT_DECLASSIFY(p, n) ((void)(p), (void)(n))
#  define PQC_CT_POISON(p, n)     ((void)(p), (void)(n))
#endif

#endif /* PQC_CT_CHECK_H */
