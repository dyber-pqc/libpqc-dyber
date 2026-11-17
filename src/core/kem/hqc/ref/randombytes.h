/* libpqc-dyber: the reference's randombytes() is the library RNG. */
#ifndef HQC_RANDOMBYTES_H
#define HQC_RANDOMBYTES_H

#include <stddef.h>
#include <stdint.h>
#include "pqc/rand.h"

static inline int randombytes(uint8_t *out, size_t outlen) {
    return pqc_randombytes(out, outlen) == PQC_OK ? 0 : -1;
}

#endif
