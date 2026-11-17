/*
 * libpqc-dyber: the incremental SHA-3 / SHAKE256 interface the HQC
 * reference expects (PQClean naming), over the library's Keccak.
 */
#ifndef HQC_FIPS202_H
#define HQC_FIPS202_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "core/common/hash/keccak.h"

typedef struct {
    uint64_t state[25];
    uint8_t buf[200];
    size_t pos;          /* bytes buffered (absorb) / consumed (squeeze) */
    size_t rate;
    uint8_t domain;      /* 0x06 SHA-3, 0x1F SHAKE */
} hqc_keccak_inc_ctx;

typedef hqc_keccak_inc_ctx sha3_256incctx;
typedef hqc_keccak_inc_ctx sha3_512incctx;
typedef hqc_keccak_inc_ctx shake256incctx;

static inline void hqc_keccak_inc_init(hqc_keccak_inc_ctx *c, size_t rate, uint8_t domain) {
    pqc_keccak_init(c->state);
    memset(c->buf, 0, sizeof c->buf);
    c->pos = 0;
    c->rate = rate;
    c->domain = domain;
}

static inline void hqc_keccak_inc_absorb(hqc_keccak_inc_ctx *c, const uint8_t *in, size_t len) {
    while (len > 0) {
        size_t take = c->rate - c->pos;
        if (take > len) take = len;
        memcpy(c->buf + c->pos, in, take);
        c->pos += take;
        in += take;
        len -= take;
        if (c->pos == c->rate) {
            /* A full block: XOR it in and permute. */
            pqc_keccak_absorb(c->state, c->rate, c->buf, c->rate);
            c->pos = 0;
        }
    }
}

static inline void hqc_keccak_inc_finalize(hqc_keccak_inc_ctx *c) {
    size_t i;
    memset(c->buf + c->pos, 0, c->rate - c->pos);
    c->buf[c->pos] ^= c->domain;
    c->buf[c->rate - 1] ^= 0x80;
    for (i = 0; i < c->rate / 8; i++) {
        uint64_t v = 0;
        unsigned j;
        for (j = 0; j < 8; j++) v |= (uint64_t)c->buf[8 * i + j] << (8 * j);
        c->state[i] ^= v;
    }
    pqc_keccak_f1600(c->state);
    c->pos = 0;                 /* squeeze offset into the current block */
}

static inline void hqc_keccak_inc_squeeze(hqc_keccak_inc_ctx *c, uint8_t *out, size_t len) {
    while (len > 0) {
        size_t i;
        if (c->pos == c->rate) {
            pqc_keccak_f1600(c->state);
            c->pos = 0;
        }
        for (i = c->pos; i < c->rate && len > 0; i++, len--)
            *out++ = (uint8_t)(c->state[i / 8] >> (8 * (i % 8)));
        c->pos = i;
    }
}

#define shake256_inc_init(c)                hqc_keccak_inc_init((c), 136, 0x1F)
#define shake256_inc_absorb(c, in, len)     hqc_keccak_inc_absorb((c), (in), (len))
#define shake256_inc_finalize(c)            hqc_keccak_inc_finalize(c)
#define shake256_inc_squeeze(out, len, c)   hqc_keccak_inc_squeeze((c), (out), (len))

#define sha3_256_inc_init(c)                hqc_keccak_inc_init((c), 136, 0x06)
#define sha3_256_inc_absorb(c, in, len)     hqc_keccak_inc_absorb((c), (in), (len))
#define sha3_256_inc_finalize(out, c) \
    do { hqc_keccak_inc_finalize(c); hqc_keccak_inc_squeeze((c), (out), 32); } while (0)

#define sha3_512_inc_init(c)                hqc_keccak_inc_init((c), 72, 0x06)
#define sha3_512_inc_absorb(c, in, len)     hqc_keccak_inc_absorb((c), (in), (len))
#define sha3_512_inc_finalize(out, c) \
    do { hqc_keccak_inc_finalize(c); hqc_keccak_inc_squeeze((c), (out), 64); } while (0)

#endif
