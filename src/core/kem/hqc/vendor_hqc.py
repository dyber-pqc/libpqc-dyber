"""Vendor the HQC v5.1.0 reference implementation into src/core/kem/hqc/ref.

Run from the repository root:
    python src/core/kem/hqc/vendor_hqc.py <extracted hqc-v5.1.0 directory>
"""
import os
import re
import shutil
import sys

SRC = sys.argv[1]
DST = 'src/core/kem/hqc/ref'

COMMON = ['code.c', 'code.h', 'crypto_memset.c', 'crypto_memset.h',
          'hqc-kem.c', 'reed_muller.h', 'symmetric.c', 'symmetric.h']
REF = ['data_structures.h', 'gf.c', 'gf.h', 'gf2x.c', 'gf2x.h', 'hqc.c',
       'hqc.h', 'parsing.c', 'parsing.h', 'reed_muller.c', 'reed_solomon.c',
       'vector.c', 'vector.h']

HEADER = ('/*\n'
          ' * Vendored from the HQC reference implementation, v5.1.0\n'
          ' * (https://gitlab.com/pqc-hqc/hqc, tag v5.1.0, commit 06567ccbad10),\n'
          ' * which is in the public domain. Changes for libpqc-dyber: the\n'
          ' * unused <immintrin.h> includes are removed so the portable code\n'
          ' * builds on every architecture, BITMASK shifts a 64-bit one (1UL is\n'
          ' * 32 bits on Windows, which broke HQC-5 there), and SHA-3/SHAKE and\n'
          ' * the RNG come from the library (fips202.h, randombytes.h); vector.c\n'
          ' * marks the key sampler\'s accept bit public for ctgrind.\n'
          ' * See ../README.md.\n'
          ' */\n')

os.makedirs(DST, exist_ok=True)
for e in os.listdir(DST):
    q = os.path.join(DST, e)
    shutil.rmtree(q) if os.path.isdir(q) else os.remove(q)


def copy(src, dst):
    s = open(src, encoding='utf-8').read().replace('\r\n', '\n')
    s = re.sub(r'#include <immintrin\.h>\n', '', s)
    # BITMASK shifted 1UL, which is 32 bits on LLP64 (Windows): for HQC-5,
    # PARAM_N % 64 == 37, so the shift was undefined and the mask wrong.
    old = '#define BITMASK(a, size)  ((1UL << (a % size)) - 1)'
    if old in s:
        s = s.replace(old, '#define BITMASK(a, size)  (((uint64_t)1 << ((a) % (size))) - 1)')
        if '#include <stdint.h>' not in s:
            s = s.replace('#define HQC_PARAMETERS_H\n', '#define HQC_PARAMETERS_H\n\n#include <stdint.h>\n', 1)
    if os.path.basename(src) == 'vector.c' and dst.endswith('vector.c'):
        old = '        support[i] = candidate;\n        i += accept;\n'
        assert s.count(old) == 1, 'vector.c: support1 anchor'
        s = s.replace(old, (
            '        /*\n'
            '         * libpqc-dyber: the specification samples by rejection, so the\n'
            '         * number of iterations reveals how many candidates were rejected\n'
            '         * (out of range, or equal to a position already chosen). The\n'
            '         * rejected values are discarded and the accepted positions do not\n'
            '         * reach control flow or addresses; only the count is revealed.\n'
            '         * Mark the accept bit public so ctgrind checks everything else.\n'
            '         */\n'
            '        PQC_CT_DECLASSIFY(&accept, sizeof accept);\n'
            '        support[i] = candidate;\n'
            '        i += accept;\n'))
        s = s.replace('#include "vector.h"\n', '#include "vector.h"\n#include "core/common/ct_check.h"\n', 1)
        assert 'core/common/ct_check.h' in s, 'vector.c: include anchor'
    open(dst, 'w', encoding='utf-8', newline='\n').write(HEADER + s)


for f in COMMON:
    copy(os.path.join(SRC, 'src/common', f), os.path.join(DST, f))
for f in REF:
    copy(os.path.join(SRC, 'src/ref', f), os.path.join(DST, f))
for lvl in (1, 3, 5):
    d = os.path.join(DST, f'hqc-{lvl}')
    os.makedirs(d)
    copy(os.path.join(SRC, f'src/ref/hqc-{lvl}/parameters.h'), os.path.join(d, 'parameters.h'))
    copy(os.path.join(SRC, f'src/ref/hqc-{lvl}/reed_solomon.h'), os.path.join(d, 'reed_solomon.h'))
    copy(os.path.join(SRC, f'src/common/hqc-{lvl}/hqc-kem.h'), os.path.join(d, 'hqc-kem.h'))

# Level-selecting stubs: the vendored sources include these by plain name;
# HQC_LEVEL is set by the translation unit that includes them.
for name, guard in (('parameters.h', 'PQC_HQC_SELECT_PARAMETERS_H'),
                    ('reed_solomon.h', 'PQC_HQC_SELECT_REED_SOLOMON_H'),
                    ('hqc-kem.h', 'PQC_HQC_SELECT_KEM_H')):
    open(os.path.join(DST, name), 'w', newline='\n').write(f'''/* Selects the per-level {name} (libpqc-dyber). */
#ifndef {guard}
#define {guard}
#if HQC_LEVEL == 1
#include "hqc-1/{name}"
#elif HQC_LEVEL == 3
#include "hqc-3/{name}"
#elif HQC_LEVEL == 5
#include "hqc-5/{name}"
#else
#error "HQC_LEVEL must be 1, 3 or 5"
#endif
#endif
''')

open(os.path.join(DST, 'randombytes.h'), 'w', newline='\n').write('''/* libpqc-dyber: the reference's randombytes() is the library RNG. */
#ifndef HQC_RANDOMBYTES_H
#define HQC_RANDOMBYTES_H

#include <stddef.h>
#include <stdint.h>
#include "pqc/rand.h"

static inline int randombytes(uint8_t *out, size_t outlen) {
    return pqc_randombytes(out, outlen) == PQC_OK ? 0 : -1;
}

#endif
''')

open(os.path.join(DST, 'fips202.h'), 'w', newline='\n').write('''/*
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
#define sha3_256_inc_finalize(out, c) \\
    do { hqc_keccak_inc_finalize(c); hqc_keccak_inc_squeeze((c), (out), 32); } while (0)

#define sha3_512_inc_init(c)                hqc_keccak_inc_init((c), 72, 0x06)
#define sha3_512_inc_absorb(c, in, len)     hqc_keccak_inc_absorb((c), (in), (len))
#define sha3_512_inc_finalize(out, c) \\
    do { hqc_keccak_inc_finalize(c); hqc_keccak_inc_squeeze((c), (out), 64); } while (0)

#endif
''')

# Namespace every external symbol so the three levels link side by side.
names = set()
for f in os.listdir(DST):
    if not f.endswith('.c'):
        continue
    s = open(os.path.join(DST, f), encoding='utf-8').read()
    for m in re.finditer(r'^(?!static)[A-Za-z_][\w \t\*]*?\b([A-Za-z_]\w*)\s*\([^;{]*\)\s*\{', s, re.M):
        names.add(m.group(1))
names.add('memset_volatile')  # global function pointer in crypto_memset.c
names -= {'if', 'for', 'while', 'switch', 'return', 'sizeof'}
with open(os.path.join(DST, 'namespace.h'), 'w', newline='\n') as fh:
    fh.write('/* libpqc-dyber: per-level prefixes for the vendored HQC symbols. */\n')
    fh.write('#ifndef PQC_HQC_NAMESPACE_H\n#define PQC_HQC_NAMESPACE_H\n')
    fh.write('#define HQC_NS_(l, x) pqc_hqc##l##_##x\n#define HQC_NS2_(l, x) HQC_NS_(l, x)\n')
    fh.write('#define HQC_NS(x) HQC_NS2_(HQC_LEVEL, x)\n')
    for n in sorted(names):
        fh.write(f'#define {n} HQC_NS({n})\n')
    fh.write('#endif\n')
print(sorted(names))
