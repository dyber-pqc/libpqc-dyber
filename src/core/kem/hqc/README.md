# HQC

HQC-128, HQC-192 and HQC-256 are the HQC v5.1 parameter sets HQC-1, HQC-3
and HQC-5 (NIST security categories 1, 3 and 5). NIST selected HQC for
standardization in March 2025; FIPS 207 is not final, so the encodings can
still change, and this code will follow the specification when it does.

## Where the code comes from

`ref/` is the reference implementation from the HQC team's repository,
<https://gitlab.com/pqc-hqc/hqc>, tag `v5.1.0` (commit `06567ccbad10`,
2026-10-26; archive `hqc-v5.1.0.tar.gz`, SHA-256
`66fa3238403dc45bf3b63d097c05d307407d6bf5655582d536ced4c2a0464c7f`). It is
in the public domain. The files were copied from `src/common` and `src/ref`
with these changes, each marked in the file header:

- The `#include <immintrin.h>` lines are removed. The reference code does
  not use intrinsics, and the include broke the build on ARM64.
- `BITMASK` in `hqc-*/parameters.h` shifted `1UL`, which is 32 bits on
  Windows (LLP64). For HQC-5, `PARAM_N % 64` is 37, so the shift was
  undefined and the mask that clears the unused top bits of every vector
  was wrong: with MSVC, HQC-256 produced keys and ciphertexts that matched
  none of the official vectors while still decrypting its own output. It
  now shifts a 64-bit one.
- `vect_generate_random_support1` in `vector.c`, which samples the secret
  vectors x and y at key generation, marks its accept bit public with
  `PQC_CT_DECLASSIFY`. The specification samples positions by rejection,
  so the loop's iteration count reveals how many candidates were rejected
  (out of range, or a repeat of a position already chosen); the rejected
  values are discarded and the accepted positions never reach a branch or
  an address. ctgrind flagged exactly this and nothing else; with the bit
  declassified it checks the rest of the code. The algorithm cannot change
  without changing the output, since the KATs fix how much of the XOF
  stream it consumes.
- `fips202.h` and `randombytes.h` are replaced by adapters onto the
  library's Keccak and `pqc_randombytes()`.
- `parameters.h`, `reed_solomon.h` and `hqc-kem.h` in `ref/` are stubs that
  select the per-level header from `HQC_LEVEL`, and `namespace.h` prefixes
  every external symbol by level.

`hqc1.c`, `hqc3.c` and `hqc5.c` each compile the whole of `ref/` as one
translation unit for one level (`hqc_level.inc`) and export its vtable;
`hqc.c` registers the three.

The reference serializes vectors by copying `uint64_t` arrays, so, like the
upstream code, it assumes a little-endian target.

## How it is checked

- `tests/kat/test_kat_hqc` regenerates the official response files
  `kats/ref/hqc-{1,3,5}/PQCkemKAT_32.rsp` (100 vectors each, from NIST's
  AES-256 CTR DRBG) and compares their SHA-256 with the published files'.
  It also checks implicit rejection for ciphertexts modified in u, v and
  the salt against K_bar computed independently from the specification.
- `tests/ct/test_ct` runs key generation, encapsulation and decapsulation
  under Valgrind with every random byte marked secret (ctgrind); HQC is
  in the CI gate, `tests/ct/ct_gate.txt`.

## Updating

`vendor_hqc.py` makes every change above; rerunning it on the extracted
v5.1.0 archive reproduces `ref/` exactly. To move to a new release,
download the tag's archive, check it against the release, update the tag
and commit in the script's header comment, rerun it, review the diff, and
update the three hashes in `tests/kat/test_kat_hqc.c` from the new
`kats/ref` files.
