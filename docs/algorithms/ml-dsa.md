# ML-DSA (Module-Lattice-Based Digital Signature Algorithm)

**Standard:** FIPS 204
**Type:** Digital Signature
**Mathematical Basis:** Module Learning with Errors (MLWE)
**Status:** NIST Standardized (August 2024)

## Parameter Sets

| Parameter | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|-----------|----------|----------|----------|
| NIST Level | 2 | 3 | 5 |
| n | 256 | 256 | 256 |
| q | 8380417 | 8380417 | 8380417 |
| k | 4 | 6 | 8 |
| l | 4 | 5 | 7 |
| eta | 2 | 4 | 2 |
| tau | 39 | 49 | 60 |
| beta | 78 | 196 | 120 |
| gamma1 | 2^17 | 2^19 | 2^19 |
| gamma2 | (q-1)/88 | (q-1)/32 | (q-1)/32 |
| omega | 80 | 55 | 75 |
| Public Key (bytes) | 1312 | 1952 | 2592 |
| Secret Key (bytes) | 2560 | 4032 | 4896 |
| Signature (bytes) | 2420 | 3309 | 4627 |

## Usage

```c
#include <pqc/pqc.h>

PQC_SIG *sig = pqc_sig_new("ML-DSA-65");
// ... keygen, sign, verify ...
pqc_sig_free(sig);
```

## Security

ML-DSA's security relies on the hardness of finding short vectors in module lattices. The signing process uses a Fiat-Shamir with Aborts paradigm for EUF-CMA security.

## References

- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
- [CRYSTALS-Dilithium specification](https://pq-crystals.org/dilithium/)
