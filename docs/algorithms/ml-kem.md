# ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)

**Standard:** FIPS 203
**Type:** Key Encapsulation Mechanism (KEM)
**Mathematical Basis:** Module Learning with Errors (MLWE)
**Status:** NIST Standardized (August 2024)

## Parameter Sets

| Parameter | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
|-----------|-----------|-----------|------------|
| NIST Level | 1 | 3 | 5 |
| n | 256 | 256 | 256 |
| k | 2 | 3 | 4 |
| q | 3329 | 3329 | 3329 |
| eta1 | 3 | 2 | 2 |
| eta2 | 2 | 2 | 2 |
| du | 10 | 10 | 11 |
| dv | 4 | 4 | 5 |
| Public Key (bytes) | 800 | 1184 | 1568 |
| Secret Key (bytes) | 1632 | 2400 | 3168 |
| Ciphertext (bytes) | 768 | 1088 | 1568 |
| Shared Secret (bytes) | 32 | 32 | 32 |

## Usage

```c
#include <pqc/pqc.h>

PQC_KEM *kem = pqc_kem_new("ML-KEM-768");
// ... keygen, encaps, decaps ...
pqc_kem_free(kem);
```

## Security

ML-KEM's security relies on the hardness of the Module Learning with Errors (MLWE) problem. It provides IND-CCA2 security through a Fujisaki-Okamoto transform applied to an IND-CPA scheme.

## References

- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
- [CRYSTALS-Kyber specification](https://pq-crystals.org/kyber/)
