# SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)

**Standard:** FIPS 205
**Type:** Digital Signature (Stateless, Hash-Based)
**Mathematical Basis:** Cryptographic hash functions
**Status:** NIST Standardized (August 2024)

## Parameter Sets

| Parameter Set | NIST Level | PK (bytes) | SK (bytes) | Sig (bytes) |
|--------------|-----------|-----------|-----------|------------|
| SLH-DSA-SHA2-128s | 1 | 32 | 64 | 7856 |
| SLH-DSA-SHA2-128f | 1 | 32 | 64 | 17088 |
| SLH-DSA-SHA2-192s | 3 | 48 | 96 | 16224 |
| SLH-DSA-SHA2-192f | 3 | 48 | 96 | 35664 |
| SLH-DSA-SHA2-256s | 5 | 64 | 128 | 29792 |
| SLH-DSA-SHA2-256f | 5 | 64 | 128 | 49856 |
| SLH-DSA-SHAKE-128s | 1 | 32 | 64 | 7856 |
| SLH-DSA-SHAKE-128f | 1 | 32 | 64 | 17088 |
| SLH-DSA-SHAKE-192s | 3 | 48 | 96 | 16224 |
| SLH-DSA-SHAKE-192f | 3 | 48 | 96 | 35664 |
| SLH-DSA-SHAKE-256s | 5 | 64 | 128 | 29792 |
| SLH-DSA-SHAKE-256f | 5 | 64 | 128 | 49856 |

"s" = small (slower signing, smaller signatures), "f" = fast (faster signing, larger signatures)

## Security

SLH-DSA's security relies solely on the security of the underlying hash functions. This provides a fundamentally different security assumption from lattice-based schemes, serving as a backup if lattice assumptions are broken.

## References

- [NIST FIPS 205](https://csrc.nist.gov/pubs/fips/205/final)
- [SPHINCS+ specification](https://sphincs.org/)
