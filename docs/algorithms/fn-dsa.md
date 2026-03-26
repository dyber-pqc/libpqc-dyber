# FN-DSA (Fast-Fourier Lattice-Based Compact Signatures over NTRU)

**Standard:** FIPS 206 (Draft)
**Type:** Digital Signature
**Mathematical Basis:** NTRU Lattices, Hash-Then-Sign
**Status:** NIST Draft Standard (expected finalization ~2027)
**Also known as:** Falcon

## Parameter Sets

| Parameter | FN-DSA-512 | FN-DSA-1024 |
|-----------|-----------|------------|
| NIST Level | 1 | 5 |
| n | 512 | 1024 |
| sigma | 165.736... | 168.388... |
| sigmin | 1.277... | 1.298... |
| Public Key (bytes) | 897 | 1793 |
| Secret Key (bytes) | 1281 | 2305 |
| Signature (bytes) | ~666 | ~1280 |

## Key Characteristics

- **Compact signatures** — significantly smaller than ML-DSA
- **Complex signing** — requires FFT-based Gaussian sampling
- **Ideal for certificates** — especially root/intermediate CAs
- **Not constant-time by nature** — requires careful implementation of Gaussian sampler

## References

- [NIST FIPS 206 Draft](https://csrc.nist.gov/pubs/fips/206/ipd)
- [Falcon specification](https://falcon-sign.info/)
