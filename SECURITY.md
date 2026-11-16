# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in libpqc-dyber, please report it responsibly.

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please email: **security@dyber.org**

Include:
- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact

We will acknowledge receipt within 48 hours and provide a detailed response within 7 days.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x.x   | Current development |

## Security Considerations

libpqc-dyber implements post-quantum cryptographic algorithms. Not every
algorithm in this repository is finished — see "Implementation status" below
before depending on one.

What CI verifies:

- Memory safety, under AddressSanitizer, UndefinedBehaviorSanitizer and
  Valgrind memcheck, across the test suite
- Published known-answer vectors for the hash layer (FIPS 180-4, FIPS 202,
  RFC 4231) and for the classical primitives used by the hybrid schemes
  (RFC 7748, RFC 8032, RFC 6979, NIST CAVP)
- Interoperability of ML-DSA and SLH-DSA with OpenSSL (3.5 or later), in
  both directions, for every parameter set, with and without a context
  string
- Constant-time execution, with the ctgrind approach: `tests/ct/test_ct`
  marks every byte from the RNG as undefined to Valgrind, which then
  reports any branch or memory address derived from secret data. Blocking
  for ML-KEM, ML-DSA, SLH-DSA, FrodoKEM, the hybrid schemes,
  LMS-SHA256-H10 and XMSS-SHA2-10-256 (`tests/ct/ct_gate.txt`); run
  weekly, and reported, for every algorithm. This covers the paths the
  test exercises in a gcc -O2 x86-64 build; it does not see
  variable-time instructions or what other compilers emit.
- Round-trip tests, and a regression suite asserting the specific invariant
  behind each previously reported defect
- Zero-warning builds, reproducible builds, and static analysis

Design intent that CI does **not** yet verify:

- Constant-time execution of HQC and BIKE, which the ctgrind run shows
  they do not have, and of the algorithm families that are not yet
  functionally correct.
- Known-answer vectors for the post-quantum algorithms themselves. None are
  in the repository yet.
- Deep fuzzing. CI fuzzes signature verification and KEM decapsulation /
  encapsulation for 10 minutes per target per run (`tests/fuzz/`); that
  is a smoke test, not continuous fuzzing. BIKE decapsulation is not
  fuzzed because it is too slow (CHANGELOG known issues), and a few
  algorithms are fuzzed with attacker-chosen keys only.

Secret key material is zeroized on deallocation.

## Implementation status

ML-KEM (FIPS 203), the hash layer and, as of 0.2.1, the classical halves of
the hybrid schemes are tested against independent references; so, as of
0.3.0, are ML-DSA (FIPS 204) and SLH-DSA (FIPS 205). Several other algorithm families are incomplete. The "Known
issues" section of CHANGELOG.md is the maintained list; it is kept specific
on purpose, because a general statement that some algorithms are "being
filled in" is too easy to misread.

## Scope

The following are in scope for security reports:
- Timing side-channel vulnerabilities
- Memory safety issues (buffer overflows, use-after-free, etc.)
- Incorrect algorithm implementations that weaken security
- Key material leakage

## Acknowledgments

We gratefully acknowledge security researchers who responsibly disclose vulnerabilities.
