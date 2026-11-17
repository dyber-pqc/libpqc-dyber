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
  for ML-KEM, ML-DSA, SLH-DSA, BIKE, FrodoKEM, the hybrid schemes,
  LMS-SHA256-H10 and XMSS-SHA2-10-256 (`tests/ct/ct_gate.txt`); run
  weekly, and reported, for every algorithm. This covers the paths the
  test exercises in a gcc -O2 x86-64 build; it does not see
  variable-time instructions or what other compilers emit.
- ML-KEM against NIST's ACVP vectors for FIPS 203 (key generation,
  encapsulation, decapsulation and the section 7.2 / 7.3 input checks;
  240 tests)
- ML-DSA and SLH-DSA against NIST's ACVP vectors for FIPS 204 and 205
  (key generation, deterministic and hedged signing, verification;
  210 and 344 tests, through the pure external interface)
- BIKE against all 300 official round 4 known-answer vectors, and HQC
  against all 300 official v5.1 vectors, by regenerating the response
  files with NIST's DRBG (`tests/kat/`)
- Round-trip tests, and a regression suite asserting the specific invariant
  behind each previously reported defect
- Zero-warning builds, reproducible builds, and static analysis

Design intent that CI does **not** yet verify:

- Constant-time execution of the algorithm families that are not yet
  functionally correct. They are hidden unless the caller opts in with
  `pqc_set_experimental(1)`.
- Known-answer vectors for the post-quantum algorithms other than ML-KEM,
  ML-DSA, SLH-DSA, BIKE and HQC.
- HashML-DSA / HashSLH-DSA (pre-hash signing), which is not implemented,
  and the internal and external-mu signing interfaces, which are not
  exposed, so their ACVP vectors cannot be run.
- Deep fuzzing. CI fuzzes signature verification and KEM decapsulation /
  encapsulation for 10 minutes per target per run (`tests/fuzz/`); that
  is a smoke test, not continuous fuzzing. A few algorithms are fuzzed
  with attacker-chosen keys only, because setting up valid keys for them
  is too slow under AddressSanitizer.

Secret key material is zeroized on deallocation.

## Implementation status

ML-KEM (FIPS 203; NIST's ACVP vectors as of 0.3.0), the hash layer and, as
of 0.2.1, the classical halves of the hybrid schemes are tested against
independent references; so, as of
0.3.0, are ML-DSA (FIPS 204) and SLH-DSA (FIPS 205), and BIKE (round 4,
against its official known-answer tests). Several other algorithm families are incomplete. The "Known
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
