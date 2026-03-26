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

libpqc-dyber implements post-quantum cryptographic algorithms. While we strive for correctness and security:

- All implementations target constant-time execution for secret-dependent operations
- Memory containing secret key material is zeroized on deallocation
- We validate against NIST Known Answer Test (KAT) vectors
- We run constant-time verification tools (valgrind/ctgrind) in CI

## Scope

The following are in scope for security reports:
- Timing side-channel vulnerabilities
- Memory safety issues (buffer overflows, use-after-free, etc.)
- Incorrect algorithm implementations that weaken security
- Key material leakage

## Acknowledgments

We gratefully acknowledge security researchers who responsibly disclose vulnerabilities.
