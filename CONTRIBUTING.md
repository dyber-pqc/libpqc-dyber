# Contributing to libpqc-dyber

Thank you for your interest in contributing to libpqc-dyber! This project is maintained by Dyber, Inc. and welcomes contributions from the community.

## Getting Started

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `cmake -B build && cmake --build build && ctest --test-dir build`
5. Submit a pull request

## Code Style

### C/C++
- Follow the `.clang-format` configuration
- Use `snake_case` for functions and variables
- Use `UPPER_CASE` for macros and constants
- Prefix public API functions with `pqc_`
- All public headers go in `include/pqc/`

### General
- Follow the `.editorconfig` settings
- Keep lines under 100 characters
- Write meaningful commit messages

## Security Requirements

**Critical**: All cryptographic code must be:
- **Constant-time** for secret-dependent operations
- **Memory-safe** with proper bounds checking
- **Zeroizing** secret data on deallocation
- **Validated** against Known Answer Test (KAT) vectors

## Pull Request Process

1. Ensure all tests pass
2. Add tests for new functionality
3. Update documentation as needed
4. One approval required for merge
5. Squash commits before merge

## Algorithm Contributions

When implementing a new algorithm:
1. Create a datasheet in `docs/algorithms/`
2. Include all parameter sets
3. Add KAT vectors in `tests/kat/`
4. Add unit tests in `tests/unit/`
5. Register in the algorithm dispatch table

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 and MIT dual license.
