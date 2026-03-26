# libpqc-dyber - Post-Quantum Cryptography Library
# Copyright (c) 2024-2026 Dyber, Inc.
# SPDX-License-Identifier: Apache-2.0 OR MIT

"""Algorithm enumeration and query functions."""

from __future__ import annotations

from typing import List

from ._ffi import get_lib


def kem_algorithms() -> List[str]:
    """Return a list of all enabled KEM algorithm names."""
    lib = get_lib()
    count = lib.pqc_kem_algorithm_count()
    result = []
    for i in range(count):
        name = lib.pqc_kem_algorithm_name(i)
        if name:
            result.append(name.decode("utf-8"))
    return result


def sig_algorithms() -> List[str]:
    """Return a list of all enabled signature algorithm names."""
    lib = get_lib()
    count = lib.pqc_sig_algorithm_count()
    result = []
    for i in range(count):
        name = lib.pqc_sig_algorithm_name(i)
        if name:
            result.append(name.decode("utf-8"))
    return result


def kem_is_enabled(algorithm: str) -> bool:
    """Check if a KEM algorithm is enabled in this build."""
    lib = get_lib()
    return lib.pqc_kem_is_enabled(algorithm.encode("utf-8")) != 0


def sig_is_enabled(algorithm: str) -> bool:
    """Check if a signature algorithm is enabled in this build."""
    lib = get_lib()
    return lib.pqc_sig_is_enabled(algorithm.encode("utf-8")) != 0


def version() -> str:
    """Return the libpqc version string."""
    lib = get_lib()
    return lib.pqc_version().decode("utf-8")
