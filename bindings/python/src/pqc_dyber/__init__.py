# libpqc-dyber - Post-Quantum Cryptography Library
# Copyright (c) 2024-2026 Dyber, Inc.
# SPDX-License-Identifier: Apache-2.0 OR MIT

"""
pqc_dyber -- Python bindings for the libpqc-dyber post-quantum cryptography library.

Quick start::

    from pqc_dyber import KEM, Signature

    # Key Encapsulation
    kem = KEM("ML-KEM-768")
    pk, sk = kem.keygen()
    ct, shared_secret_enc = kem.encaps(pk)
    shared_secret_dec = kem.decaps(ct, sk)
    assert shared_secret_enc == shared_secret_dec

    # Digital Signatures
    sig = Signature("ML-DSA-65")
    pk, sk = sig.keygen()
    signature = sig.sign(b"hello", sk)
    assert sig.verify(b"hello", signature, pk)
"""

__version__ = "0.1.0"

from .algorithms import (
    kem_algorithms,
    kem_is_enabled,
    sig_algorithms,
    sig_is_enabled,
    version,
)
from .exceptions import (
    AlgorithmNotSupportedError,
    DecapsulationFailedError,
    InvalidKeyError,
    PQCError,
    StateExhaustedError,
    VerificationFailedError,
)
from .kem import KEM
from .sig import Signature

__all__ = [
    # Version
    "__version__",
    "version",
    # Core classes
    "KEM",
    "Signature",
    # Algorithm helpers
    "kem_algorithms",
    "sig_algorithms",
    "kem_is_enabled",
    "sig_is_enabled",
    # Exceptions
    "PQCError",
    "AlgorithmNotSupportedError",
    "InvalidKeyError",
    "VerificationFailedError",
    "DecapsulationFailedError",
    "StateExhaustedError",
]
