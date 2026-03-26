# libpqc-dyber - Post-Quantum Cryptography Library
# Copyright (c) 2024-2026 Dyber, Inc.
# SPDX-License-Identifier: Apache-2.0 OR MIT

"""Exception hierarchy for the PQC library."""


class PQCError(Exception):
    """Base exception for all PQC library errors."""

    # Maps C enum values to human-readable names.
    _STATUS_NAMES = {
        0: "PQC_OK",
        -1: "PQC_ERROR",
        -2: "PQC_ERROR_INVALID_ARGUMENT",
        -3: "PQC_ERROR_ALLOC",
        -4: "PQC_ERROR_NOT_SUPPORTED",
        -5: "PQC_ERROR_INVALID_KEY",
        -6: "PQC_ERROR_VERIFICATION_FAILED",
        -7: "PQC_ERROR_DECAPSULATION_FAILED",
        -8: "PQC_ERROR_RNG_FAILED",
        -9: "PQC_ERROR_BUFFER_TOO_SMALL",
        -10: "PQC_ERROR_INTERNAL",
        -11: "PQC_ERROR_STATE_EXHAUSTED",
    }

    def __init__(self, status_code: int, context: str = ""):
        self.status_code = status_code
        name = self._STATUS_NAMES.get(status_code, f"UNKNOWN({status_code})")
        msg = f"{context}: {name}" if context else name
        super().__init__(msg)


class AlgorithmNotSupportedError(PQCError):
    """Raised when the requested algorithm is not supported or not enabled."""

    def __init__(self, algorithm: str):
        super().__init__(-4, f"Algorithm not supported: {algorithm}")
        self.algorithm = algorithm


class InvalidKeyError(PQCError):
    """Raised when a key is invalid."""

    def __init__(self, context: str = ""):
        super().__init__(-5, context or "Invalid key")


class VerificationFailedError(PQCError):
    """Raised when signature verification fails."""

    def __init__(self, context: str = ""):
        super().__init__(-6, context or "Verification failed")


class DecapsulationFailedError(PQCError):
    """Raised when KEM decapsulation fails."""

    def __init__(self, context: str = ""):
        super().__init__(-7, context or "Decapsulation failed")


class StateExhaustedError(PQCError):
    """Raised when a stateful signature scheme has exhausted its state."""

    def __init__(self, context: str = ""):
        super().__init__(-11, context or "State exhausted")


# Map status codes to specific exception subclasses.
_STATUS_EXCEPTION_MAP = {
    -4: AlgorithmNotSupportedError,
    -5: InvalidKeyError,
    -6: VerificationFailedError,
    -7: DecapsulationFailedError,
    -11: StateExhaustedError,
}


def check_status(status: int, context: str = "") -> None:
    """Check a pqc_status_t return code and raise on error.

    Args:
        status: The integer status code returned by a C function.
        context: Optional context string for the error message.

    Raises:
        PQCError: (or a subclass) if *status* is not PQC_OK (0).
    """
    if status == 0:
        return
    exc_cls = _STATUS_EXCEPTION_MAP.get(status, PQCError)
    if exc_cls is PQCError:
        raise PQCError(status, context)
    raise exc_cls(context)
