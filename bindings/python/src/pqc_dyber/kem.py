# libpqc-dyber - Post-Quantum Cryptography Library
# Copyright (c) 2024-2026 Dyber, Inc.
# SPDX-License-Identifier: Apache-2.0 OR MIT

"""Key Encapsulation Mechanism (KEM) wrapper."""

from __future__ import annotations

import ctypes
from typing import Tuple

from ._ffi import get_lib
from .exceptions import AlgorithmNotSupportedError, check_status


class KEM:
    """High-level wrapper around a PQC KEM context.

    Example::

        kem = KEM("ML-KEM-768")
        pk, sk = kem.keygen()
        ct, ss_enc = kem.encaps(pk)
        ss_dec = kem.decaps(ct, sk)
        assert ss_enc == ss_dec

    The context is automatically freed when the object is garbage-collected.
    """

    def __init__(self, algorithm: str) -> None:
        """Create a KEM context for *algorithm*.

        Args:
            algorithm: Algorithm name, e.g. ``"ML-KEM-768"``.

        Raises:
            AlgorithmNotSupportedError: If the algorithm is not available.
        """
        lib = get_lib()
        self._lib = lib
        self._ctx = lib.pqc_kem_new(algorithm.encode("utf-8"))
        if not self._ctx:
            raise AlgorithmNotSupportedError(algorithm)

    def __del__(self) -> None:
        ctx = getattr(self, "_ctx", None)
        if ctx:
            self._lib.pqc_kem_free(ctx)
            self._ctx = None

    # -- Properties ----------------------------------------------------------

    @property
    def algorithm(self) -> str:
        """Return the algorithm name."""
        return self._lib.pqc_kem_algorithm(self._ctx).decode("utf-8")

    @property
    def public_key_size(self) -> int:
        """Return the public key size in bytes."""
        return self._lib.pqc_kem_public_key_size(self._ctx)

    @property
    def secret_key_size(self) -> int:
        """Return the secret key size in bytes."""
        return self._lib.pqc_kem_secret_key_size(self._ctx)

    @property
    def ciphertext_size(self) -> int:
        """Return the ciphertext size in bytes."""
        return self._lib.pqc_kem_ciphertext_size(self._ctx)

    @property
    def shared_secret_size(self) -> int:
        """Return the shared secret size in bytes."""
        return self._lib.pqc_kem_shared_secret_size(self._ctx)

    # -- Operations ----------------------------------------------------------

    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate a key pair.

        Returns:
            A tuple ``(public_key, secret_key)`` of raw bytes.

        Raises:
            PQCError: On failure.
        """
        pk = (ctypes.c_uint8 * self.public_key_size)()
        sk = (ctypes.c_uint8 * self.secret_key_size)()
        status = self._lib.pqc_kem_keygen(self._ctx, pk, sk)
        check_status(status, "pqc_kem_keygen")
        return bytes(pk), bytes(sk)

    def encaps(self, pk: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate: produce ciphertext and shared secret from a public key.

        Args:
            pk: The recipient's public key.

        Returns:
            A tuple ``(ciphertext, shared_secret)`` of raw bytes.

        Raises:
            PQCError: On failure.
        """
        pk_buf = (ctypes.c_uint8 * len(pk)).from_buffer_copy(pk)
        ct = (ctypes.c_uint8 * self.ciphertext_size)()
        ss = (ctypes.c_uint8 * self.shared_secret_size)()
        status = self._lib.pqc_kem_encaps(self._ctx, ct, ss, pk_buf)
        check_status(status, "pqc_kem_encaps")
        return bytes(ct), bytes(ss)

    def decaps(self, ct: bytes, sk: bytes) -> bytes:
        """Decapsulate: recover the shared secret from ciphertext and secret key.

        Args:
            ct: The ciphertext from encapsulation.
            sk: The recipient's secret key.

        Returns:
            The shared secret as raw bytes.

        Raises:
            PQCError: On failure.
        """
        ct_buf = (ctypes.c_uint8 * len(ct)).from_buffer_copy(ct)
        sk_buf = (ctypes.c_uint8 * len(sk)).from_buffer_copy(sk)
        ss = (ctypes.c_uint8 * self.shared_secret_size)()
        status = self._lib.pqc_kem_decaps(self._ctx, ss, ct_buf, sk_buf)
        check_status(status, "pqc_kem_decaps")
        return bytes(ss)

    def __repr__(self) -> str:
        return f"KEM({self.algorithm!r})"
