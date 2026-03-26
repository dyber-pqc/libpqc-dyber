# libpqc-dyber - Post-Quantum Cryptography Library
# Copyright (c) 2024-2026 Dyber, Inc.
# SPDX-License-Identifier: Apache-2.0 OR MIT

"""Digital Signature wrapper."""

from __future__ import annotations

import ctypes
from typing import Tuple

from ._ffi import get_lib
from .exceptions import AlgorithmNotSupportedError, check_status


class Signature:
    """High-level wrapper around a PQC signature context.

    Example::

        sig = Signature("ML-DSA-65")
        pk, sk = sig.keygen()
        signature = sig.sign(b"hello world", sk)
        assert sig.verify(b"hello world", signature, pk)

    The context is automatically freed when the object is garbage-collected.
    """

    # PQC_ERROR_VERIFICATION_FAILED
    _VERIFICATION_FAILED = -6

    def __init__(self, algorithm: str) -> None:
        """Create a signature context for *algorithm*.

        Args:
            algorithm: Algorithm name, e.g. ``"ML-DSA-65"``.

        Raises:
            AlgorithmNotSupportedError: If the algorithm is not available.
        """
        lib = get_lib()
        self._lib = lib
        self._ctx = lib.pqc_sig_new(algorithm.encode("utf-8"))
        if not self._ctx:
            raise AlgorithmNotSupportedError(algorithm)

    def __del__(self) -> None:
        ctx = getattr(self, "_ctx", None)
        if ctx:
            self._lib.pqc_sig_free(ctx)
            self._ctx = None

    # -- Properties ----------------------------------------------------------

    @property
    def algorithm(self) -> str:
        """Return the algorithm name."""
        return self._lib.pqc_sig_algorithm(self._ctx).decode("utf-8")

    @property
    def public_key_size(self) -> int:
        """Return the public key size in bytes."""
        return self._lib.pqc_sig_public_key_size(self._ctx)

    @property
    def secret_key_size(self) -> int:
        """Return the secret key size in bytes."""
        return self._lib.pqc_sig_secret_key_size(self._ctx)

    @property
    def max_signature_size(self) -> int:
        """Return the maximum signature size in bytes."""
        return self._lib.pqc_sig_max_signature_size(self._ctx)

    @property
    def is_stateful(self) -> bool:
        """Return whether this is a stateful signature scheme."""
        return self._lib.pqc_sig_is_stateful(self._ctx) != 0

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
        status = self._lib.pqc_sig_keygen(self._ctx, pk, sk)
        check_status(status, "pqc_sig_keygen")
        return bytes(pk), bytes(sk)

    def sign(self, message: bytes, sk: bytes) -> bytes:
        """Sign a message.

        Args:
            message: The message to sign.
            sk: The signer's secret key.

        Returns:
            The signature as raw bytes (trimmed to actual length).

        Raises:
            PQCError: On failure.
        """
        msg_buf = (ctypes.c_uint8 * len(message)).from_buffer_copy(message)
        sk_buf = (ctypes.c_uint8 * len(sk)).from_buffer_copy(sk)
        sig_buf = (ctypes.c_uint8 * self.max_signature_size)()
        sig_len = ctypes.c_size_t(0)
        status = self._lib.pqc_sig_sign(
            self._ctx,
            sig_buf,
            ctypes.byref(sig_len),
            msg_buf,
            ctypes.c_size_t(len(message)),
            sk_buf,
        )
        check_status(status, "pqc_sig_sign")
        return bytes(sig_buf[: sig_len.value])

    def verify(self, message: bytes, signature: bytes, pk: bytes) -> bool:
        """Verify a signature.

        Args:
            message: The message that was signed.
            signature: The signature to verify.
            pk: The signer's public key.

        Returns:
            ``True`` if the signature is valid, ``False`` otherwise.

        Raises:
            PQCError: On errors other than verification failure.
        """
        msg_buf = (ctypes.c_uint8 * len(message)).from_buffer_copy(message)
        sig_buf = (ctypes.c_uint8 * len(signature)).from_buffer_copy(signature)
        pk_buf = (ctypes.c_uint8 * len(pk)).from_buffer_copy(pk)
        status = self._lib.pqc_sig_verify(
            self._ctx,
            msg_buf,
            ctypes.c_size_t(len(message)),
            sig_buf,
            ctypes.c_size_t(len(signature)),
            pk_buf,
        )
        if status == 0:
            return True
        if status == self._VERIFICATION_FAILED:
            return False
        check_status(status, "pqc_sig_verify")
        return False  # unreachable, but keeps type checkers happy

    def sign_stateful(self, message: bytes, sk: bytearray) -> bytes:
        """Sign with a stateful scheme, modifying *sk* in-place.

        Only valid for stateful algorithms (LMS, XMSS). The secret key
        is updated to advance internal state.

        Args:
            message: The message to sign.
            sk: The signer's secret key as a mutable ``bytearray``.
                It will be modified in-place to advance the state.

        Returns:
            The signature as raw bytes.

        Raises:
            PQCError: On failure.
        """
        msg_buf = (ctypes.c_uint8 * len(message)).from_buffer_copy(message)
        sk_buf = (ctypes.c_uint8 * len(sk)).from_buffer(sk)
        sig_buf = (ctypes.c_uint8 * self.max_signature_size)()
        sig_len = ctypes.c_size_t(0)
        status = self._lib.pqc_sig_sign_stateful(
            self._ctx,
            sig_buf,
            ctypes.byref(sig_len),
            msg_buf,
            ctypes.c_size_t(len(message)),
            sk_buf,
        )
        check_status(status, "pqc_sig_sign_stateful")
        # Write updated key back into the caller's bytearray.
        sk[:] = bytes(sk_buf)
        return bytes(sig_buf[: sig_len.value])

    def __repr__(self) -> str:
        return f"Signature({self.algorithm!r})"
