# libpqc-dyber - Post-Quantum Cryptography Library
# Copyright (c) 2024-2026 Dyber, Inc.
# SPDX-License-Identifier: Apache-2.0 OR MIT

"""Pytest tests for the Signature binding."""

import pytest

from pqc_dyber import (
    AlgorithmNotSupportedError,
    PQCError,
    Signature,
    sig_algorithms,
    sig_is_enabled,
)


TEST_MESSAGE = b"This is a test message."


class TestSignatureProperties:
    """Test Signature context properties."""

    def test_algorithm_name(self):
        sig = Signature("ML-DSA-65")
        assert sig.algorithm == "ML-DSA-65"

    def test_sizes_are_positive(self):
        sig = Signature("ML-DSA-65")
        assert sig.public_key_size > 0
        assert sig.secret_key_size > 0
        assert sig.max_signature_size > 0

    def test_is_not_stateful(self):
        sig = Signature("ML-DSA-65")
        assert sig.is_stateful is False

    def test_repr(self):
        sig = Signature("ML-DSA-65")
        assert repr(sig) == "Signature('ML-DSA-65')"

    def test_invalid_algorithm_raises(self):
        with pytest.raises(AlgorithmNotSupportedError):
            Signature("INVALID-ALGORITHM-NAME")


class TestSignatureOperations:
    """Test sign / verify round-trip."""

    def test_sign_verify_mldsa65(self):
        sig = Signature("ML-DSA-65")
        pk, sk = sig.keygen()

        assert isinstance(pk, bytes)
        assert isinstance(sk, bytes)
        assert len(pk) == sig.public_key_size
        assert len(sk) == sig.secret_key_size

        signature = sig.sign(TEST_MESSAGE, sk)
        assert isinstance(signature, bytes)
        assert len(signature) <= sig.max_signature_size
        assert len(signature) > 0

        assert sig.verify(TEST_MESSAGE, signature, pk) is True

    def test_sign_verify_mldsa44(self):
        sig = Signature("ML-DSA-44")
        pk, sk = sig.keygen()
        signature = sig.sign(TEST_MESSAGE, sk)
        assert sig.verify(TEST_MESSAGE, signature, pk) is True

    def test_sign_verify_mldsa87(self):
        sig = Signature("ML-DSA-87")
        pk, sk = sig.keygen()
        signature = sig.sign(TEST_MESSAGE, sk)
        assert sig.verify(TEST_MESSAGE, signature, pk) is True

    def test_verify_tampered_message(self):
        sig = Signature("ML-DSA-65")
        pk, sk = sig.keygen()
        signature = sig.sign(TEST_MESSAGE, sk)

        tampered = b"Tampered message."
        assert sig.verify(tampered, signature, pk) is False

    def test_verify_tampered_signature(self):
        sig = Signature("ML-DSA-65")
        pk, sk = sig.keygen()
        signature = sig.sign(TEST_MESSAGE, sk)

        tampered_sig = bytearray(signature)
        tampered_sig[0] ^= 0xFF
        assert sig.verify(TEST_MESSAGE, bytes(tampered_sig), pk) is False

    def test_empty_message(self):
        sig = Signature("ML-DSA-65")
        pk, sk = sig.keygen()
        signature = sig.sign(b"", sk)
        assert sig.verify(b"", signature, pk) is True

    def test_different_keypairs_produce_different_keys(self):
        sig = Signature("ML-DSA-65")
        pk1, sk1 = sig.keygen()
        pk2, sk2 = sig.keygen()
        assert pk1 != pk2
        assert sk1 != sk2


class TestSignatureAlgorithmEnumeration:
    """Test algorithm listing and query functions."""

    def test_sig_algorithms_not_empty(self):
        algs = sig_algorithms()
        assert len(algs) > 0

    def test_mldsa65_is_listed(self):
        algs = sig_algorithms()
        assert "ML-DSA-65" in algs

    def test_sig_is_enabled(self):
        assert sig_is_enabled("ML-DSA-65") is True
        assert sig_is_enabled("NONEXISTENT") is False
