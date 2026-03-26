# libpqc-dyber - Post-Quantum Cryptography Library
# Copyright (c) 2024-2026 Dyber, Inc.
# SPDX-License-Identifier: Apache-2.0 OR MIT

"""Pytest tests for the KEM binding."""

import pytest

from pqc_dyber import KEM, AlgorithmNotSupportedError, PQCError, kem_algorithms, kem_is_enabled


class TestKEMProperties:
    """Test KEM context properties."""

    def test_algorithm_name(self):
        kem = KEM("ML-KEM-768")
        assert kem.algorithm == "ML-KEM-768"

    def test_sizes_are_positive(self):
        kem = KEM("ML-KEM-768")
        assert kem.public_key_size > 0
        assert kem.secret_key_size > 0
        assert kem.ciphertext_size > 0
        assert kem.shared_secret_size > 0

    def test_repr(self):
        kem = KEM("ML-KEM-768")
        assert repr(kem) == "KEM('ML-KEM-768')"

    def test_invalid_algorithm_raises(self):
        with pytest.raises(AlgorithmNotSupportedError):
            KEM("INVALID-ALGORITHM-NAME")


class TestKEMOperations:
    """Test KEM keygen / encaps / decaps round-trip."""

    def test_roundtrip_mlkem768(self):
        kem = KEM("ML-KEM-768")
        pk, sk = kem.keygen()

        assert isinstance(pk, bytes)
        assert isinstance(sk, bytes)
        assert len(pk) == kem.public_key_size
        assert len(sk) == kem.secret_key_size

        ct, ss_enc = kem.encaps(pk)
        assert isinstance(ct, bytes)
        assert isinstance(ss_enc, bytes)
        assert len(ct) == kem.ciphertext_size
        assert len(ss_enc) == kem.shared_secret_size

        ss_dec = kem.decaps(ct, sk)
        assert isinstance(ss_dec, bytes)
        assert len(ss_dec) == kem.shared_secret_size
        assert ss_enc == ss_dec

    def test_roundtrip_mlkem512(self):
        kem = KEM("ML-KEM-512")
        pk, sk = kem.keygen()
        ct, ss_enc = kem.encaps(pk)
        ss_dec = kem.decaps(ct, sk)
        assert ss_enc == ss_dec

    def test_roundtrip_mlkem1024(self):
        kem = KEM("ML-KEM-1024")
        pk, sk = kem.keygen()
        ct, ss_enc = kem.encaps(pk)
        ss_dec = kem.decaps(ct, sk)
        assert ss_enc == ss_dec

    def test_different_keypairs_produce_different_keys(self):
        kem = KEM("ML-KEM-768")
        pk1, sk1 = kem.keygen()
        pk2, sk2 = kem.keygen()
        # Keys should differ (with overwhelming probability).
        assert pk1 != pk2
        assert sk1 != sk2


class TestKEMAlgorithmEnumeration:
    """Test algorithm listing and query functions."""

    def test_kem_algorithms_not_empty(self):
        algs = kem_algorithms()
        assert len(algs) > 0

    def test_mlkem768_is_listed(self):
        algs = kem_algorithms()
        assert "ML-KEM-768" in algs

    def test_kem_is_enabled(self):
        assert kem_is_enabled("ML-KEM-768") is True
        assert kem_is_enabled("NONEXISTENT") is False
