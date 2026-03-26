# libpqc-dyber - Post-Quantum Cryptography Library
# Copyright (c) 2024-2026 Dyber, Inc.
# SPDX-License-Identifier: Apache-2.0 OR MIT

"""Low-level ctypes bindings to the libpqc shared library."""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import platform
import sys
from ctypes import (
    POINTER,
    c_char_p,
    c_int,
    c_size_t,
    c_uint8,
    c_void_p,
)
from pathlib import Path
from typing import Optional


def _find_library() -> str:
    """Locate the libpqc shared library.

    Search order:
      1. ``PQC_LIB_PATH`` environment variable (exact path to the .so/.dylib/.dll).
      2. ``PQC_LIB_DIR`` environment variable (directory containing the library).
      3. Standard ctypes.util.find_library lookup.
      4. Common installation prefixes relative to this package.
    """
    # 1. Exact path from environment
    env_path = os.environ.get("PQC_LIB_PATH")
    if env_path and os.path.isfile(env_path):
        return env_path

    system = platform.system()
    if system == "Windows":
        lib_names = ["pqc.dll", "libpqc.dll"]
    elif system == "Darwin":
        lib_names = ["libpqc.dylib"]
    else:
        lib_names = ["libpqc.so"]

    # 2. Directory from environment
    env_dir = os.environ.get("PQC_LIB_DIR")
    if env_dir:
        for name in lib_names:
            candidate = os.path.join(env_dir, name)
            if os.path.isfile(candidate):
                return candidate

    # 3. System library search
    found = ctypes.util.find_library("pqc")
    if found:
        return found

    # 4. Common relative paths (when installed alongside this package or in
    #    a build tree).
    search_dirs = [
        Path(__file__).resolve().parent,
        Path(__file__).resolve().parent.parent.parent.parent / "lib",
        Path(__file__).resolve().parent.parent.parent.parent / "build" / "lib",
        Path(__file__).resolve().parent.parent.parent.parent / "build",
    ]
    for d in search_dirs:
        for name in lib_names:
            candidate = d / name
            if candidate.is_file():
                return str(candidate)

    raise OSError(
        "Could not find the libpqc shared library. "
        "Set the PQC_LIB_PATH or PQC_LIB_DIR environment variable, "
        "or install libpqc-dyber into a standard system location."
    )


def _load_library() -> ctypes.CDLL:
    """Load the shared library and declare all function signatures."""
    path = _find_library()
    lib = ctypes.CDLL(path)
    _declare_functions(lib)
    return lib


# ---------------------------------------------------------------------------
# Opaque handle types
# ---------------------------------------------------------------------------

class _PQC_KEM(ctypes.Structure):
    """Opaque PQC_KEM handle."""
    pass


class _PQC_SIG(ctypes.Structure):
    """Opaque PQC_SIG handle."""
    pass


PQC_KEM_PTR = POINTER(_PQC_KEM)
PQC_SIG_PTR = POINTER(_PQC_SIG)


# ---------------------------------------------------------------------------
# Function signature declarations
# ---------------------------------------------------------------------------

def _declare_functions(lib: ctypes.CDLL) -> None:
    """Set argtypes and restype for every C function we use."""

    # -- Version -----------------------------------------------------------------
    lib.pqc_version.argtypes = []
    lib.pqc_version.restype = c_char_p

    lib.pqc_version_major.argtypes = []
    lib.pqc_version_major.restype = c_int

    lib.pqc_version_minor.argtypes = []
    lib.pqc_version_minor.restype = c_int

    lib.pqc_version_patch.argtypes = []
    lib.pqc_version_patch.restype = c_int

    # -- Init / cleanup ----------------------------------------------------------
    lib.pqc_init.argtypes = []
    lib.pqc_init.restype = c_int

    lib.pqc_cleanup.argtypes = []
    lib.pqc_cleanup.restype = None

    # -- Status string -----------------------------------------------------------
    lib.pqc_status_string.argtypes = [c_int]
    lib.pqc_status_string.restype = c_char_p

    # -- Secure memory -----------------------------------------------------------
    lib.pqc_memzero.argtypes = [c_void_p, c_size_t]
    lib.pqc_memzero.restype = None

    # -- KEM context -------------------------------------------------------------
    lib.pqc_kem_new.argtypes = [c_char_p]
    lib.pqc_kem_new.restype = PQC_KEM_PTR

    lib.pqc_kem_free.argtypes = [PQC_KEM_PTR]
    lib.pqc_kem_free.restype = None

    # -- KEM properties ----------------------------------------------------------
    lib.pqc_kem_algorithm.argtypes = [PQC_KEM_PTR]
    lib.pqc_kem_algorithm.restype = c_char_p

    lib.pqc_kem_public_key_size.argtypes = [PQC_KEM_PTR]
    lib.pqc_kem_public_key_size.restype = c_size_t

    lib.pqc_kem_secret_key_size.argtypes = [PQC_KEM_PTR]
    lib.pqc_kem_secret_key_size.restype = c_size_t

    lib.pqc_kem_ciphertext_size.argtypes = [PQC_KEM_PTR]
    lib.pqc_kem_ciphertext_size.restype = c_size_t

    lib.pqc_kem_shared_secret_size.argtypes = [PQC_KEM_PTR]
    lib.pqc_kem_shared_secret_size.restype = c_size_t

    # -- KEM operations ----------------------------------------------------------
    lib.pqc_kem_keygen.argtypes = [PQC_KEM_PTR, POINTER(c_uint8), POINTER(c_uint8)]
    lib.pqc_kem_keygen.restype = c_int

    lib.pqc_kem_encaps.argtypes = [
        PQC_KEM_PTR, POINTER(c_uint8), POINTER(c_uint8), POINTER(c_uint8),
    ]
    lib.pqc_kem_encaps.restype = c_int

    lib.pqc_kem_decaps.argtypes = [
        PQC_KEM_PTR, POINTER(c_uint8), POINTER(c_uint8), POINTER(c_uint8),
    ]
    lib.pqc_kem_decaps.restype = c_int

    # -- Signature context -------------------------------------------------------
    lib.pqc_sig_new.argtypes = [c_char_p]
    lib.pqc_sig_new.restype = PQC_SIG_PTR

    lib.pqc_sig_free.argtypes = [PQC_SIG_PTR]
    lib.pqc_sig_free.restype = None

    # -- Signature properties ----------------------------------------------------
    lib.pqc_sig_algorithm.argtypes = [PQC_SIG_PTR]
    lib.pqc_sig_algorithm.restype = c_char_p

    lib.pqc_sig_public_key_size.argtypes = [PQC_SIG_PTR]
    lib.pqc_sig_public_key_size.restype = c_size_t

    lib.pqc_sig_secret_key_size.argtypes = [PQC_SIG_PTR]
    lib.pqc_sig_secret_key_size.restype = c_size_t

    lib.pqc_sig_max_signature_size.argtypes = [PQC_SIG_PTR]
    lib.pqc_sig_max_signature_size.restype = c_size_t

    lib.pqc_sig_is_stateful.argtypes = [PQC_SIG_PTR]
    lib.pqc_sig_is_stateful.restype = c_int

    # -- Signature operations ----------------------------------------------------
    lib.pqc_sig_keygen.argtypes = [PQC_SIG_PTR, POINTER(c_uint8), POINTER(c_uint8)]
    lib.pqc_sig_keygen.restype = c_int

    lib.pqc_sig_sign.argtypes = [
        PQC_SIG_PTR,
        POINTER(c_uint8),   # signature (out)
        POINTER(c_size_t),  # signature_len (out)
        POINTER(c_uint8),   # message
        c_size_t,            # message_len
        POINTER(c_uint8),   # secret_key
    ]
    lib.pqc_sig_sign.restype = c_int

    lib.pqc_sig_verify.argtypes = [
        PQC_SIG_PTR,
        POINTER(c_uint8),   # message
        c_size_t,            # message_len
        POINTER(c_uint8),   # signature
        c_size_t,            # signature_len
        POINTER(c_uint8),   # public_key
    ]
    lib.pqc_sig_verify.restype = c_int

    lib.pqc_sig_sign_stateful.argtypes = [
        PQC_SIG_PTR,
        POINTER(c_uint8),   # signature (out)
        POINTER(c_size_t),  # signature_len (out)
        POINTER(c_uint8),   # message
        c_size_t,            # message_len
        POINTER(c_uint8),   # secret_key (in/out)
    ]
    lib.pqc_sig_sign_stateful.restype = c_int

    # -- Algorithm enumeration ---------------------------------------------------
    lib.pqc_kem_algorithm_count.argtypes = []
    lib.pqc_kem_algorithm_count.restype = c_int

    lib.pqc_kem_algorithm_name.argtypes = [c_int]
    lib.pqc_kem_algorithm_name.restype = c_char_p

    lib.pqc_kem_is_enabled.argtypes = [c_char_p]
    lib.pqc_kem_is_enabled.restype = c_int

    lib.pqc_sig_algorithm_count.argtypes = []
    lib.pqc_sig_algorithm_count.restype = c_int

    lib.pqc_sig_algorithm_name.argtypes = [c_int]
    lib.pqc_sig_algorithm_name.restype = c_char_p

    lib.pqc_sig_is_enabled.argtypes = [c_char_p]
    lib.pqc_sig_is_enabled.restype = c_int


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_lib: Optional[ctypes.CDLL] = None


def get_lib() -> ctypes.CDLL:
    """Return the loaded shared library (lazy singleton)."""
    global _lib
    if _lib is None:
        _lib = _load_library()
    return _lib
