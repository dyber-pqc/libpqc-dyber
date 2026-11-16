#!/usr/bin/env python3
# libpqc-dyber - Post-Quantum Cryptography Library
# Copyright (c) 2024-2026 Dyber, Inc.
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""
Cross-check ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) against OpenSSL >= 3.5.

A round-trip test cannot see a defect that sign() and verify() share, which
is how both the SLH-DSA key-pair address bug and the missing FIPS 204/205
message prefix survived. This checks every parameter set in both
directions against an independent implementation:

  1. libpqc keygen + sign     -> OpenSSL verifies   (empty and non-empty ctx)
  2. OpenSSL sign with our key -> libpqc verifies   (empty and non-empty ctx)
  3. a signature made under one ctx is rejected under another, by both

Our raw keys are wrapped in SPKI / PKCS#8 (draft-ietf-lamps-dilithium-
certificates and RFC 9909 encodings), so (2) also has OpenSSL load our
expanded secret key.

usage: openssl_interop.py PATH_TO_pqc_sig_tool [--openssl PATH] [--only SUBSTR]
Exit 0 if every check passes, 1 on any failure, 77 if OpenSSL lacks the
algorithms or libpqc was built without any of them (CTest SKIP_RETURN_CODE).
Algorithms left out of this libpqc build are skipped; --require-all makes
that a failure instead, for the CI job whose build has everything.
"""
import argparse
import os
import subprocess
import sys
import tempfile

ARC = "2.16.840.1.101.3.4.3."
# (libpqc name, OpenSSL name, OID last arc, private key is OCTET STRING-wrapped)
ALGS = [
    ("ML-DSA-44", "ML-DSA-44", 17, True),
    ("ML-DSA-65", "ML-DSA-65", 18, True),
    ("ML-DSA-87", "ML-DSA-87", 19, True),
] + [
    ("SLH-DSA-%s-%s" % (h, s), "SLH-DSA-%s-%s" % (h, s), 20 + i, False)
    for i, (h, s) in enumerate(
        (h, s) for h in ("SHA2", "SHAKE")
        for s in ("128s", "128f", "192s", "192f", "256s", "256f"))
]


def der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, body):
    return bytes([tag]) + der_len(len(body)) + body


def oid(dotted):
    parts = [int(x) for x in dotted.split(".")]
    out = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        enc = [p & 0x7F]
        p >>= 7
        while p:
            enc.append(0x80 | (p & 0x7F))
            p >>= 7
        out += bytes(reversed(enc))
    return tlv(0x06, out)


def spki(arc, pk):
    return tlv(0x30, tlv(0x30, oid(ARC + str(arc))) + tlv(0x03, b"\x00" + pk))


def pkcs8(arc, sk, wrapped):
    inner = tlv(0x04, sk) if wrapped else sk   # ML-DSA expandedKey CHOICE
    return tlv(0x30, tlv(0x02, b"\x00") + tlv(0x30, oid(ARC + str(arc)))
               + tlv(0x04, inner))


def run(cmd):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tool")
    ap.add_argument("--openssl", default="openssl")
    ap.add_argument("--only", default="")
    ap.add_argument("--require-all", action="store_true",
                    help="fail, rather than skip, algorithms not in this build")
    a = ap.parse_args()
    a.tool = os.path.abspath(a.tool)

    probe = run([a.openssl, "list", "-signature-algorithms"])
    if probe.returncode != 0 or b"ML-DSA-44" not in probe.stdout \
            or b"SLH-DSA" not in probe.stdout:
        print("SKIP: %s has no ML-DSA/SLH-DSA (needs OpenSSL >= 3.5)"
              % a.openssl)
        return 77

    msg = b"libpqc-dyber interop \x00\xff" + bytes(range(256)) * 3
    ctx_a = b"libpqc-dyber/interop/ctx"
    ctx_b = b"libpqc-dyber/interop/ctX"
    failures = 0
    checks = 0
    skipped = []

    def check(ok, what):
        nonlocal failures, checks
        checks += 1
        if not ok:
            failures += 1
        print("  [%s] %s" % ("PASS" if ok else "FAIL", what))

    with tempfile.TemporaryDirectory() as d:
        def f(name):
            return os.path.join(d, name)

        with open(f("msg"), "wb") as fh:
            fh.write(msg)

        for ours, theirs, arc, wrapped in ALGS:
            if a.only and a.only not in ours:
                continue
            print(ours)
            r = run([a.tool, "keygen", ours, f("pk"), f("sk")])
            if r.returncode == 3 and not a.require_all:
                print("  [SKIP] not in this build")
                skipped.append(ours)
                continue
            if r.returncode != 0:
                check(False, "libpqc keygen: %s" % r.stderr.decode().strip())
                continue
            pk = open(f("pk"), "rb").read()
            sk = open(f("sk"), "rb").read()
            open(f("pk.der"), "wb").write(spki(arc, pk))
            open(f("sk.der"), "wb").write(pkcs8(arc, sk, wrapped))

            for ctx in (b"", ctx_a):
                hx = ctx.hex() or "-"
                label = "ctx=%r" % ctx if ctx else "empty ctx"
                opt = ["-pkeyopt", "hexcontext-string:" + ctx.hex()] if ctx else []

                # 1. we sign, OpenSSL verifies
                r = run([a.tool, "sign", ours, f("sk"), f("msg"), hx, f("sig1")])
                if r.returncode != 0:
                    check(False, "libpqc sign (%s): %s" % (label, r.stderr.decode().strip()))
                    continue
                r = run([a.openssl, "pkeyutl", "-verify", "-rawin",
                         "-pubin", "-keyform", "DER", "-inkey", f("pk.der"),
                         "-in", f("msg"), "-sigfile", f("sig1")] + opt)
                check(r.returncode == 0,
                      "libpqc sign -> OpenSSL verify (%s)%s" % (
                          label, "" if r.returncode == 0 else
                          ": " + (r.stdout + r.stderr).decode(errors="replace").strip().splitlines()[-1]))

                # 2. OpenSSL signs with our secret key, we verify
                r = run([a.openssl, "pkeyutl", "-sign", "-rawin",
                         "-keyform", "DER", "-inkey", f("sk.der"),
                         "-in", f("msg"), "-out", f("sig2")] + opt)
                if r.returncode != 0:
                    check(False, "OpenSSL sign with libpqc key (%s): %s" % (
                        label, r.stderr.decode(errors="replace").strip().splitlines()[-1]))
                else:
                    r = run([a.tool, "verify", ours, f("pk"), f("msg"), hx, f("sig2")])
                    check(r.returncode == 0,
                          "OpenSSL sign -> libpqc verify (%s)" % label)

            # 3. context separation, both implementations
            r = run([a.tool, "verify", ours, f("pk"), f("msg"),
                     ctx_b.hex(), f("sig1")])
            check(r.returncode == 1, "libpqc rejects signature under a different ctx")
            r = run([a.openssl, "pkeyutl", "-verify", "-rawin", "-pubin",
                     "-keyform", "DER", "-inkey", f("pk.der"), "-in", f("msg"),
                     "-sigfile", f("sig1"), "-pkeyopt",
                     "hexcontext-string:" + ctx_b.hex()])
            check(r.returncode != 0, "OpenSSL rejects it too")

    print("\n%d checks, %d failures, %d algorithms skipped"
          % (checks, failures, len(skipped)))
    if failures:
        return 1
    return 77 if checks == 0 else 0


if __name__ == "__main__":
    sys.exit(main())
