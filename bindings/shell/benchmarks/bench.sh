#!/usr/bin/env bash
# libpqc-dyber - Post-Quantum Cryptography Library
# Copyright (c) 2024-2026 Dyber, Inc.
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Shell script benchmarks using pqc-cli tool.
# Measures wall-clock time for keygen, encaps/sign, decaps/verify
# by invoking the pqc-cli binary and timing with /usr/bin/time or
# the built-in bash TIMEFORMAT.

set -euo pipefail

PQC_CLI="${PQC_CLI:-pqc-cli}"
ITERATIONS="${1:-10}"
TMPDIR_BENCH="$(mktemp -d)"

cleanup() {
    rm -rf "$TMPDIR_BENCH"
}
trap cleanup EXIT

echo "language,algorithm,operation,iterations,wall_time_ms"

# Check pqc-cli is available
if ! command -v "$PQC_CLI" &>/dev/null; then
    echo "Error: $PQC_CLI not found in PATH" >&2
    exit 1
fi

# Get algorithm lists
KEM_ALGORITHMS=$("$PQC_CLI" list --kem 2>/dev/null || true)
SIG_ALGORITHMS=$("$PQC_CLI" list --sig 2>/dev/null || true)

time_ms() {
    local start end
    start=$(date +%s%N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1e9))')
    "$@" >/dev/null 2>&1
    end=$(date +%s%N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1e9))')
    echo "scale=6; ($end - $start) / 1000000" | bc
}

# KEM benchmarks
if [ -n "$KEM_ALGORITHMS" ]; then
    while IFS= read -r alg; do
        [ -z "$alg" ] && continue

        # Keygen
        total=0
        for ((i = 0; i < ITERATIONS; i++)); do
            ms=$(time_ms "$PQC_CLI" kem keygen --algorithm "$alg" \
                --pk "$TMPDIR_BENCH/pk.bin" --sk "$TMPDIR_BENCH/sk.bin")
            total=$(echo "$total + $ms" | bc)
        done
        avg=$(echo "scale=6; $total / $ITERATIONS" | bc)
        echo "shell,$alg,keygen,$ITERATIONS,$avg"

        # Encaps (use last generated keypair)
        total=0
        for ((i = 0; i < ITERATIONS; i++)); do
            ms=$(time_ms "$PQC_CLI" kem encaps --algorithm "$alg" \
                --pk "$TMPDIR_BENCH/pk.bin" \
                --ct "$TMPDIR_BENCH/ct.bin" --ss "$TMPDIR_BENCH/ss.bin")
            total=$(echo "$total + $ms" | bc)
        done
        avg=$(echo "scale=6; $total / $ITERATIONS" | bc)
        echo "shell,$alg,encaps,$ITERATIONS,$avg"

        # Decaps
        total=0
        for ((i = 0; i < ITERATIONS; i++)); do
            ms=$(time_ms "$PQC_CLI" kem decaps --algorithm "$alg" \
                --sk "$TMPDIR_BENCH/sk.bin" \
                --ct "$TMPDIR_BENCH/ct.bin" --ss "$TMPDIR_BENCH/ss2.bin")
            total=$(echo "$total + $ms" | bc)
        done
        avg=$(echo "scale=6; $total / $ITERATIONS" | bc)
        echo "shell,$alg,decaps,$ITERATIONS,$avg"

    done <<< "$KEM_ALGORITHMS"
fi

# Signature benchmarks
MSG_FILE="$TMPDIR_BENCH/msg.bin"
dd if=/dev/urandom of="$MSG_FILE" bs=1024 count=1 2>/dev/null

if [ -n "$SIG_ALGORITHMS" ]; then
    while IFS= read -r alg; do
        [ -z "$alg" ] && continue

        # Keygen
        total=0
        for ((i = 0; i < ITERATIONS; i++)); do
            ms=$(time_ms "$PQC_CLI" sig keygen --algorithm "$alg" \
                --pk "$TMPDIR_BENCH/pk.bin" --sk "$TMPDIR_BENCH/sk.bin")
            total=$(echo "$total + $ms" | bc)
        done
        avg=$(echo "scale=6; $total / $ITERATIONS" | bc)
        echo "shell,$alg,keygen,$ITERATIONS,$avg"

        # Sign
        total=0
        for ((i = 0; i < ITERATIONS; i++)); do
            ms=$(time_ms "$PQC_CLI" sig sign --algorithm "$alg" \
                --sk "$TMPDIR_BENCH/sk.bin" \
                --message "$MSG_FILE" --sig "$TMPDIR_BENCH/sig.bin")
            total=$(echo "$total + $ms" | bc)
        done
        avg=$(echo "scale=6; $total / $ITERATIONS" | bc)
        echo "shell,$alg,sign(1KB),$ITERATIONS,$avg"

        # Verify
        total=0
        for ((i = 0; i < ITERATIONS; i++)); do
            ms=$(time_ms "$PQC_CLI" sig verify --algorithm "$alg" \
                --pk "$TMPDIR_BENCH/pk.bin" \
                --message "$MSG_FILE" --sig "$TMPDIR_BENCH/sig.bin")
            total=$(echo "$total + $ms" | bc)
        done
        avg=$(echo "scale=6; $total / $ITERATIONS" | bc)
        echo "shell,$alg,verify(1KB),$ITERATIONS,$avg"

    done <<< "$SIG_ALGORITHMS"
fi

echo ""
echo "# Shell benchmarks complete. Note: timings include process startup overhead."
