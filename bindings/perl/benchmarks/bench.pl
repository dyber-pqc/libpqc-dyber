#!/usr/bin/env perl
# libpqc-dyber - Post-Quantum Cryptography Library
# Copyright (c) 2024-2026 Dyber, Inc.
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Perl binding benchmarks for all PQC algorithms.
# Uses Time::HiRes for microsecond-precision timing.

use strict;
use warnings;
use Time::HiRes qw(clock_gettime CLOCK_MONOTONIC);
use List::Util qw(sum min);
use POSIX qw(sqrt);

use PqcDyber;

my $DEFAULT_ITERATIONS = 100;
my $SLOW_ITERATIONS    = 5;
my $WARMUP_ITERATIONS  = 5;

sub is_slow {
    my ($name) = @_;
    return $name =~ /McEliece|Frodo|XMSS|LMS/;
}

sub adjusted_iters {
    my ($name, $base) = @_;
    return is_slow($name) ? min($base, $SLOW_ITERATIONS) : $base;
}

sub compute_stats {
    my (@samples) = @_;
    my @sorted = sort { $a <=> $b } @samples;
    my $n = scalar @sorted;
    my $min_v = $sorted[0];
    my $max_v = $sorted[$n - 1];
    my $median;
    if ($n % 2 == 0) {
        $median = ($sorted[$n / 2 - 1] + $sorted[$n / 2]) / 2.0;
    } else {
        $median = $sorted[int($n / 2)];
    }
    my $mean = sum(@sorted) / $n;
    my $var = 0;
    for my $s (@sorted) {
        my $d = $s - $mean;
        $var += $d * $d;
    }
    my $stddev = $n > 1 ? sqrt($var / ($n - 1)) : 0.0;
    my $ops = $mean > 0 ? 1000.0 / $mean : 0.0;
    return ($min_v, $max_v, $mean, $median, $stddev, $ops);
}

sub csv_row {
    my ($algo, $op, $iters, $stats_ref, $pk_size, $sk_size) = @_;
    my @s = @$stats_ref;
    printf "perl,%s,%s,%d,%.6f,%.6f,%.6f,%.6f,%.6f,%.1f,%d,%d\n",
        $algo, $op, $iters, $s[0], $s[1], $s[2], $s[3], $s[4], $s[5],
        $pk_size, $sk_size;
}

sub timer_ms {
    my ($code) = @_;
    my $t0 = clock_gettime(CLOCK_MONOTONIC);
    $code->();
    my $t1 = clock_gettime(CLOCK_MONOTONIC);
    return ($t1 - $t0) * 1000.0;
}

# Main
my $base_iters = $ARGV[0] && $ARGV[0] =~ /^\d+$/ ? int($ARGV[0]) : $DEFAULT_ITERATIONS;

PqcDyber::init();

print "language,algorithm,operation,iterations,"
    . "min_ms,max_ms,mean_ms,median_ms,stddev_ms,ops_per_sec,"
    . "pk_bytes,sk_bytes\n";

# KEM benchmarks
for my $name (@{ PqcDyber::kem_algorithm_names() }) {
    my $iters = adjusted_iters($name, $base_iters);
    my $kem = PqcDyber::Kem->new($name);
    my $pk_size = $kem->public_key_size();
    my $sk_size = $kem->secret_key_size();

    for (1 .. $WARMUP_ITERATIONS) { $kem->keygen() }

    # Keygen
    my @samples = map { timer_ms(sub { $kem->keygen() }) } (1 .. $iters);
    my @stats = compute_stats(@samples);
    csv_row($name, "keygen", $iters, \@stats, $pk_size, $sk_size);

    # Encaps
    my ($pk, $sk) = $kem->keygen();
    @samples = map { timer_ms(sub { $kem->encaps($pk) }) } (1 .. $iters);
    @stats = compute_stats(@samples);
    csv_row($name, "encaps", $iters, \@stats, $pk_size, $sk_size);

    # Decaps
    my ($ct, $ss) = $kem->encaps($pk);
    @samples = map { timer_ms(sub { $kem->decaps($ct, $sk) }) } (1 .. $iters);
    @stats = compute_stats(@samples);
    csv_row($name, "decaps", $iters, \@stats, $pk_size, $sk_size);

    $kem->free();
}

# Signature benchmarks
my $msg = pack("C*", map { ($_ * 137 + 42) & 0xFF } (0 .. 1023));

for my $name (@{ PqcDyber::sig_algorithm_names() }) {
    my $iters = adjusted_iters($name, $base_iters);
    my $sig = PqcDyber::Signature->new($name);
    my $pk_size = $sig->public_key_size();
    my $sk_size = $sig->secret_key_size();
    $iters = min($iters, $SLOW_ITERATIONS) if $sig->is_stateful();

    # Keygen
    my @samples = map { timer_ms(sub { $sig->keygen() }) } (1 .. $iters);
    my @stats = compute_stats(@samples);
    csv_row($name, "keygen", $iters, \@stats, $pk_size, $sk_size);

    # Sign
    my ($pk, $sk) = $sig->keygen();
    @samples = map { timer_ms(sub { $sig->sign($msg, $sk) }) } (1 .. $iters);
    @stats = compute_stats(@samples);
    csv_row($name, "sign(1KB)", $iters, \@stats, $pk_size, $sk_size);

    # Verify
    my $signature = $sig->sign($msg, $sk);
    @samples = map { timer_ms(sub { $sig->verify($msg, $signature, $pk) }) } (1 .. $iters);
    @stats = compute_stats(@samples);
    csv_row($name, "verify(1KB)", $iters, \@stats, $pk_size, $sk_size);

    $sig->free();
}

PqcDyber::cleanup();
