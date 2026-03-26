% libpqc-dyber - Post-Quantum Cryptography Library
% Copyright (c) 2024-2026 Dyber, Inc.
% SPDX-License-Identifier: Apache-2.0 OR MIT
%
% MATLAB binding benchmarks for all PQC algorithms.
% Uses tic/toc for timing with statistical reporting.

function bench_pqc(base_iters)
    if nargin < 1
        base_iters = 100;
    end

    DEFAULT_ITERATIONS = base_iters;
    SLOW_ITERATIONS = 5;
    WARMUP_ITERATIONS = 5;

    pqc_init();

    fprintf('language,algorithm,operation,iterations,');
    fprintf('min_ms,max_ms,mean_ms,median_ms,stddev_ms,ops_per_sec,');
    fprintf('pk_bytes,sk_bytes\n');

    % KEM benchmarks
    kem_names = pqc_kem_algorithm_names();
    for k = 1:length(kem_names)
        name = kem_names{k};
        iters = adjusted_iters(name, DEFAULT_ITERATIONS, SLOW_ITERATIONS);
        kem = pqc_kem_new(name);
        pk_size = pqc_kem_public_key_size(kem);
        sk_size = pqc_kem_secret_key_size(kem);

        % Warmup
        for w = 1:WARMUP_ITERATIONS
            pqc_kem_keygen(kem);
        end

        % Keygen
        samples = zeros(1, iters);
        for i = 1:iters
            tic;
            pqc_kem_keygen(kem);
            samples(i) = toc * 1000;
        end
        csv_row('matlab', name, 'keygen', iters, compute_stats(samples), pk_size, sk_size);

        % Encaps
        [pk, sk] = pqc_kem_keygen(kem);
        for i = 1:iters
            tic;
            pqc_kem_encaps(kem, pk);
            samples(i) = toc * 1000;
        end
        csv_row('matlab', name, 'encaps', iters, compute_stats(samples), pk_size, sk_size);

        % Decaps
        [ct, ss] = pqc_kem_encaps(kem, pk);
        for i = 1:iters
            tic;
            pqc_kem_decaps(kem, ct, sk);
            samples(i) = toc * 1000;
        end
        csv_row('matlab', name, 'decaps', iters, compute_stats(samples), pk_size, sk_size);

        pqc_kem_free(kem);
    end

    % Signature benchmarks
    msg = uint8(mod((0:1023) * 137 + 42, 256));

    sig_names = pqc_sig_algorithm_names();
    for k = 1:length(sig_names)
        name = sig_names{k};
        iters = adjusted_iters(name, DEFAULT_ITERATIONS, SLOW_ITERATIONS);
        sig = pqc_sig_new(name);
        pk_size = pqc_sig_public_key_size(sig);
        sk_size = pqc_sig_secret_key_size(sig);
        if pqc_sig_is_stateful(sig)
            iters = min(iters, SLOW_ITERATIONS);
        end

        % Keygen
        samples = zeros(1, iters);
        for i = 1:iters
            tic;
            pqc_sig_keygen(sig);
            samples(i) = toc * 1000;
        end
        csv_row('matlab', name, 'keygen', iters, compute_stats(samples), pk_size, sk_size);

        % Sign
        [pk, sk] = pqc_sig_keygen(sig);
        for i = 1:iters
            tic;
            pqc_sig_sign(sig, msg, sk);
            samples(i) = toc * 1000;
        end
        csv_row('matlab', name, 'sign(1KB)', iters, compute_stats(samples), pk_size, sk_size);

        % Verify
        signature = pqc_sig_sign(sig, msg, sk);
        for i = 1:iters
            tic;
            pqc_sig_verify(sig, msg, signature, pk);
            samples(i) = toc * 1000;
        end
        csv_row('matlab', name, 'verify(1KB)', iters, compute_stats(samples), pk_size, sk_size);

        pqc_sig_free(sig);
    end

    pqc_cleanup();
end

function iters = adjusted_iters(name, base, slow_max)
    if contains(name, 'McEliece') || contains(name, 'Frodo') || ...
       contains(name, 'XMSS') || contains(name, 'LMS')
        iters = min(base, slow_max);
    else
        iters = base;
    end
end

function s = compute_stats(samples)
    sorted = sort(samples);
    n = length(sorted);
    s.min_v = sorted(1);
    s.max_v = sorted(end);
    s.median_v = median(sorted);
    s.mean_v = mean(sorted);
    if n > 1
        s.stddev_v = std(sorted);
    else
        s.stddev_v = 0;
    end
    if s.mean_v > 0
        s.ops = 1000.0 / s.mean_v;
    else
        s.ops = 0;
    end
end

function csv_row(lang, algo, op, iters, s, pk_size, sk_size)
    fprintf('%s,%s,%s,%d,%.6f,%.6f,%.6f,%.6f,%.6f,%.1f,%d,%d\n', ...
        lang, algo, op, iters, ...
        s.min_v, s.max_v, s.mean_v, s.median_v, ...
        s.stddev_v, s.ops, pk_size, sk_size);
end
