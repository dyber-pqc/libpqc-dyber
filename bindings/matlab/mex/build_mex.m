% libpqc-dyber - Post-Quantum Cryptography Library
% Copyright (c) 2024-2026 Dyber, Inc.
% SPDX-License-Identifier: Apache-2.0 OR MIT
%
% Build script for the PQC MEX gateway.
%
% Usage:
%   cd bindings/matlab/mex
%   build_mex

function build_mex()
    % Paths relative to this script
    pqc_include = fullfile('..', '..', '..', 'include');
    pqc_lib_dir = fullfile('..', '..', '..', 'build');

    if ispc
        pqc_lib = fullfile(pqc_lib_dir, 'Release', 'pqc.lib');
        if ~exist(pqc_lib, 'file')
            pqc_lib = fullfile(pqc_lib_dir, 'pqc.lib');
        end
    else
        pqc_lib = '-lpqc';
    end

    fprintf('Building pqc_mex...\n');
    fprintf('  Include: %s\n', pqc_include);
    fprintf('  Library: %s\n', pqc_lib_dir);

    if ispc
        mex('-v', ...
            ['-I' pqc_include], ...
            ['-L' pqc_lib_dir], ...
            '-lpqc', ...
            'pqc_mex.c');
    else
        mex('-v', ...
            ['-I' pqc_include], ...
            ['-L' pqc_lib_dir], ...
            '-lpqc', ...
            'LDFLAGS="$LDFLAGS -Wl,-rpath,\$ORIGIN/../../../build"', ...
            'pqc_mex.c');
    end

    fprintf('Build complete.\n');
end
