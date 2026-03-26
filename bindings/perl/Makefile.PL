# libpqc-dyber - Post-Quantum Cryptography Library
# Copyright (c) 2024-2026 Dyber, Inc.
# SPDX-License-Identifier: Apache-2.0 OR MIT

use ExtUtils::MakeMaker;

WriteMakefile(
    NAME         => 'Crypt::PQC::Dyber',
    VERSION_FROM => 'lib/Crypt/PQC/Dyber.pm',
    ABSTRACT     => 'Perl bindings for libpqc-dyber post-quantum cryptography library',
    AUTHOR       => 'Dyber, Inc.',
    LICENSE      => 'open_source',
    XS           => { 'xs/Dyber.xs' => 'Dyber.c' },
    INC          => '-I../../include',
    LIBS         => ['-L../../build -lpqc'],
    OBJECT       => 'Dyber$(OBJ_EXT)',
    META_MERGE   => {
        'meta-spec' => { version => 2 },
        resources   => {
            repository => {
                type => 'git',
                url  => 'https://github.com/dyber/libpqc-dyber.git',
                web  => 'https://github.com/dyber/libpqc-dyber',
            },
        },
    },
);
