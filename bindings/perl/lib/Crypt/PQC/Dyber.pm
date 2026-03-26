# libpqc-dyber - Post-Quantum Cryptography Library
# Copyright (c) 2024-2026 Dyber, Inc.
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Perl bindings for libpqc-dyber.

package Crypt::PQC::Dyber;

use strict;
use warnings;
use Carp;

our $VERSION = '1.00';

require XSLoader;
XSLoader::load('Crypt::PQC::Dyber', $VERSION);

# Initialize the library on load
_pqc_init() or croak "Failed to initialize libpqc";

=head1 NAME

Crypt::PQC::Dyber - Post-Quantum Cryptography library bindings

=head1 SYNOPSIS

    use Crypt::PQC::Dyber;

    # KEM
    my $kem = Crypt::PQC::Dyber::KEM->new("ML-KEM-768");
    my ($pk, $sk) = $kem->keygen();
    my ($ct, $ss_enc) = $kem->encaps($pk);
    my $ss_dec = $kem->decaps($ct, $sk);
    # $ss_enc eq $ss_dec

    # Signature
    my $sig = Crypt::PQC::Dyber::Signature->new("ML-DSA-65");
    my ($pk, $sk) = $sig->keygen();
    my $signature = $sig->sign($message, $sk);
    my $valid = $sig->verify($message, $signature, $pk);

=head1 DESCRIPTION

Perl XS bindings for the libpqc-dyber post-quantum cryptography library.

=cut

sub version { _pqc_version() }

sub kem_algorithms {
    my $count = _pqc_kem_algorithm_count();
    return map { _pqc_kem_algorithm_name($_) } 0 .. $count - 1;
}

sub sig_algorithms {
    my $count = _pqc_sig_algorithm_count();
    return map { _pqc_sig_algorithm_name($_) } 0 .. $count - 1;
}

# ------------------------------------------------------------------ #
# KEM class
# ------------------------------------------------------------------ #

package Crypt::PQC::Dyber::KEM;

use strict;
use warnings;
use Carp;

sub new {
    my ($class, $algorithm) = @_;
    my $handle = Crypt::PQC::Dyber::_kem_new($algorithm)
        or croak "Unsupported KEM algorithm: $algorithm";
    return bless { handle => $handle, algorithm => $algorithm }, $class;
}

sub DESTROY {
    my $self = shift;
    Crypt::PQC::Dyber::_kem_free($self->{handle}) if $self->{handle};
}

sub algorithm        { $_[0]->{algorithm} }
sub public_key_size  { Crypt::PQC::Dyber::_kem_public_key_size($_[0]->{handle}) }
sub secret_key_size  { Crypt::PQC::Dyber::_kem_secret_key_size($_[0]->{handle}) }
sub ciphertext_size  { Crypt::PQC::Dyber::_kem_ciphertext_size($_[0]->{handle}) }
sub shared_secret_size { Crypt::PQC::Dyber::_kem_shared_secret_size($_[0]->{handle}) }

sub keygen {
    my $self = shift;
    return Crypt::PQC::Dyber::_kem_keygen($self->{handle});
}

sub encaps {
    my ($self, $public_key) = @_;
    return Crypt::PQC::Dyber::_kem_encaps($self->{handle}, $public_key);
}

sub decaps {
    my ($self, $ciphertext, $secret_key) = @_;
    return Crypt::PQC::Dyber::_kem_decaps($self->{handle}, $ciphertext, $secret_key);
}

# ------------------------------------------------------------------ #
# Signature class
# ------------------------------------------------------------------ #

package Crypt::PQC::Dyber::Signature;

use strict;
use warnings;
use Carp;

sub new {
    my ($class, $algorithm) = @_;
    my $handle = Crypt::PQC::Dyber::_sig_new($algorithm)
        or croak "Unsupported signature algorithm: $algorithm";
    return bless { handle => $handle, algorithm => $algorithm }, $class;
}

sub DESTROY {
    my $self = shift;
    Crypt::PQC::Dyber::_sig_free($self->{handle}) if $self->{handle};
}

sub algorithm           { $_[0]->{algorithm} }
sub public_key_size     { Crypt::PQC::Dyber::_sig_public_key_size($_[0]->{handle}) }
sub secret_key_size     { Crypt::PQC::Dyber::_sig_secret_key_size($_[0]->{handle}) }
sub max_signature_size  { Crypt::PQC::Dyber::_sig_max_signature_size($_[0]->{handle}) }

sub keygen {
    my $self = shift;
    return Crypt::PQC::Dyber::_sig_keygen($self->{handle});
}

sub sign {
    my ($self, $message, $secret_key) = @_;
    return Crypt::PQC::Dyber::_sig_sign($self->{handle}, $message, $secret_key);
}

sub verify {
    my ($self, $message, $signature, $public_key) = @_;
    return Crypt::PQC::Dyber::_sig_verify($self->{handle}, $message, $signature, $public_key);
}

1;

__END__

=head1 LICENSE

Apache-2.0 OR MIT

=head1 COPYRIGHT

Copyright (c) 2024-2026 Dyber, Inc.

=cut
