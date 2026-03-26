# libpqc-dyber - Post-Quantum Cryptography Library
# Copyright (c) 2024-2026 Dyber, Inc.
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Main module for pqc-dyber Ruby bindings.

require 'ffi'
require_relative 'pqc_dyber/kem'
require_relative 'pqc_dyber/signature'

module PqcDyber
  extend FFI::Library

  lib_name = case RbConfig::CONFIG['host_os']
             when /mswin|mingw|cygwin/ then 'pqc'
             when /darwin/ then 'libpqc.dylib'
             else 'libpqc.so'
             end

  ffi_lib lib_name

  # Version
  attach_function :pqc_version, [], :string
  attach_function :pqc_version_major, [], :int
  attach_function :pqc_version_minor, [], :int
  attach_function :pqc_version_patch, [], :int

  # Lifecycle
  attach_function :pqc_init, [], :int
  attach_function :pqc_cleanup, [], :void

  # Status
  attach_function :pqc_status_string, [:int], :string

  # Algorithm enumeration
  attach_function :pqc_kem_algorithm_count, [], :int
  attach_function :pqc_kem_algorithm_name, [:int], :string
  attach_function :pqc_kem_is_enabled, [:string], :int
  attach_function :pqc_sig_algorithm_count, [], :int
  attach_function :pqc_sig_algorithm_name, [:int], :string
  attach_function :pqc_sig_is_enabled, [:string], :int

  # KEM context
  attach_function :pqc_kem_new, [:string], :pointer
  attach_function :pqc_kem_free, [:pointer], :void
  attach_function :pqc_kem_algorithm, [:pointer], :string
  attach_function :pqc_kem_public_key_size, [:pointer], :size_t
  attach_function :pqc_kem_secret_key_size, [:pointer], :size_t
  attach_function :pqc_kem_ciphertext_size, [:pointer], :size_t
  attach_function :pqc_kem_shared_secret_size, [:pointer], :size_t
  attach_function :pqc_kem_security_level, [:pointer], :int
  attach_function :pqc_kem_keygen, [:pointer, :pointer, :pointer], :int
  attach_function :pqc_kem_encaps, [:pointer, :pointer, :pointer, :pointer], :int
  attach_function :pqc_kem_decaps, [:pointer, :pointer, :pointer, :pointer], :int

  # Signature context
  attach_function :pqc_sig_new, [:string], :pointer
  attach_function :pqc_sig_free, [:pointer], :void
  attach_function :pqc_sig_algorithm, [:pointer], :string
  attach_function :pqc_sig_public_key_size, [:pointer], :size_t
  attach_function :pqc_sig_secret_key_size, [:pointer], :size_t
  attach_function :pqc_sig_max_signature_size, [:pointer], :size_t
  attach_function :pqc_sig_security_level, [:pointer], :int
  attach_function :pqc_sig_is_stateful, [:pointer], :int
  attach_function :pqc_sig_keygen, [:pointer, :pointer, :pointer], :int
  attach_function :pqc_sig_sign, [:pointer, :pointer, :pointer, :pointer, :size_t, :pointer], :int
  attach_function :pqc_sig_verify, [:pointer, :pointer, :size_t, :pointer, :size_t, :pointer], :int

  # Initialize the library on load
  rc = pqc_init
  raise "Failed to initialize libpqc: #{rc}" unless rc == 0

  # Convenience methods

  def self.version
    pqc_version
  end

  def self.kem_algorithms
    count = pqc_kem_algorithm_count
    (0...count).map { |i| pqc_kem_algorithm_name(i) }
  end

  def self.sig_algorithms
    count = pqc_sig_algorithm_count
    (0...count).map { |i| pqc_sig_algorithm_name(i) }
  end
end
