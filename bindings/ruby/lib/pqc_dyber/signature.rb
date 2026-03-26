# libpqc-dyber - Post-Quantum Cryptography Library
# Copyright (c) 2024-2026 Dyber, Inc.
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Signature class.

module PqcDyber
  class Signature
    attr_reader :algorithm

    # Create a Signature instance for the given algorithm.
    #
    # @param algorithm [String] e.g. "ML-DSA-65"
    # @raise [RuntimeError] if algorithm is not supported
    def initialize(algorithm)
      @algorithm = algorithm
      @handle = PqcDyber.pqc_sig_new(algorithm)
      raise "Unsupported signature algorithm: #{algorithm}" if @handle.null?

      ObjectSpace.define_finalizer(self, self.class._release(@handle))
    end

    def public_key_size
      PqcDyber.pqc_sig_public_key_size(@handle)
    end

    def secret_key_size
      PqcDyber.pqc_sig_secret_key_size(@handle)
    end

    def max_signature_size
      PqcDyber.pqc_sig_max_signature_size(@handle)
    end

    def security_level
      PqcDyber.pqc_sig_security_level(@handle)
    end

    def stateful?
      PqcDyber.pqc_sig_is_stateful(@handle) != 0
    end

    # Generate a keypair.
    #
    # @return [Hash] { public_key: String, secret_key: String }
    def keygen
      pk = FFI::MemoryPointer.new(:uint8, public_key_size)
      sk = FFI::MemoryPointer.new(:uint8, secret_key_size)
      rc = PqcDyber.pqc_sig_keygen(@handle, pk, sk)
      raise "Signature keygen failed: #{PqcDyber.pqc_status_string(rc)}" unless rc == 0

      { public_key: pk.read_bytes(public_key_size),
        secret_key: sk.read_bytes(secret_key_size) }
    end

    # Sign a message.
    #
    # @param message [String]
    # @param secret_key [String]
    # @return [String] the signature
    def sign(message, secret_key)
      sig_buf = FFI::MemoryPointer.new(:uint8, max_signature_size)
      sig_len = FFI::MemoryPointer.new(:size_t)
      sig_len.write(:size_t, max_signature_size)

      msg_buf = FFI::MemoryPointer.from_string(message)
      sk_buf = FFI::MemoryPointer.from_string(secret_key)

      rc = PqcDyber.pqc_sig_sign(@handle, sig_buf, sig_len, msg_buf, message.bytesize, sk_buf)
      raise "Signature sign failed: #{PqcDyber.pqc_status_string(rc)}" unless rc == 0

      actual_len = sig_len.read(:size_t)
      sig_buf.read_bytes(actual_len)
    end

    # Verify a signature.
    #
    # @param message [String]
    # @param signature [String]
    # @param public_key [String]
    # @return [Boolean] true if valid
    def verify(message, signature, public_key)
      msg_buf = FFI::MemoryPointer.from_string(message)
      sig_buf = FFI::MemoryPointer.from_string(signature)
      pk_buf = FFI::MemoryPointer.from_string(public_key)

      rc = PqcDyber.pqc_sig_verify(@handle, msg_buf, message.bytesize,
                                     sig_buf, signature.bytesize, pk_buf)
      rc == 0
    end

    # @private
    def self._release(handle)
      proc { PqcDyber.pqc_sig_free(handle) }
    end
  end
end
