# libpqc-dyber - Post-Quantum Cryptography Library
# Copyright (c) 2024-2026 Dyber, Inc.
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# KEM (Key Encapsulation Mechanism) class.

module PqcDyber
  class KEM
    attr_reader :algorithm

    # Create a KEM instance for the given algorithm.
    #
    # @param algorithm [String] e.g. "ML-KEM-768"
    # @raise [RuntimeError] if algorithm is not supported
    def initialize(algorithm)
      @algorithm = algorithm
      @handle = PqcDyber.pqc_kem_new(algorithm)
      raise "Unsupported KEM algorithm: #{algorithm}" if @handle.null?

      ObjectSpace.define_finalizer(self, self.class._release(@handle))
    end

    def public_key_size
      PqcDyber.pqc_kem_public_key_size(@handle)
    end

    def secret_key_size
      PqcDyber.pqc_kem_secret_key_size(@handle)
    end

    def ciphertext_size
      PqcDyber.pqc_kem_ciphertext_size(@handle)
    end

    def shared_secret_size
      PqcDyber.pqc_kem_shared_secret_size(@handle)
    end

    def security_level
      PqcDyber.pqc_kem_security_level(@handle)
    end

    # Generate a keypair.
    #
    # @return [Hash] { public_key: String, secret_key: String }
    def keygen
      pk = FFI::MemoryPointer.new(:uint8, public_key_size)
      sk = FFI::MemoryPointer.new(:uint8, secret_key_size)
      rc = PqcDyber.pqc_kem_keygen(@handle, pk, sk)
      raise "KEM keygen failed: #{PqcDyber.pqc_status_string(rc)}" unless rc == 0

      { public_key: pk.read_bytes(public_key_size),
        secret_key: sk.read_bytes(secret_key_size) }
    end

    # Encapsulate: generate shared secret and ciphertext from a public key.
    #
    # @param public_key [String]
    # @return [Hash] { ciphertext: String, shared_secret: String }
    def encaps(public_key)
      ct = FFI::MemoryPointer.new(:uint8, ciphertext_size)
      ss = FFI::MemoryPointer.new(:uint8, shared_secret_size)
      pk_buf = FFI::MemoryPointer.from_string(public_key)

      rc = PqcDyber.pqc_kem_encaps(@handle, ct, ss, pk_buf)
      raise "KEM encaps failed: #{PqcDyber.pqc_status_string(rc)}" unless rc == 0

      { ciphertext: ct.read_bytes(ciphertext_size),
        shared_secret: ss.read_bytes(shared_secret_size) }
    end

    # Decapsulate: recover shared secret from ciphertext using secret key.
    #
    # @param ciphertext [String]
    # @param secret_key [String]
    # @return [String] the shared secret
    def decaps(ciphertext, secret_key)
      ss = FFI::MemoryPointer.new(:uint8, shared_secret_size)
      ct_buf = FFI::MemoryPointer.from_string(ciphertext)
      sk_buf = FFI::MemoryPointer.from_string(secret_key)

      rc = PqcDyber.pqc_kem_decaps(@handle, ss, ct_buf, sk_buf)
      raise "KEM decaps failed: #{PqcDyber.pqc_status_string(rc)}" unless rc == 0

      ss.read_bytes(shared_secret_size)
    end

    # @private
    def self._release(handle)
      proc { PqcDyber.pqc_kem_free(handle) }
    end
  end
end
