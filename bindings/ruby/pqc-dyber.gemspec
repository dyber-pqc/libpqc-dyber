# libpqc-dyber - Post-Quantum Cryptography Library
# Copyright (c) 2024-2026 Dyber, Inc.
# SPDX-License-Identifier: Apache-2.0 OR MIT

Gem::Specification.new do |spec|
  spec.name          = 'pqc-dyber'
  spec.version       = '1.0.0'
  spec.authors       = ['Dyber, Inc.']
  spec.email         = ['info@dyber.org']

  spec.summary       = 'Post-Quantum Cryptography library bindings for Ruby'
  spec.description   = 'Ruby FFI bindings for libpqc-dyber, providing ML-KEM, ML-DSA, and other post-quantum algorithms.'
  spec.homepage      = 'https://github.com/dyber-pqc/libpqc-dyber'
  spec.license       = 'Apache-2.0 OR MIT'

  spec.required_ruby_version = '>= 2.7.0'

  spec.files = Dir['lib/**/*.rb'] + ['pqc-dyber.gemspec']
  spec.require_paths = ['lib']

  spec.add_runtime_dependency 'ffi', '~> 1.15'

  spec.metadata['homepage_uri']    = spec.homepage
  spec.metadata['source_code_uri'] = spec.homepage
end
