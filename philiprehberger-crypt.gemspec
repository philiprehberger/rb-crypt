# frozen_string_literal: true

require_relative 'lib/philiprehberger/crypt/version'

Gem::Specification.new do |spec|
  spec.name = 'philiprehberger-crypt'
  spec.version = Philiprehberger::Crypt::VERSION
  spec.authors = ['Philip Rehberger']
  spec.email = ['me@philiprehberger.com']

  spec.summary = 'High-level encryption with AES-256-GCM, key derivation, and secure random'
  spec.description = 'A high-level encryption toolkit providing AES-256-GCM encryption and decryption, ' \
                     'PBKDF2 key derivation, secure random generation, SHA-256 hashing, and ' \
                     "constant-time string comparison using Ruby's built-in OpenSSL."
  spec.homepage = 'https://philiprehberger.com/open-source-packages/ruby/philiprehberger-crypt'
  spec.license = 'MIT'

  spec.required_ruby_version = '>= 3.1.0'

  spec.metadata['homepage_uri'] = spec.homepage
  spec.metadata['source_code_uri'] = 'https://github.com/philiprehberger/rb-crypt'
  spec.metadata['changelog_uri'] = 'https://github.com/philiprehberger/rb-crypt/blob/main/CHANGELOG.md'
  spec.metadata['bug_tracker_uri'] = 'https://github.com/philiprehberger/rb-crypt/issues'
  spec.metadata['rubygems_mfa_required'] = 'true'

  spec.files = Dir['lib/**/*.rb', 'LICENSE', 'README.md', 'CHANGELOG.md']
  spec.require_paths = ['lib']
end
