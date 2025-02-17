# Changelog

All notable changes to this gem will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-04-09

### Added
- `hmac(data, key:, algorithm:)` for computing HMAC signatures (SHA-256/384/512)
- `hmac_verify(data, signature:, key:, algorithm:)` for constant-time HMAC verification
- `derive_key` now accepts an `iterations:` keyword to configure PBKDF2 work factor

## [0.2.0] - 2026-04-03

### Added
- `rotate_key(encrypted, old_key:, new_key:)` for re-encrypting data with a new key
- `envelope_encrypt(data, master_key:)` and `envelope_decrypt(envelope, master_key:)` for envelope encryption with random data keys
- `random_bytes(n)` for generating cryptographically secure random bytes
- `hash(data, algorithm:)` now supports `:sha256`, `:sha384`, and `:sha512` algorithms

## [0.1.4] - 2026-03-31

### Added
- Add GitHub issue templates, dependabot config, and PR template

## [0.1.3] - 2026-03-31

### Changed
- Standardize README badges, support section, and license format

## [0.1.2] - 2026-03-22

### Changed
- Expand test coverage with edge cases, boundary conditions, and error paths

## [0.1.1] - 2026-03-22

### Changed
- Update rubocop configuration for Windows compatibility

## [0.1.0] - 2026-03-22

### Added
- Initial release
- AES-256-GCM encryption and decryption with authenticated data
- PBKDF2 key derivation from password and salt
- Secure random salt, token, and hex generation
- SHA-256 hashing
- Constant-time string comparison
