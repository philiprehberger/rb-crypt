# philiprehberger-crypt

[![Tests](https://github.com/philiprehberger/rb-crypt/actions/workflows/ci.yml/badge.svg)](https://github.com/philiprehberger/rb-crypt/actions/workflows/ci.yml)
[![Gem Version](https://badge.fury.io/rb/philiprehberger-crypt.svg)](https://rubygems.org/gems/philiprehberger-crypt)
[![License](https://img.shields.io/github/license/philiprehberger/rb-crypt)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-GitHub%20Sponsors-ec6cb9)](https://github.com/sponsors/philiprehberger)

High-level encryption with AES-256-GCM, key derivation, and secure random

## Requirements

- Ruby >= 3.1

## Installation

Add to your Gemfile:

```ruby
gem "philiprehberger-crypt"
```

Or install directly:

```bash
gem install philiprehberger-crypt
```

## Usage

```ruby
require "philiprehberger/crypt"

# Generate a random key and encrypt data
key = Philiprehberger::Crypt.random_hex(16)
encrypted = Philiprehberger::Crypt.encrypt("Hello, World!", key: key)
decrypted = Philiprehberger::Crypt.decrypt(encrypted, key: key)
# => "Hello, World!"
```

### Key Derivation

```ruby
salt = Philiprehberger::Crypt.random_salt
key = Philiprehberger::Crypt.derive_key("my-password", salt: salt)

encrypted = Philiprehberger::Crypt.encrypt("secret data", key: key)
decrypted = Philiprehberger::Crypt.decrypt(encrypted, key: key)
```

### Secure Random Generation

```ruby
Philiprehberger::Crypt.random_salt    # => 32-byte random salt
Philiprehberger::Crypt.random_token   # => URL-safe Base64 token
Philiprehberger::Crypt.random_hex(16) # => 32-character hex string
```

### Hashing

```ruby
digest = Philiprehberger::Crypt.hash("data to hash")
# => "b8e6cd431..."  (SHA-256 hex digest)
```

### Secure Comparison

```ruby
Philiprehberger::Crypt.secure_compare(token_a, token_b)
# => true/false (constant-time comparison)
```

## API

| Method | Description |
|--------|-------------|
| `.encrypt(data, key:)` | Encrypt data using AES-256-GCM |
| `.decrypt(data, key:)` | Decrypt data encrypted with `.encrypt` |
| `.derive_key(password, salt:)` | Derive a 32-byte key using PBKDF2-HMAC-SHA256 |
| `.random_salt` | Generate a 32-byte cryptographic random salt |
| `.random_token` | Generate a URL-safe Base64 random token |
| `.random_hex(n)` | Generate a hex-encoded random string (2*n characters) |
| `.hash(data)` | Compute SHA-256 hex digest |
| `.secure_compare(a, b)` | Constant-time string comparison |
| `DecryptionError` | Raised when decryption fails |

## Development

```bash
bundle install
bundle exec rspec
bundle exec rubocop
```

## License

MIT
