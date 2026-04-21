# philiprehberger-crypt

[![Tests](https://github.com/philiprehberger/rb-crypt/actions/workflows/ci.yml/badge.svg)](https://github.com/philiprehberger/rb-crypt/actions/workflows/ci.yml)
[![Gem Version](https://badge.fury.io/rb/philiprehberger-crypt.svg)](https://rubygems.org/gems/philiprehberger-crypt)
[![Last updated](https://img.shields.io/github/last-commit/philiprehberger/rb-crypt)](https://github.com/philiprehberger/rb-crypt/commits/main)

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

### Key Rotation

```ruby
old_key = Philiprehberger::Crypt.random_hex(16)
new_key = Philiprehberger::Crypt.random_hex(16)

encrypted = Philiprehberger::Crypt.encrypt("secret", key: old_key)
rotated = Philiprehberger::Crypt.rotate_key(encrypted, old_key: old_key, new_key: new_key)

Philiprehberger::Crypt.decrypt(rotated, key: new_key)
# => "secret"
```

### Envelope Encryption

```ruby
master_key = Philiprehberger::Crypt.random_hex(16)

envelope = Philiprehberger::Crypt.envelope_encrypt("secret data", master_key: master_key)
# => { encrypted_data: "...", encrypted_key: "..." }

Philiprehberger::Crypt.envelope_decrypt(envelope, master_key: master_key)
# => "secret data"
```

### Hashing

```ruby
Philiprehberger::Crypt.hash("data to hash")
# => "b8e6cd431..."  (SHA-256 hex digest)

Philiprehberger::Crypt.hash("data", algorithm: :sha384)
Philiprehberger::Crypt.hash("data", algorithm: :sha512)
```

### Random Bytes

```ruby
Philiprehberger::Crypt.random_bytes(32)
# => 32-byte binary string
```

### HMAC Signing

```ruby
key = Philiprehberger::Crypt.random_hex(16)
signature = Philiprehberger::Crypt.hmac("payload", key: key)

Philiprehberger::Crypt.hmac_verify("payload", signature: signature, key: key)
# => true
```

### Combined Hash and HMAC

```ruby
key = Philiprehberger::Crypt.random_hex(16)
result = Philiprehberger::Crypt.hash_and_hmac('payload', key: key)
# => { hash: '...', hmac: '...' }

result = Philiprehberger::Crypt.hash_and_hmac('payload', key: key, algorithm: :sha512)
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
| `.rotate_key(encrypted, old_key:, new_key:)` | Re-encrypt data with a new key |
| `.envelope_encrypt(data, master_key:)` | Envelope encrypt with random data key |
| `.envelope_decrypt(envelope, master_key:)` | Decrypt envelope-encrypted data |
| `.derive_key(password, salt:, iterations:)` | Derive a 32-byte key using PBKDF2-HMAC-SHA256 |
| `.hmac(data, key:, algorithm:)` | Compute hex-encoded HMAC signature |
| `.hmac_verify(data, signature:, key:, algorithm:)` | Constant-time HMAC verification |
| `.random_salt` | Generate a 32-byte cryptographic random salt |
| `.random_token` | Generate a URL-safe Base64 random token |
| `.random_hex(n)` | Generate a hex-encoded random string (2*n characters) |
| `.random_bytes(n)` | Generate n cryptographically secure random bytes |
| `.hash(data, algorithm:)` | Compute hex digest (SHA-256, SHA-384, or SHA-512) |
| `.hash_and_hmac(data, key:, algorithm:)` | Compute hash and HMAC signature in one call |
| `.secure_compare(a, b)` | Constant-time string comparison |
| `DecryptionError` | Raised when decryption fails |

## Development

```bash
bundle install
bundle exec rspec
bundle exec rubocop
```

## Support

If you find this project useful:

⭐ [Star the repo](https://github.com/philiprehberger/rb-crypt)

🐛 [Report issues](https://github.com/philiprehberger/rb-crypt/issues?q=is%3Aissue+is%3Aopen+label%3Abug)

💡 [Suggest features](https://github.com/philiprehberger/rb-crypt/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement)

❤️ [Sponsor development](https://github.com/sponsors/philiprehberger)

🌐 [All Open Source Projects](https://philiprehberger.com/open-source-packages)

💻 [GitHub Profile](https://github.com/philiprehberger)

🔗 [LinkedIn Profile](https://www.linkedin.com/in/philiprehberger)

## License

[MIT](LICENSE)
