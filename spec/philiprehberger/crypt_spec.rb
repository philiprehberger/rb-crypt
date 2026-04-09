# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Philiprehberger::Crypt do
  it 'has a version number' do
    expect(Philiprehberger::Crypt::VERSION).not_to be_nil
  end

  describe '.encrypt and .decrypt' do
    let(:key) { described_class.random_hex(16) }

    it 'encrypts and decrypts data round-trip' do
      plaintext = 'Hello, World!'
      encrypted = described_class.encrypt(plaintext, key: key)
      decrypted = described_class.decrypt(encrypted, key: key)

      expect(decrypted).to eq(plaintext)
    end

    it 'produces different ciphertext for the same plaintext' do
      plaintext = 'test data'
      encrypted1 = described_class.encrypt(plaintext, key: key)
      encrypted2 = described_class.encrypt(plaintext, key: key)

      expect(encrypted1).not_to eq(encrypted2)
    end

    it 'handles short strings' do
      encrypted = described_class.encrypt('a', key: key)
      decrypted = described_class.decrypt(encrypted, key: key)

      expect(decrypted).to eq('a')
    end

    it 'handles binary data' do
      data = (0..255).map(&:chr).join
      encrypted = described_class.encrypt(data, key: key)
      decrypted = described_class.decrypt(encrypted, key: key)

      expect(decrypted).to eq(data)
    end

    it 'raises DecryptionError with wrong key' do
      encrypted = described_class.encrypt('secret', key: key)
      wrong_key = described_class.random_hex(16)

      expect do
        described_class.decrypt(encrypted, key: wrong_key)
      end.to raise_error(Philiprehberger::Crypt::DecryptionError)
    end

    it 'raises DecryptionError with tampered data' do
      encrypted = described_class.encrypt('secret', key: key)
      tampered = "#{encrypted.chop}X"

      expect do
        described_class.decrypt(tampered, key: key)
      end.to raise_error(StandardError)
    end

    it 'raises ArgumentError with invalid key length' do
      expect do
        described_class.encrypt('data', key: 'short')
      end.to raise_error(ArgumentError)
    end

    it 'accepts raw 32-byte keys' do
      raw_key = described_class.random_salt
      encrypted = described_class.encrypt('test', key: raw_key)
      decrypted = described_class.decrypt(encrypted, key: raw_key)

      expect(decrypted).to eq('test')
    end
  end

  describe '.derive_key' do
    it 'derives a 32-byte key from password and salt' do
      salt = described_class.random_salt
      key = described_class.derive_key('my-password', salt: salt)

      expect(key.bytesize).to eq(32)
    end

    it 'produces the same key for the same password and salt' do
      salt = described_class.random_salt
      key1 = described_class.derive_key('password', salt: salt)
      key2 = described_class.derive_key('password', salt: salt)

      expect(key1).to eq(key2)
    end

    it 'produces different keys for different passwords' do
      salt = described_class.random_salt
      key1 = described_class.derive_key('password1', salt: salt)
      key2 = described_class.derive_key('password2', salt: salt)

      expect(key1).not_to eq(key2)
    end

    it 'produces different keys for different salts' do
      key1 = described_class.derive_key('password', salt: described_class.random_salt)
      key2 = described_class.derive_key('password', salt: described_class.random_salt)

      expect(key1).not_to eq(key2)
    end

    it 'works with encrypt/decrypt' do
      salt = described_class.random_salt
      key = described_class.derive_key('my-secret-password', salt: salt)

      encrypted = described_class.encrypt('sensitive data', key: key)
      decrypted = described_class.decrypt(encrypted, key: key)

      expect(decrypted).to eq('sensitive data')
    end
  end

  describe '.random_salt' do
    it 'returns a 32-byte string' do
      salt = described_class.random_salt
      expect(salt.bytesize).to eq(32)
    end

    it 'produces unique values' do
      salts = Array.new(10) { described_class.random_salt }
      expect(salts.uniq.length).to eq(10)
    end
  end

  describe '.random_token' do
    it 'returns a URL-safe Base64 string' do
      token = described_class.random_token
      expect(token).to match(/\A[A-Za-z0-9_-]+\z/)
    end

    it 'produces unique values' do
      tokens = Array.new(10) { described_class.random_token }
      expect(tokens.uniq.length).to eq(10)
    end
  end

  describe '.random_hex' do
    it 'returns a hex string of the specified length' do
      hex = described_class.random_hex(16)
      expect(hex.length).to eq(32)
      expect(hex).to match(/\A[0-9a-f]+\z/)
    end

    it 'defaults to 32 bytes (64 hex chars)' do
      hex = described_class.random_hex
      expect(hex.length).to eq(64)
    end
  end

  describe '.hash' do
    it 'returns a SHA-256 hex digest by default' do
      digest = described_class.hash('hello')
      expect(digest.length).to eq(64)
      expect(digest).to match(/\A[0-9a-f]+\z/)
    end

    it 'produces consistent results' do
      expect(described_class.hash('test')).to eq(described_class.hash('test'))
    end

    it 'produces different results for different input' do
      expect(described_class.hash('a')).not_to eq(described_class.hash('b'))
    end

    it 'supports sha384 algorithm' do
      digest = described_class.hash('hello', algorithm: :sha384)
      expect(digest.length).to eq(96)
      expect(digest).to match(/\A[0-9a-f]+\z/)
    end

    it 'supports sha512 algorithm' do
      digest = described_class.hash('hello', algorithm: :sha512)
      expect(digest.length).to eq(128)
      expect(digest).to match(/\A[0-9a-f]+\z/)
    end

    it 'raises ArgumentError for unsupported algorithm' do
      expect { described_class.hash('hello', algorithm: :md5) }.to raise_error(ArgumentError, /Unsupported algorithm/)
    end
  end

  describe '.secure_compare' do
    it 'returns true for equal strings' do
      expect(described_class.secure_compare('abc', 'abc')).to be(true)
    end

    it 'returns false for different strings' do
      expect(described_class.secure_compare('abc', 'def')).to be(false)
    end

    it 'returns false for strings of different lengths' do
      expect(described_class.secure_compare('ab', 'abc')).to be(false)
    end

    it 'returns true for empty strings' do
      expect(described_class.secure_compare('', '')).to be(true)
    end

    it 'returns true for identical long strings' do
      long = 'a' * 1000
      expect(described_class.secure_compare(long, long.dup)).to be(true)
    end

    it 'returns false when strings differ by one character' do
      a = 'abcdefghij'
      b = 'abcdefghik'
      expect(described_class.secure_compare(a, b)).to be(false)
    end
  end

  describe '.rotate_key' do
    let(:old_key) { described_class.random_hex(16) }
    let(:new_key) { described_class.random_hex(16) }

    it 'decrypts with old key and re-encrypts with new key' do
      plaintext = 'sensitive data'
      encrypted = described_class.encrypt(plaintext, key: old_key)

      rotated = described_class.rotate_key(encrypted, old_key: old_key, new_key: new_key)

      expect(rotated).not_to eq(encrypted)
      expect(described_class.decrypt(rotated, key: new_key)).to eq(plaintext)
    end

    it 'raises DecryptionError with wrong old key' do
      encrypted = described_class.encrypt('data', key: old_key)
      wrong_key = described_class.random_hex(16)

      expect do
        described_class.rotate_key(encrypted, old_key: wrong_key, new_key: new_key)
      end.to raise_error(Philiprehberger::Crypt::DecryptionError)
    end
  end

  describe '.envelope_encrypt and .envelope_decrypt' do
    let(:master_key) { described_class.random_hex(16) }

    it 'encrypts and decrypts data round-trip' do
      plaintext = 'envelope secret'
      envelope = described_class.envelope_encrypt(plaintext, master_key: master_key)

      expect(envelope).to have_key(:encrypted_data)
      expect(envelope).to have_key(:encrypted_key)
      expect(envelope[:encrypted_data]).to be_a(String)
      expect(envelope[:encrypted_key]).to be_a(String)

      decrypted = described_class.envelope_decrypt(envelope, master_key: master_key)
      expect(decrypted).to eq(plaintext)
    end

    it 'raises DecryptionError with wrong master key' do
      envelope = described_class.envelope_encrypt('secret', master_key: master_key)
      wrong_master = described_class.random_hex(16)

      expect do
        described_class.envelope_decrypt(envelope, master_key: wrong_master)
      end.to raise_error(Philiprehberger::Crypt::DecryptionError)
    end

    it 'uses a unique data key each time' do
      envelope1 = described_class.envelope_encrypt('same', master_key: master_key)
      envelope2 = described_class.envelope_encrypt('same', master_key: master_key)

      expect(envelope1[:encrypted_key]).not_to eq(envelope2[:encrypted_key])
    end
  end

  describe '.random_bytes' do
    it 'returns a string of the requested length' do
      bytes = described_class.random_bytes(16)
      expect(bytes.bytesize).to eq(16)
    end

    it 'returns a binary string' do
      bytes = described_class.random_bytes(32)
      expect(bytes.encoding).to eq(Encoding::ASCII_8BIT)
    end

    it 'produces unique values' do
      values = Array.new(10) { described_class.random_bytes(16) }
      expect(values.uniq.length).to eq(10)
    end
  end

  describe '.encrypt and .decrypt (extended)' do
    let(:key) { described_class.random_hex(16) }

    it 'handles empty string data' do
      encrypted = described_class.encrypt('', key: key)
      decrypted = described_class.decrypt(encrypted, key: key)
      expect(decrypted).to eq('')
    end

    it 'handles unicode data' do
      unicode = "Hello \u{1F600} World \u{00E9}\u{00F1}\u{00FC}"
      encrypted = described_class.encrypt(unicode, key: key)
      decrypted = described_class.decrypt(encrypted, key: key)
      expect(decrypted.force_encoding('UTF-8')).to eq(unicode)
    end

    it 'handles large data' do
      large = 'x' * 100_000
      encrypted = described_class.encrypt(large, key: key)
      decrypted = described_class.decrypt(encrypted, key: key)
      expect(decrypted).to eq(large)
    end

    it 'converts non-string data to string via to_s' do
      encrypted = described_class.encrypt(12_345, key: key)
      decrypted = described_class.decrypt(encrypted, key: key)
      expect(decrypted).to eq('12345')
    end

    it 'raises ArgumentError for key that is too long but not hex' do
      bad_key = 'x' * 50
      expect { described_class.encrypt('data', key: bad_key) }.to raise_error(ArgumentError)
    end

    it 'raises DecryptionError for completely invalid base64 data' do
      expect do
        described_class.decrypt('!!not-base64!!', key: key)
      end.to raise_error(StandardError)
    end
  end

  describe '.hmac and .hmac_verify' do
    let(:key) { described_class.random_hex(16) }

    it 'produces a hex-encoded sha256 HMAC by default' do
      sig = described_class.hmac('payload', key: key)
      expect(sig.length).to eq(64)
      expect(sig).to match(/\A[0-9a-f]+\z/)
    end

    it 'is deterministic for the same inputs' do
      expect(described_class.hmac('data', key: key)).to eq(described_class.hmac('data', key: key))
    end

    it 'produces different signatures for different data' do
      expect(described_class.hmac('a', key: key)).not_to eq(described_class.hmac('b', key: key))
    end

    it 'produces different signatures for different keys' do
      k2 = described_class.random_hex(16)
      expect(described_class.hmac('data', key: key)).not_to eq(described_class.hmac('data', key: k2))
    end

    it 'supports sha384 and sha512 algorithms' do
      expect(described_class.hmac('data', key: key, algorithm: :sha384).length).to eq(96)
      expect(described_class.hmac('data', key: key, algorithm: :sha512).length).to eq(128)
    end

    it 'raises ArgumentError for unsupported algorithm' do
      expect { described_class.hmac('data', key: key, algorithm: :md5) }.to raise_error(ArgumentError)
    end

    it 'verifies a valid signature' do
      sig = described_class.hmac('payload', key: key)
      expect(described_class.hmac_verify('payload', signature: sig, key: key)).to be(true)
    end

    it 'rejects a tampered signature' do
      sig = described_class.hmac('payload', key: key)
      tampered = "#{sig[0..-2]}#{sig[-1] == '0' ? '1' : '0'}"
      expect(described_class.hmac_verify('payload', signature: tampered, key: key)).to be(false)
    end

    it 'rejects signature with wrong key' do
      sig = described_class.hmac('payload', key: key)
      expect(described_class.hmac_verify('payload', signature: sig, key: described_class.random_hex(16))).to be(false)
    end

    it 'rejects signature for modified data' do
      sig = described_class.hmac('payload', key: key)
      expect(described_class.hmac_verify('payload2', signature: sig, key: key)).to be(false)
    end

    it 'verifies across algorithms' do
      sig = described_class.hmac('data', key: key, algorithm: :sha512)
      expect(described_class.hmac_verify('data', signature: sig, key: key, algorithm: :sha512)).to be(true)
    end
  end

  describe '.derive_key with custom iterations' do
    it 'accepts a custom iteration count' do
      salt = described_class.random_salt
      key = described_class.derive_key('pw', salt: salt, iterations: 1_000)
      expect(key.bytesize).to eq(32)
    end

    it 'produces different keys for different iteration counts' do
      salt = described_class.random_salt
      k1 = described_class.derive_key('pw', salt: salt, iterations: 1_000)
      k2 = described_class.derive_key('pw', salt: salt, iterations: 2_000)
      expect(k1).not_to eq(k2)
    end

    it 'raises ArgumentError for zero iterations' do
      salt = described_class.random_salt
      expect { described_class.derive_key('pw', salt: salt, iterations: 0) }.to raise_error(ArgumentError)
    end
  end

  describe '.derive_key (extended)' do
    it 'converts non-string password via to_s' do
      salt = described_class.random_salt
      key = described_class.derive_key(12_345, salt: salt)
      expect(key.bytesize).to eq(32)
    end

    it 'works with empty password' do
      salt = described_class.random_salt
      key = described_class.derive_key('', salt: salt)
      expect(key.bytesize).to eq(32)
    end
  end

  describe '.random_token (extended)' do
    it 'produces tokens of consistent length' do
      tokens = Array.new(5) { described_class.random_token }
      lengths = tokens.map(&:length).uniq
      expect(lengths.size).to eq(1)
    end
  end

  describe '.random_hex (extended)' do
    it 'returns different values on each call' do
      hexes = Array.new(10) { described_class.random_hex(16) }
      expect(hexes.uniq.length).to eq(10)
    end

    it 'handles small byte count' do
      hex = described_class.random_hex(1)
      expect(hex.length).to eq(2)
      expect(hex).to match(/\A[0-9a-f]+\z/)
    end
  end

  describe '.hash (extended)' do
    it 'hashes empty string' do
      digest = described_class.hash('')
      expect(digest.length).to eq(64)
      expect(digest).to match(/\A[0-9a-f]+\z/)
    end

    it 'converts non-string via to_s' do
      digest = described_class.hash(42)
      expect(digest).to eq(described_class.hash('42'))
    end

    it "produces known SHA-256 for 'hello'" do
      expect(described_class.hash('hello')).to eq(
        '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
      )
    end

    it 'produces consistent results for sha384' do
      expect(described_class.hash('test', algorithm: :sha384)).to eq(described_class.hash('test', algorithm: :sha384))
    end

    it 'produces consistent results for sha512' do
      expect(described_class.hash('test', algorithm: :sha512)).to eq(described_class.hash('test', algorithm: :sha512))
    end

    it 'produces different digests for different algorithms' do
      sha256 = described_class.hash('hello', algorithm: :sha256)
      sha384 = described_class.hash('hello', algorithm: :sha384)
      sha512 = described_class.hash('hello', algorithm: :sha512)

      expect([sha256, sha384, sha512].uniq.length).to eq(3)
    end
  end
end
