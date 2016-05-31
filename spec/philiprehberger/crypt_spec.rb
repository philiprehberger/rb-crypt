# frozen_string_literal: true

require "spec_helper"

RSpec.describe Philiprehberger::Crypt do
  it "has a version number" do
    expect(Philiprehberger::Crypt::VERSION).not_to be_nil
  end

  describe ".encrypt and .decrypt" do
    let(:key) { described_class.random_hex(16) }

    it "encrypts and decrypts data round-trip" do
      plaintext = "Hello, World!"
      encrypted = described_class.encrypt(plaintext, key: key)
      decrypted = described_class.decrypt(encrypted, key: key)

      expect(decrypted).to eq(plaintext)
    end

    it "produces different ciphertext for the same plaintext" do
      plaintext = "test data"
      encrypted1 = described_class.encrypt(plaintext, key: key)
      encrypted2 = described_class.encrypt(plaintext, key: key)

      expect(encrypted1).not_to eq(encrypted2)
    end

    it 'handles short strings' do
      encrypted = described_class.encrypt('a', key: key)
      decrypted = described_class.decrypt(encrypted, key: key)

      expect(decrypted).to eq('a')
    end

    it "handles binary data" do
      data = (0..255).map(&:chr).join
      encrypted = described_class.encrypt(data, key: key)
      decrypted = described_class.decrypt(encrypted, key: key)

      expect(decrypted).to eq(data)
    end

    it "raises DecryptionError with wrong key" do
      encrypted = described_class.encrypt("secret", key: key)
      wrong_key = described_class.random_hex(16)

      expect do
        described_class.decrypt(encrypted, key: wrong_key)
      end.to raise_error(Philiprehberger::Crypt::DecryptionError)
    end

    it "raises DecryptionError with tampered data" do
      encrypted = described_class.encrypt("secret", key: key)
      tampered = encrypted.chop + "X"

      expect do
        described_class.decrypt(tampered, key: key)
      end.to raise_error(StandardError)
    end

    it "raises ArgumentError with invalid key length" do
      expect do
        described_class.encrypt("data", key: "short")
      end.to raise_error(ArgumentError)
    end

    it "accepts raw 32-byte keys" do
      raw_key = described_class.random_salt
      encrypted = described_class.encrypt("test", key: raw_key)
      decrypted = described_class.decrypt(encrypted, key: raw_key)

      expect(decrypted).to eq("test")
    end
  end

  describe ".derive_key" do
    it "derives a 32-byte key from password and salt" do
      salt = described_class.random_salt
      key = described_class.derive_key("my-password", salt: salt)

      expect(key.bytesize).to eq(32)
    end

    it "produces the same key for the same password and salt" do
      salt = described_class.random_salt
      key1 = described_class.derive_key("password", salt: salt)
      key2 = described_class.derive_key("password", salt: salt)

      expect(key1).to eq(key2)
    end

    it "produces different keys for different passwords" do
      salt = described_class.random_salt
      key1 = described_class.derive_key("password1", salt: salt)
      key2 = described_class.derive_key("password2", salt: salt)

      expect(key1).not_to eq(key2)
    end

    it "produces different keys for different salts" do
      key1 = described_class.derive_key("password", salt: described_class.random_salt)
      key2 = described_class.derive_key("password", salt: described_class.random_salt)

      expect(key1).not_to eq(key2)
    end

    it "works with encrypt/decrypt" do
      salt = described_class.random_salt
      key = described_class.derive_key("my-secret-password", salt: salt)

      encrypted = described_class.encrypt("sensitive data", key: key)
      decrypted = described_class.decrypt(encrypted, key: key)

      expect(decrypted).to eq("sensitive data")
    end
  end

  describe ".random_salt" do
    it "returns a 32-byte string" do
      salt = described_class.random_salt
      expect(salt.bytesize).to eq(32)
    end

    it "produces unique values" do
      salts = Array.new(10) { described_class.random_salt }
      expect(salts.uniq.length).to eq(10)
    end
  end

  describe ".random_token" do
    it "returns a URL-safe Base64 string" do
      token = described_class.random_token
      expect(token).to match(/\A[A-Za-z0-9_-]+\z/)
    end

    it "produces unique values" do
      tokens = Array.new(10) { described_class.random_token }
      expect(tokens.uniq.length).to eq(10)
    end
  end

  describe ".random_hex" do
    it "returns a hex string of the specified length" do
      hex = described_class.random_hex(16)
      expect(hex.length).to eq(32)
      expect(hex).to match(/\A[0-9a-f]+\z/)
    end

    it "defaults to 32 bytes (64 hex chars)" do
      hex = described_class.random_hex
      expect(hex.length).to eq(64)
    end
  end

  describe ".hash" do
    it "returns a SHA-256 hex digest" do
      digest = described_class.hash("hello")
      expect(digest.length).to eq(64)
      expect(digest).to match(/\A[0-9a-f]+\z/)
    end

    it "produces consistent results" do
      expect(described_class.hash("test")).to eq(described_class.hash("test"))
    end

    it "produces different results for different input" do
      expect(described_class.hash("a")).not_to eq(described_class.hash("b"))
    end
  end

  describe ".secure_compare" do
    it "returns true for equal strings" do
      expect(described_class.secure_compare("abc", "abc")).to be(true)
    end

    it "returns false for different strings" do
      expect(described_class.secure_compare("abc", "def")).to be(false)
    end

    it "returns false for strings of different lengths" do
      expect(described_class.secure_compare("ab", "abc")).to be(false)
    end

    it "returns true for empty strings" do
      expect(described_class.secure_compare("", "")).to be(true)
    end

    it "returns true for identical long strings" do
      long = "a" * 1000
      expect(described_class.secure_compare(long, long.dup)).to be(true)
    end

    it "returns false when strings differ by one character" do
      a = "abcdefghij"
      b = "abcdefghik"
      expect(described_class.secure_compare(a, b)).to be(false)
    end
  end

  describe ".encrypt and .decrypt (extended)" do
    let(:key) { described_class.random_hex(16) }

    it "handles empty string data" do
      encrypted = described_class.encrypt("", key: key)
      decrypted = described_class.decrypt(encrypted, key: key)
      expect(decrypted).to eq("")
    end

    it "handles unicode data" do
      unicode = "Hello \u{1F600} World \u{00E9}\u{00F1}\u{00FC}"
      encrypted = described_class.encrypt(unicode, key: key)
      decrypted = described_class.decrypt(encrypted, key: key)
      expect(decrypted.force_encoding('UTF-8')).to eq(unicode)
    end

    it "handles large data" do
      large = "x" * 100_000
      encrypted = described_class.encrypt(large, key: key)
      decrypted = described_class.decrypt(encrypted, key: key)
      expect(decrypted).to eq(large)
    end

    it "converts non-string data to string via to_s" do
      encrypted = described_class.encrypt(12345, key: key)
      decrypted = described_class.decrypt(encrypted, key: key)
      expect(decrypted).to eq("12345")
    end

    it "raises ArgumentError for key that is too long but not hex" do
      bad_key = "x" * 50
      expect { described_class.encrypt("data", key: bad_key) }.to raise_error(ArgumentError)
    end

    it "raises DecryptionError for completely invalid base64 data" do
      expect do
        described_class.decrypt("!!not-base64!!", key: key)
      end.to raise_error(StandardError)
    end
  end

  describe ".derive_key (extended)" do
    it "converts non-string password via to_s" do
      salt = described_class.random_salt
      key = described_class.derive_key(12345, salt: salt)
      expect(key.bytesize).to eq(32)
    end

    it "works with empty password" do
      salt = described_class.random_salt
      key = described_class.derive_key("", salt: salt)
      expect(key.bytesize).to eq(32)
    end
  end

  describe ".random_token (extended)" do
    it "produces tokens of consistent length" do
      tokens = Array.new(5) { described_class.random_token }
      lengths = tokens.map(&:length).uniq
      expect(lengths.size).to eq(1)
    end
  end

  describe ".random_hex (extended)" do
    it "returns different values on each call" do
      hexes = Array.new(10) { described_class.random_hex(16) }
      expect(hexes.uniq.length).to eq(10)
    end

    it "handles small byte count" do
      hex = described_class.random_hex(1)
      expect(hex.length).to eq(2)
      expect(hex).to match(/\A[0-9a-f]+\z/)
    end
  end

  describe ".hash (extended)" do
    it "hashes empty string" do
      digest = described_class.hash("")
      expect(digest.length).to eq(64)
      expect(digest).to match(/\A[0-9a-f]+\z/)
    end

    it "converts non-string via to_s" do
      digest = described_class.hash(42)
      expect(digest).to eq(described_class.hash("42"))
    end

    it "produces known SHA-256 for 'hello'" do
      expect(described_class.hash("hello")).to eq(
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
      )
    end
  end
end
