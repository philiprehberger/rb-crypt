# frozen_string_literal: true

require "openssl"
require "securerandom"
require "base64"

module Philiprehberger
  module Crypt
    class Error < StandardError; end

    # Raised when decryption fails due to invalid key, tampered data, or corrupt ciphertext.
    class DecryptionError < Error; end

    CIPHER = "aes-256-gcm"
    IV_LENGTH = 12
    AUTH_TAG_LENGTH = 16
    KEY_LENGTH = 32
    SALT_LENGTH = 32
    PBKDF2_ITERATIONS = 100_000

    # Encrypt data using AES-256-GCM.
    #
    # @param data [String] the plaintext data to encrypt
    # @param key [String] a 32-byte encryption key (raw bytes or hex-encoded)
    # @return [String] Base64-encoded string containing IV + auth tag + ciphertext
    # @raise [ArgumentError] if key length is invalid
    def self.encrypt(data, key:)
      raw_key = normalize_key(key)
      cipher = OpenSSL::Cipher.new(CIPHER)
      cipher.encrypt
      cipher.key = raw_key

      iv = cipher.random_iv
      cipher.auth_data = ""

      ciphertext = cipher.update(data.to_s) + cipher.final
      auth_tag = cipher.auth_tag(AUTH_TAG_LENGTH)

      Base64.strict_encode64(iv + auth_tag + ciphertext)
    end

    # Decrypt data encrypted with {.encrypt}.
    #
    # @param data [String] Base64-encoded encrypted data from {.encrypt}
    # @param key [String] the same key used for encryption
    # @return [String] the decrypted plaintext
    # @raise [DecryptionError] if decryption fails
    # @raise [ArgumentError] if key length is invalid
    def self.decrypt(data, key:)
      raw_key = normalize_key(key)
      raw = Base64.strict_decode64(data)

      iv = raw[0, IV_LENGTH]
      auth_tag = raw[IV_LENGTH, AUTH_TAG_LENGTH]
      ciphertext = raw[(IV_LENGTH + AUTH_TAG_LENGTH)..]

      cipher = OpenSSL::Cipher.new(CIPHER)
      cipher.decrypt
      cipher.key = raw_key
      cipher.iv = iv
      cipher.auth_tag = auth_tag
      cipher.auth_data = ""

      cipher.update(ciphertext) + cipher.final
    rescue OpenSSL::Cipher::CipherError => e
      raise DecryptionError, "Decryption failed: #{e.message}"
    end

    # Derive an encryption key from a password using PBKDF2-HMAC-SHA256.
    #
    # @param password [String] the password to derive from
    # @param salt [String] a random salt (use {.random_salt} to generate)
    # @return [String] a 32-byte raw key suitable for {.encrypt}/{.decrypt}
    def self.derive_key(password, salt:)
      OpenSSL::PKCS5.pbkdf2_hmac(
        password.to_s,
        salt,
        PBKDF2_ITERATIONS,
        KEY_LENGTH,
        OpenSSL::Digest.new("SHA256")
      )
    end

    # Generate a cryptographically secure random salt.
    #
    # @return [String] a 32-byte random salt (raw bytes)
    def self.random_salt
      SecureRandom.random_bytes(SALT_LENGTH)
    end

    # Generate a cryptographically secure random token.
    #
    # @return [String] a URL-safe Base64-encoded random token (32 bytes of entropy)
    def self.random_token
      SecureRandom.urlsafe_base64(32)
    end

    # Generate a cryptographically secure random hex string.
    #
    # @param n [Integer] the number of random bytes (output will be 2*n hex characters)
    # @return [String] a hex-encoded random string
    def self.random_hex(n = 32)
      SecureRandom.hex(n)
    end

    # Compute the SHA-256 hash of data.
    #
    # @param data [String] the data to hash
    # @return [String] the hex-encoded SHA-256 digest
    def self.hash(data)
      OpenSSL::Digest.new("SHA256").hexdigest(data.to_s)
    end

    # Constant-time string comparison to prevent timing attacks.
    #
    # @param a [String] first string
    # @param b [String] second string
    # @return [Boolean] true if the strings are equal
    def self.secure_compare(a, b)
      return false unless a.bytesize == b.bytesize

      OpenSSL.fixed_length_secure_compare(a, b)
    end

    # @api private
    def self.normalize_key(key)
      return key if key.bytesize == KEY_LENGTH

      if key.bytesize == KEY_LENGTH * 2 && key.match?(/\A[0-9a-fA-F]+\z/)
        return [key].pack("H*")
      end

      raise ArgumentError, "Key must be #{KEY_LENGTH} bytes (raw) or #{KEY_LENGTH * 2} hex characters"
    end
    private_class_method :normalize_key
  end
end

require_relative "crypt/version"
