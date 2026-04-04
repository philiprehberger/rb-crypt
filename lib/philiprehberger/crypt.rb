# frozen_string_literal: true

require 'openssl'
require 'securerandom'
require 'base64'

module Philiprehberger
  module Crypt
    class Error < StandardError; end

    # Raised when decryption fails due to invalid key, tampered data, or corrupt ciphertext.
    class DecryptionError < Error; end

    CIPHER = 'aes-256-gcm'
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
      cipher.auth_data = ''

      plaintext = data.to_s
      ciphertext = plaintext.empty? ? cipher.final : cipher.update(plaintext) + cipher.final
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
      cipher.auth_data = ''

      ciphertext.empty? ? cipher.final : cipher.update(ciphertext) + cipher.final
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
        OpenSSL::Digest.new('SHA256')
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

    HASH_ALGORITHMS = {
      sha256: 'SHA256',
      sha384: 'SHA384',
      sha512: 'SHA512'
    }.freeze

    # Compute a cryptographic hash of data.
    #
    # @param data [String] the data to hash
    # @param algorithm [Symbol] the hash algorithm (:sha256, :sha384, or :sha512)
    # @return [String] the hex-encoded digest
    # @raise [ArgumentError] if algorithm is unsupported
    def self.hash(data, algorithm: :sha256)
      algo = HASH_ALGORITHMS[algorithm]
      raise ArgumentError, "Unsupported algorithm: #{algorithm}. Use :sha256, :sha384, or :sha512" unless algo

      OpenSSL::Digest.new(algo).hexdigest(data.to_s)
    end

    # Re-encrypt data with a new key.
    #
    # @param encrypted [String] Base64-encoded encrypted data from {.encrypt}
    # @param old_key [String] the key used for the original encryption
    # @param new_key [String] the new key to encrypt with
    # @return [String] Base64-encoded string encrypted with new_key
    # @raise [DecryptionError] if decryption with old_key fails
    # @raise [ArgumentError] if key length is invalid
    def self.rotate_key(encrypted, old_key:, new_key:)
      plaintext = decrypt(encrypted, key: old_key)
      encrypt(plaintext, key: new_key)
    end

    # Encrypt data using envelope encryption.
    #
    # Generates a random data key, encrypts data with it, then encrypts the data key with the master key.
    #
    # @param data [String] the plaintext data to encrypt
    # @param master_key [String] a 32-byte master key (raw bytes or hex-encoded)
    # @return [Hash] with :encrypted_data and :encrypted_key (both Base64 strings)
    # @raise [ArgumentError] if master_key length is invalid
    def self.envelope_encrypt(data, master_key:)
      data_key = SecureRandom.random_bytes(KEY_LENGTH)
      encrypted_data = encrypt(data, key: data_key)
      encrypted_key = encrypt(data_key, key: master_key)

      { encrypted_data: encrypted_data, encrypted_key: encrypted_key }
    end

    # Decrypt data encrypted with {.envelope_encrypt}.
    #
    # @param envelope [Hash] with :encrypted_data and :encrypted_key keys
    # @param master_key [String] the master key used during envelope encryption
    # @return [String] the decrypted plaintext
    # @raise [DecryptionError] if decryption fails
    # @raise [ArgumentError] if master_key length is invalid
    def self.envelope_decrypt(envelope, master_key:)
      data_key = decrypt(envelope[:encrypted_key], key: master_key)
      decrypt(envelope[:encrypted_data], key: data_key)
    end

    # Generate cryptographically secure random bytes.
    #
    # @param n [Integer] the number of random bytes
    # @return [String] a binary string of n random bytes
    def self.random_bytes(n)
      SecureRandom.random_bytes(n)
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

      return [key].pack('H*') if key.bytesize == KEY_LENGTH * 2 && key.match?(/\A[0-9a-fA-F]+\z/)

      raise ArgumentError, "Key must be #{KEY_LENGTH} bytes (raw) or #{KEY_LENGTH * 2} hex characters"
    end
    private_class_method :normalize_key
  end
end

require_relative 'crypt/version'
