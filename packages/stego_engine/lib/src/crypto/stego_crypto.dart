import 'dart:math';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

import '../errors/stego_errors.dart';

/// Cryptographic services supporting StegoEngine container encryption.
///
/// Implements AES-256-GCM authenticated encryption and Argon2id password-based
/// key derivation using audited primitives from the `cryptography` package.
class StegoCrypto {
  /// Standard salt length in bytes (128 bits).
  static const int saltLength = 16;

  /// Standard AES-GCM nonce length in bytes (96 bits).
  static const int nonceLength = 12;

  /// Standard AES-GCM authentication tag length in bytes (128 bits).
  static const int authTagLength = 16;

  /// Argon2id iterations (time cost).
  static const int argon2Iterations = 2;

  /// Argon2id memory cost in KiB (~19 MB).
  static const int argon2MemoryKiB = 19456;

  /// Argon2id parallelism (lanes).
  static const int argon2Parallelism = 1;

  final AesGcm _cipher;
  final Argon2id _kdf;
  final Random _random;

  StegoCrypto({
    AesGcm? cipher,
    Argon2id? kdf,
    Random? random,
  })  : _cipher = cipher ?? AesGcm.with256bits(),
        _kdf = kdf ??
            Argon2id(
              parallelism: argon2Parallelism,
              memory: argon2MemoryKiB,
              iterations: argon2Iterations,
              hashLength: 32,
            ),
        _random = random ?? Random.secure();

  /// Generates cryptographically secure random bytes.
  Uint8List generateRandomBytes(int length) {
    if (length <= 0) return Uint8List(0);
    final bytes = Uint8List(length);
    for (int i = 0; i < length; i++) {
      bytes[i] = _random.nextInt(256);
    }
    return bytes;
  }

  /// Generates a fresh 16-byte random salt for Argon2id.
  Uint8List generateSalt() => generateRandomBytes(saltLength);

  /// Generates a fresh 12-byte random nonce for AES-256-GCM.
  Uint8List generateNonce() => generateRandomBytes(nonceLength);

  /// Derives a 256-bit symmetric key from a user password and salt using Argon2id.
  Future<SecretKey> deriveKey({
    required String password,
    required List<int> salt,
  }) async {
    if (password.isEmpty) {
      throw const InvalidInputException('Password cannot be empty.');
    }
    if (salt.length < 8) {
      throw const InvalidInputException('Salt must be at least 8 bytes.');
    }

    try {
      final secretKey = await _kdf.deriveKeyFromPassword(
        password: password,
        nonce: salt,
      );
      return secretKey;
    } catch (e) {
      throw AuthenticationException('Failed to derive key from password: $e');
    }
  }

  /// Encrypts plaintext bytes using AES-256-GCM with associated authenticated data (AAD).
  ///
  /// Returns a record of `(ciphertext, tag)`.
  Future<({Uint8List ciphertext, Uint8List tag})> encrypt({
    required List<int> plaintext,
    required SecretKey key,
    required List<int> nonce,
    required List<int> aad,
  }) async {
    if (nonce.length != nonceLength) {
      throw InvalidInputException('Nonce must be exactly $nonceLength bytes.');
    }

    try {
      final secretBox = await _cipher.encrypt(
        plaintext,
        secretKey: key,
        nonce: nonce,
        aad: aad,
      );

      final ciphertext = Uint8List.fromList(secretBox.cipherText);
      final tag = Uint8List.fromList(secretBox.mac.bytes);
      return (ciphertext: ciphertext, tag: tag);
    } catch (e) {
      throw AuthenticationException('Encryption failed: $e');
    }
  }

  /// Decrypts ciphertext and verifies the 16-byte authentication tag and AAD.
  ///
  /// Throws [AuthenticationException] if authentication fails or data is corrupted.
  Future<Uint8List> decrypt({
    required List<int> ciphertext,
    required SecretKey key,
    required List<int> nonce,
    required List<int> tag,
    required List<int> aad,
  }) async {
    if (nonce.length != nonceLength) {
      throw const AuthenticationException('Invalid nonce length.');
    }
    if (tag.length != authTagLength) {
      throw const AuthenticationException('Invalid authentication tag length.');
    }

    try {
      final secretBox = SecretBox(
        ciphertext,
        nonce: nonce,
        mac: Mac(tag),
      );

      final clearText = await _cipher.decrypt(
        secretBox,
        secretKey: key,
        aad: aad,
      );

      return Uint8List.fromList(clearText);
    } catch (_) {
      // Return generic failure without leaking details about cipher state
      throw const AuthenticationException();
    }
  }
}

