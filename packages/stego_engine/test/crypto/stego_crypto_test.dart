import 'dart:convert';
import 'dart:typed_data';
import 'package:stego_engine/src/crypto/stego_crypto.dart';
import 'package:stego_engine/src/errors/stego_errors.dart';
import 'package:test/test.dart';

void main() {
  late StegoCrypto crypto;

  setUp(() {
    crypto = StegoCrypto();
  });

  group('StegoCrypto', () {
    test('generateSalt and generateNonce produce expected lengths', () {
      final salt = crypto.generateSalt();
      expect(salt.length, equals(16));

      final nonce = crypto.generateNonce();
      expect(nonce.length, equals(12));

      // Different invocations produce different values
      final salt2 = crypto.generateSalt();
      expect(salt, isNot(equals(salt2)));
    });

    test('deriveKey produces deterministic 32-byte key for same inputs', () async {
      final salt = Uint8List.fromList(List.generate(16, (i) => i));
      final key1 = await crypto.deriveKey(password: 'SecretPass123', salt: salt);
      final key2 = await crypto.deriveKey(password: 'SecretPass123', salt: salt);

      final bytes1 = await key1.extractBytes();
      final bytes2 = await key2.extractBytes();

      expect(bytes1.length, equals(32));
      expect(bytes1, equals(bytes2));
    });

    test('deriveKey produces different keys for different passwords or salts', () async {
      final salt1 = Uint8List.fromList(List.generate(16, (i) => i));
      final salt2 = Uint8List.fromList(List.generate(16, (i) => i + 1));

      final key1 = await crypto.deriveKey(password: 'Password1', salt: salt1);
      final key2 = await crypto.deriveKey(password: 'Password2', salt: salt1);
      final key3 = await crypto.deriveKey(password: 'Password1', salt: salt2);

      final b1 = await key1.extractBytes();
      final b2 = await key2.extractBytes();
      final b3 = await key3.extractBytes();

      expect(b1, isNot(equals(b2)));
      expect(b1, isNot(equals(b3)));
    });

    test('encrypt and decrypt round trip succeeds', () async {
      final salt = crypto.generateSalt();
      final nonce = crypto.generateNonce();
      final key = await crypto.deriveKey(password: 'CorrectPassword!', salt: salt);

      final plaintext = utf8.encode('Steganography Confidential Message');
      final aad = utf8.encode('HeaderMetadataAAD');

      final enc = await crypto.encrypt(
        plaintext: plaintext,
        key: key,
        nonce: nonce,
        aad: aad,
      );

      expect(enc.ciphertext.length, equals(plaintext.length));
      expect(enc.tag.length, equals(16));

      final decrypted = await crypto.decrypt(
        ciphertext: enc.ciphertext,
        key: key,
        nonce: nonce,
        tag: enc.tag,
        aad: aad,
      );

      expect(utf8.decode(decrypted), equals('Steganography Confidential Message'));
    });

    test('decrypt with wrong password throws AuthenticationException', () async {
      final salt = crypto.generateSalt();
      final nonce = crypto.generateNonce();
      final correctKey = await crypto.deriveKey(password: 'CorrectPass', salt: salt);
      final wrongKey = await crypto.deriveKey(password: 'WrongPass', salt: salt);

      final plaintext = utf8.encode('Sensitive Data');
      final aad = [1, 2, 3];

      final enc = await crypto.encrypt(
        plaintext: plaintext,
        key: correctKey,
        nonce: nonce,
        aad: aad,
      );

      expect(
        () async => await crypto.decrypt(
          ciphertext: enc.ciphertext,
          key: wrongKey,
          nonce: nonce,
          tag: enc.tag,
          aad: aad,
        ),
        throwsA(isA<AuthenticationException>()),
      );
    });

    test('tampered ciphertext throws AuthenticationException', () async {
      final salt = crypto.generateSalt();
      final nonce = crypto.generateNonce();
      final key = await crypto.deriveKey(password: 'Pass', salt: salt);

      final enc = await crypto.encrypt(
        plaintext: [1, 2, 3, 4, 5],
        key: key,
        nonce: nonce,
        aad: [10],
      );

      final tamperedCiphertext = Uint8List.fromList(enc.ciphertext);
      tamperedCiphertext[0] ^= 0x01; // flip one bit

      expect(
        () async => await crypto.decrypt(
          ciphertext: tamperedCiphertext,
          key: key,
          nonce: nonce,
          tag: enc.tag,
          aad: [10],
        ),
        throwsA(isA<AuthenticationException>()),
      );
    });

    test('tampered auth tag throws AuthenticationException', () async {
      final salt = crypto.generateSalt();
      final nonce = crypto.generateNonce();
      final key = await crypto.deriveKey(password: 'Pass', salt: salt);

      final enc = await crypto.encrypt(
        plaintext: [1, 2, 3, 4, 5],
        key: key,
        nonce: nonce,
        aad: [10],
      );

      final tamperedTag = Uint8List.fromList(enc.tag);
      tamperedTag[0] ^= 0xFF;

      expect(
        () async => await crypto.decrypt(
          ciphertext: enc.ciphertext,
          key: key,
          nonce: nonce,
          tag: tamperedTag,
          aad: [10],
        ),
        throwsA(isA<AuthenticationException>()),
      );
    });

    test('altered AAD throws AuthenticationException', () async {
      final salt = crypto.generateSalt();
      final nonce = crypto.generateNonce();
      final key = await crypto.deriveKey(password: 'Pass', salt: salt);

      final enc = await crypto.encrypt(
        plaintext: [1, 2, 3, 4, 5],
        key: key,
        nonce: nonce,
        aad: [1, 2, 3],
      );

      expect(
        () async => await crypto.decrypt(
          ciphertext: enc.ciphertext,
          key: key,
          nonce: nonce,
          tag: enc.tag,
          aad: [1, 2, 4], // altered AAD
        ),
        throwsA(isA<AuthenticationException>()),
      );
    });
  });
}

