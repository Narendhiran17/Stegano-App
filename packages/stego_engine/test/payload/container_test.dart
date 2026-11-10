import 'dart:convert';
import 'dart:typed_data';

import 'package:stego_engine/src/errors/stego_errors.dart';
import 'package:stego_engine/src/models/payload_type.dart';
import 'package:stego_engine/src/payload/container_header.dart';
import 'package:stego_engine/src/payload/container_parser.dart';
import 'package:stego_engine/src/payload/container_serializer.dart';
import 'package:test/test.dart';

void main() {
  group('ContainerHeader', () {
    test('serializes and parses unencrypted header correctly', () {
      final original = ContainerHeader(
        flags: 0,
        payloadType: PayloadType.text,
        salt: Uint8List(0),
        nonce: Uint8List(0),
        payloadLength: 42,
      );

      final bytes = original.toBytes();
      expect(bytes.length, equals(13));

      final parsed = ContainerHeader.parse(bytes);
      expect(parsed.version, equals(1));
      expect(parsed.isEncrypted, isFalse);
      expect(parsed.payloadType, equals(PayloadType.text));
      expect(parsed.salt.length, equals(0));
      expect(parsed.nonce.length, equals(0));
      expect(parsed.payloadLength, equals(42));
    });

    test('serializes and parses encrypted header correctly', () {
      final salt = Uint8List.fromList(List.generate(16, (i) => i));
      final nonce = Uint8List.fromList(List.generate(12, (i) => i * 2));

      final original = ContainerHeader(
        flags: ContainerHeader.flagEncrypted,
        payloadType: PayloadType.file,
        salt: salt,
        nonce: nonce,
        payloadLength: 1024,
      );

      final bytes = original.toBytes();
      expect(bytes.length, equals(41));

      final parsed = ContainerHeader.parse(bytes);
      expect(parsed.isEncrypted, isTrue);
      expect(parsed.payloadType, equals(PayloadType.file));
      expect(parsed.salt, equals(salt));
      expect(parsed.nonce, equals(nonce));
      expect(parsed.payloadLength, equals(1024));
    });

    test('rejects magic signature mismatch', () {
      final valid = ContainerHeader(
        flags: 0,
        payloadType: PayloadType.text,
        salt: Uint8List(0),
        nonce: Uint8List(0),
        payloadLength: 10,
      ).toBytes();

      final invalid = Uint8List.fromList(valid);
      invalid[0] = 0x00; // corrupt magic

      expect(
        () => ContainerHeader.parse(invalid),
        throwsA(isA<ContainerParsingException>()),
      );
    });

    test('rejects unsupported version', () {
      final valid = ContainerHeader(
        flags: 0,
        payloadType: PayloadType.text,
        salt: Uint8List(0),
        nonce: Uint8List(0),
        payloadLength: 10,
      ).toBytes();

      final invalid = Uint8List.fromList(valid);
      invalid[4] = 2; // version 2

      expect(
        () => ContainerHeader.parse(invalid),
        throwsA(isA<ContainerParsingException>().having(
          (e) => e.message,
          'message',
          contains('Unsupported container version'),
        )),
      );
    });

    test('rejects unknown reserved flags', () {
      final valid = ContainerHeader(
        flags: 0,
        payloadType: PayloadType.text,
        salt: Uint8List(0),
        nonce: Uint8List(0),
        payloadLength: 10,
      ).toBytes();

      final invalid = Uint8List.fromList(valid);
      invalid[5] = 0x80; // set reserved bit 7

      expect(
        () => ContainerHeader.parse(invalid),
        throwsA(isA<ContainerParsingException>().having(
          (e) => e.message,
          'message',
          contains('unknown reserved flags'),
        )),
      );
    });
  });

  group('ContainerSerializer and ContainerParser', () {
    test('unencrypted text round trip', () {
      const message = 'Hello, Steganography World! 🔑🔒';
      final container = ContainerSerializer.serializeUnencryptedText(message);

      final parts = ContainerParser.parseUnencrypted(container);
      expect(parts.header.isEncrypted, isFalse);
      expect(parts.header.payloadType, equals(PayloadType.text));

      final extractedText = utf8.decode(parts.payloadBytes);
      expect(extractedText, equals(message));
    });

    test('unencrypted file round trip', () {
      const filename = 'test_document.pdf';
      const mediaType = 'application/pdf';
      final fileData = Uint8List.fromList([0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x35]);

      final container = ContainerSerializer.serializeUnencryptedFile(
        filename: filename,
        mediaType: mediaType,
        fileBytes: fileData,
      );

      final parts = ContainerParser.parseUnencrypted(container);
      expect(parts.header.isEncrypted, isFalse);
      expect(parts.header.payloadType, equals(PayloadType.file));

      final unpacked = ContainerParser.unpackFilePayload(parts.payloadBytes);
      expect(unpacked.filename, equals(filename));
      expect(unpacked.mediaType, equals(mediaType));
      expect(unpacked.fileBytes, equals(fileData));
    });

    test('path traversal in filename is sanitized', () {
      const maliciousName = '../../../../secret/passwords.txt';
      final fileData = Uint8List.fromList([1, 2, 3]);

      final container = ContainerSerializer.serializeUnencryptedFile(
        filename: maliciousName,
        mediaType: 'text/plain',
        fileBytes: fileData,
      );

      final parts = ContainerParser.parseUnencrypted(container);
      final unpacked = ContainerParser.unpackFilePayload(parts.payloadBytes);
      expect(unpacked.filename, equals('passwords.txt'));
      expect(unpacked.filename.contains('/'), isFalse);
      expect(unpacked.filename.contains('..'), isFalse);
    });

    test('encrypted container serialization and parsing', () {
      final salt = Uint8List.fromList(List.generate(16, (i) => i));
      final nonce = Uint8List.fromList(List.generate(12, (i) => i));
      final ciphertext = Uint8List.fromList([10, 20, 30, 40]);
      final tag = Uint8List.fromList(List.generate(16, (i) => 0xFF - i));

      final container = ContainerSerializer.serializeEncrypted(
        payloadType: PayloadType.text,
        salt: salt,
        nonce: nonce,
        ciphertext: ciphertext,
        tag: tag,
      );

      final parts = ContainerParser.parseEncrypted(container);
      expect(parts.header.isEncrypted, isTrue);
      expect(parts.header.payloadType, equals(PayloadType.text));
      expect(parts.header.salt, equals(salt));
      expect(parts.header.nonce, equals(nonce));
      expect(parts.ciphertext, equals(ciphertext));
      expect(parts.authTag, equals(tag));
    });

    test('inspectHeader recognizes magic bytes or returns null', () {
      final validContainer = ContainerSerializer.serializeUnencryptedText('Inspect test');
      final header = ContainerParser.inspectHeader(validContainer);
      expect(header, isNotNull);
      expect(header!.payloadType, equals(PayloadType.text));

      final randomBytes = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
      final noHeader = ContainerParser.inspectHeader(randomBytes);
      expect(noHeader, isNull);
    });

    test('truncated container throws ContainerParsingException', () {
      final validContainer = ContainerSerializer.serializeUnencryptedText('Hello');
      final truncated = Uint8List.sublistView(validContainer, 0, validContainer.length - 2);

      expect(
        () => ContainerParser.parseUnencrypted(truncated),
        throwsA(isA<ContainerParsingException>()),
      );
    });
  });
}
