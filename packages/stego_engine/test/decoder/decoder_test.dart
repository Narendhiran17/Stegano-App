import 'dart:convert';
import 'dart:typed_data';
import 'package:image/image.dart' as img;
import 'package:stego_engine/stego_engine.dart';
import 'package:test/test.dart';

void main() {
  late StegoEncoder encoder;
  late StegoDecoder decoder;
  late Uint8List cleanCarrierBytes;

  setUp(() {
    encoder = StegoEncoder();
    decoder = StegoDecoder();

    // 25x25 image = 625 px * 3 bits = 1875 bits = 234 bytes raw capacity
    final image = img.Image(width: 25, height: 25, numChannels: 4);
    for (int y = 0; y < 25; y++) {
      for (int x = 0; x < 25; x++) {
        image.setPixelRgba(x, y, 50, 100, 150, 255);
      }
    }
    cleanCarrierBytes = ImageCarrier.encode(image);
  });

  group('StegoDecoder', () {
    test('inspectCarrier returns accurate carrier dimensions and capacity', () {
      final info = decoder.inspectCarrier(cleanCarrierBytes);
      expect(info.width, equals(25));
      expect(info.height, equals(25));
      expect(info.totalPixels, equals(625));
      expect(info.rawCapacityBytes, equals(234));
      expect(info.format, equals('PNG'));
    });

    test('inspectPayload on clean carrier returns NoSupportedPayloadInspection', () {
      final result = decoder.inspectPayload(cleanCarrierBytes);
      expect(result, isA<NoSupportedPayloadInspection>());
    });

    test('inspectPayload detects unencrypted text container', () async {
      final encodedBytes = await encoder.encode(EncodeRequest.text(
        carrierBytes: cleanCarrierBytes,
        text: 'Visible secret text',
      ));

      final result = decoder.inspectPayload(encodedBytes);
      expect(result, isA<SupportedPayloadInspection>());
      final supported = result as SupportedPayloadInspection;
      expect(supported.payloadType, equals(PayloadType.text));
      expect(supported.isEncrypted, isFalse);
      expect(supported.declaredPayloadLength, equals(utf8.encode('Visible secret text').length));
    });

    test('inspectPayload detects encrypted file container', () async {
      final fileData = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
      final encodedBytes = await encoder.encode(EncodeRequest.file(
        carrierBytes: cleanCarrierBytes,
        fileBytes: fileData,
        filename: 'report.pdf',
        mediaType: 'application/pdf',
        password: 'TopSecretPassword',
      ));

      final result = decoder.inspectPayload(encodedBytes);
      expect(result, isA<SupportedPayloadInspection>());
      final supported = result as SupportedPayloadInspection;
      expect(supported.payloadType, equals(PayloadType.file));
      expect(supported.isEncrypted, isTrue);
      expect(supported.saltLength, equals(16));
      expect(supported.nonceLength, equals(12));
    });

    test('extract unencrypted text succeeds', () async {
      const message = 'Hello, Unencrypted Steganography!';
      final encodedBytes = await encoder.encode(EncodeRequest.text(
        carrierBytes: cleanCarrierBytes,
        text: message,
      ));

      final result = await decoder.extract(carrierBytes: encodedBytes);
      expect(result, isA<TextExtractionSuccess>());
      final success = result as TextExtractionSuccess;
      expect(success.text, equals(message));
      expect(success.isEncrypted, isFalse);
    });

    test('extract encrypted text with correct password succeeds', () async {
      const message = 'Encrypted payload text 🚀';
      const password = 'StrongPassword#2026';
      final encodedBytes = await encoder.encode(EncodeRequest.text(
        carrierBytes: cleanCarrierBytes,
        text: message,
        password: password,
      ));

      final result = await decoder.extract(carrierBytes: encodedBytes, password: password);
      expect(result, isA<TextExtractionSuccess>());
      final success = result as TextExtractionSuccess;
      expect(success.text, equals(message));
      expect(success.isEncrypted, isTrue);
    });

    test('extract encrypted text with wrong password returns ExtractionFailure(AuthenticationException)', () async {
      final encodedBytes = await encoder.encode(EncodeRequest.text(
        carrierBytes: cleanCarrierBytes,
        text: 'Secret Data',
        password: 'CorrectPassword',
      ));

      final result = await decoder.extract(carrierBytes: encodedBytes, password: 'WrongPassword');
      expect(result, isA<ExtractionFailure>());
      final failure = result as ExtractionFailure;
      expect(failure.exception, isA<AuthenticationException>());
    });

    test('extract encrypted text with no password returns ExtractionFailure(InvalidInputException)', () async {
      final encodedBytes = await encoder.encode(EncodeRequest.text(
        carrierBytes: cleanCarrierBytes,
        text: 'Secret Data',
        password: 'CorrectPassword',
      ));

      final result = await decoder.extract(carrierBytes: encodedBytes);
      expect(result, isA<ExtractionFailure>());
      final failure = result as ExtractionFailure;
      expect(failure.exception, isA<InvalidInputException>());
    });

    test('extract unencrypted file succeeds', () async {
      final fileData = Uint8List.fromList([0xCA, 0xFE, 0xBA, 0xBE, 1, 2, 3]);
      final encodedBytes = await encoder.encode(EncodeRequest.file(
        carrierBytes: cleanCarrierBytes,
        fileBytes: fileData,
        filename: 'test.bin',
        mediaType: 'application/octet-stream',
      ));

      final result = await decoder.extract(carrierBytes: encodedBytes);
      expect(result, isA<FileExtractionSuccess>());
      final success = result as FileExtractionSuccess;
      expect(success.filename, equals('test.bin'));
      expect(success.mediaType, equals('application/octet-stream'));
      expect(success.fileBytes, equals(fileData));
      expect(success.isEncrypted, isFalse);
    });

    test('extract encrypted file succeeds', () async {
      final fileData = Uint8List.fromList([10, 20, 30, 40, 50]);
      final encodedBytes = await encoder.encode(EncodeRequest.file(
        carrierBytes: cleanCarrierBytes,
        fileBytes: fileData,
        filename: 'safe.dat',
        mediaType: 'application/binary',
        password: 'VaultPassword987',
      ));

      final result = await decoder.extract(carrierBytes: encodedBytes, password: 'VaultPassword987');
      expect(result, isA<FileExtractionSuccess>());
      final success = result as FileExtractionSuccess;
      expect(success.filename, equals('safe.dat'));
      expect(success.mediaType, equals('application/binary'));
      expect(success.fileBytes, equals(fileData));
      expect(success.isEncrypted, isTrue);
    });

    test('extract from tampered encrypted image returns ExtractionFailure(AuthenticationException)', () async {
      final encodedBytes = await encoder.encode(EncodeRequest.text(
        carrierBytes: cleanCarrierBytes,
        text: 'Tamper proof message',
        password: 'SecureKey123',
      ));

      // Decode the PNG, flip one pixel bit in the ciphertext region, re-encode
      final image = ImageCarrier.decode(encodedBytes);
      final pixel = image.getPixel(5, 5);
      image.setPixelRgba(5, 5, pixel.r.toInt() ^ 1, pixel.g, pixel.b, pixel.a);
      final tamperedBytes = ImageCarrier.encode(image);

      final result = await decoder.extract(carrierBytes: tamperedBytes, password: 'SecureKey123');
      expect(result, isA<ExtractionFailure>());
      final failure = result as ExtractionFailure;
      expect(failure.exception, isA<AuthenticationException>());
    });
  });
}

