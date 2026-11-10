import 'dart:typed_data';
import 'package:image/image.dart' as img;
import 'package:stego_engine/stego_engine.dart';
import 'package:test/test.dart';

void main() {
  late StegoEncoder encoder;
  late StegoDecoder decoder;

  Uint8List createTestPng(int width, int height) {
    final image = img.Image(width: width, height: height, numChannels: 4);
    for (int y = 0; y < height; y++) {
      for (int x = 0; x < width; x++) {
        image.setPixelRgba(x, y, (x * 17) % 256, (y * 23) % 256, ((x + y) * 31) % 256, 255);
      }
    }
    return ImageCarrier.encode(image);
  }

  setUp(() {
    encoder = StegoEncoder();
    decoder = StegoDecoder();
  });

  group('End-to-End Integration & Round-Trip', () {
    test('round trip: UTF-8 text with special characters and emojis (unencrypted)', () async {
      final carrier = createTestPng(30, 30); // 900 px * 3 bits = 2700 bits = 337 bytes
      const message = 'Steganography Test: 🔒 🔑 — 日本語 — Special Symbols: ©®™±§';

      final encoded = await encoder.encode(EncodeRequest.text(
        carrierBytes: carrier,
        text: message,
      ));

      final inspection = decoder.inspectPayload(encoded);
      expect(inspection, isA<SupportedPayloadInspection>());
      final supported = inspection as SupportedPayloadInspection;
      expect(supported.isEncrypted, isFalse);
      expect(supported.payloadType, equals(PayloadType.text));

      final extraction = await decoder.extract(carrierBytes: encoded);
      expect(extraction, isA<TextExtractionSuccess>());
      final success = extraction as TextExtractionSuccess;
      expect(success.text, equals(message));
      expect(success.isEncrypted, isFalse);
    });

    test('round trip: UTF-8 text (encrypted with Argon2id & AES-256-GCM)', () async {
      final carrier = createTestPng(30, 30);
      const message = 'Confidential Top-Secret Payload';
      const password = 'SuperStrongMasterPassword!99';

      final encoded = await encoder.encode(EncodeRequest.text(
        carrierBytes: carrier,
        text: message,
        password: password,
      ));

      final inspection = decoder.inspectPayload(encoded);
      expect(inspection, isA<SupportedPayloadInspection>());
      final supported = inspection as SupportedPayloadInspection;
      expect(supported.isEncrypted, isTrue);
      expect(supported.payloadType, equals(PayloadType.text));

      // Correct password
      final extraction = await decoder.extract(carrierBytes: encoded, password: password);
      expect(extraction, isA<TextExtractionSuccess>());
      expect((extraction as TextExtractionSuccess).text, equals(message));

      // Incorrect password fails safely
      final failExtraction = await decoder.extract(carrierBytes: encoded, password: 'WrongPassword');
      expect(failExtraction, isA<ExtractionFailure>());
      expect((failExtraction as ExtractionFailure).exception, isA<AuthenticationException>());
    });

    test('round trip: arbitrary binary file bytes (encrypted and unencrypted)', () async {
      final carrier = createTestPng(40, 40); // 1600 px * 3 bits = 4800 bits = 600 bytes
      final binaryData = Uint8List.fromList(List.generate(200, (i) => (i * 13) % 256));
      const filename = 'sample_firmware.bin';
      const mediaType = 'application/octet-stream';
      const password = 'FileEncryptionPassword456';

      // 1. Unencrypted
      final unencPng = await encoder.encode(EncodeRequest.file(
        carrierBytes: carrier,
        fileBytes: binaryData,
        filename: filename,
        mediaType: mediaType,
      ));

      final unencResult = await decoder.extract(carrierBytes: unencPng);
      expect(unencResult, isA<FileExtractionSuccess>());
      final unencSuccess = unencResult as FileExtractionSuccess;
      expect(unencSuccess.filename, equals(filename));
      expect(unencSuccess.mediaType, equals(mediaType));
      expect(unencSuccess.fileBytes, equals(binaryData));
      expect(unencSuccess.isEncrypted, isFalse);

      // 2. Encrypted
      final encPng = await encoder.encode(EncodeRequest.file(
        carrierBytes: carrier,
        fileBytes: binaryData,
        filename: filename,
        mediaType: mediaType,
        password: password,
      ));

      final encResult = await decoder.extract(carrierBytes: encPng, password: password);
      expect(encResult, isA<FileExtractionSuccess>());
      final encSuccess = encResult as FileExtractionSuccess;
      expect(encSuccess.filename, equals(filename));
      expect(encSuccess.mediaType, equals(mediaType));
      expect(encSuccess.fileBytes, equals(binaryData));
      expect(encSuccess.isEncrypted, isTrue);
    });

    test('tampered ciphertext bit triggers safe authentication failure', () async {
      final carrier = createTestPng(30, 30);
      final encoded = await encoder.encode(EncodeRequest.text(
        carrierBytes: carrier,
        text: 'Critical message',
        password: 'Password123',
      ));

      // Flip one bit in carrier pixel within the container region (pixel at index 62, ~byte 23)
      final image = ImageCarrier.decode(encoded);
      final pixel = image.getPixel(2, 2);
      image.setPixelRgba(2, 2, pixel.r.toInt() ^ 1, pixel.g, pixel.b, pixel.a);
      final tamperedCarrier = ImageCarrier.encode(image);

      final result = await decoder.extract(carrierBytes: tamperedCarrier, password: 'Password123');
      expect(result, isA<ExtractionFailure>());
      expect((result as ExtractionFailure).exception, isA<AuthenticationException>());
    });

    test('test vectors: deterministic verification for inter-app consistency', () async {
      // Deterministic test vector:
      // Fixed 10x10 image with uniform color (128, 128, 128, 255)
      // Message: "InterOp-V1"
      final image = img.Image(width: 10, height: 10, numChannels: 4);
      for (int y = 0; y < 10; y++) {
        for (int x = 0; x < 10; x++) {
          image.setPixelRgba(x, y, 128, 128, 128, 255);
        }
      }
      final carrier = ImageCarrier.encode(image);

      final encoded = await encoder.encode(EncodeRequest.text(
        carrierBytes: carrier,
        text: 'InterOp-V1',
      ));

      final inspection = decoder.inspectPayload(encoded);
      expect(inspection, isA<SupportedPayloadInspection>());
      final supported = inspection as SupportedPayloadInspection;
      expect(supported.formatVersion, equals(1));
      expect(supported.payloadType, equals(PayloadType.text));
      expect(supported.declaredPayloadLength, equals(10)); // "InterOp-V1".length = 10

      final extracted = await decoder.extract(carrierBytes: encoded);
      expect(extracted, isA<TextExtractionSuccess>());
      expect((extracted as TextExtractionSuccess).text, equals('InterOp-V1'));
    });
  });
}
