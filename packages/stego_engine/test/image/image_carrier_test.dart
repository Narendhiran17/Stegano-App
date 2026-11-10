import 'dart:typed_data';
import 'package:image/image.dart' as img;
import 'package:stego_engine/src/errors/stego_errors.dart';
import 'package:stego_engine/src/image/image_carrier.dart';
import 'package:test/test.dart';

void main() {
  group('ImageCarrier', () {
    late Uint8List validPngBytes;

    setUp(() {
      final image = img.Image(width: 10, height: 10, numChannels: 4);
      for (int y = 0; y < 10; y++) {
        for (int x = 0; x < 10; x++) {
          image.setPixelRgba(x, y, 100, 150, 200, 255);
        }
      }
      validPngBytes = ImageCarrier.encode(image);
    });

    test('isPng detects PNG signature correctly', () {
      expect(ImageCarrier.isPng(validPngBytes), isTrue);
      expect(ImageCarrier.isPng([0xFF, 0xD8, 0xFF]), isFalse); // JPEG signature
      expect(ImageCarrier.isPng([]), isFalse);
    });

    test('decode and inspect valid PNG succeeds', () {
      final info = ImageCarrier.inspect(validPngBytes);
      expect(info.width, equals(10));
      expect(info.height, equals(10));
      expect(info.totalPixels, equals(100));
      expect(info.rawCapacityBytes, equals(37)); // (100 * 3) ~/ 8
      expect(info.format, equals('PNG'));
    });

    test('rejects non-PNG formats with CarrierValidationException', () {
      final fakeJpeg = Uint8List.fromList([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46]);
      expect(
        () => ImageCarrier.decode(fakeJpeg),
        throwsA(isA<CarrierValidationException>().having(
          (e) => e.message,
          'message',
          contains('Only lossless PNG images are supported'),
        )),
      );
    });

    test('rejects empty carrier bytes', () {
      expect(
        () => ImageCarrier.decode(Uint8List(0)),
        throwsA(isA<CarrierValidationException>()),
      );
    });

    test('rejects corrupt/truncated PNG bytes', () {
      // Signature correct but truncated
      final truncated = Uint8List.fromList(ImageCarrier.pngSignature);
      expect(
        () => ImageCarrier.decode(truncated),
        throwsA(isA<CarrierValidationException>()),
      );
    });
  });
}

