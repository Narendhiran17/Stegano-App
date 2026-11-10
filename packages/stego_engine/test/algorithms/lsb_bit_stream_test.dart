import 'dart:typed_data';
import 'package:image/image.dart' as img;
import 'package:stego_engine/src/algorithms/lsb/lsb_bit_stream.dart';
import 'package:stego_engine/src/errors/stego_errors.dart';
import 'package:test/test.dart';

void main() {
  group('LsbBitStream', () {
    test('capacity calculations are exact and overflow safe', () {
      expect(LsbBitStream.rawCapacityBits(1, 1), equals(3));
      expect(LsbBitStream.rawCapacityBytes(1, 1), equals(0));

      expect(LsbBitStream.rawCapacityBits(2, 2), equals(12));
      expect(LsbBitStream.rawCapacityBytes(2, 2), equals(1)); // 12 ~/ 8 = 1

      expect(LsbBitStream.rawCapacityBits(10, 10), equals(300));
      expect(LsbBitStream.rawCapacityBytes(10, 10), equals(37)); // 300 ~/ 8 = 37

      expect(LsbBitStream.rawCapacityBits(100, 100), equals(30000));
      expect(LsbBitStream.rawCapacityBytes(100, 100), equals(3750));
    });

    test('embed and extract round trip matches payload bytes exactly', () {
      final image = img.Image(width: 20, height: 20);
      // Initialize with test colors
      for (int y = 0; y < 20; y++) {
        for (int x = 0; x < 20; x++) {
          image.setPixelRgba(x, y, 128, 128, 128, 255);
        }
      }

      final payload = Uint8List.fromList(List.generate(50, (i) => (i * 7 + 13) % 256));
      LsbBitStream.embed(image: image, payloadBytes: payload);

      final extracted = LsbBitStream.extract(image: image, byteCount: payload.length);
      expect(extracted, equals(payload));
    });

    test('alpha channel is preserved unmodified during embed', () {
      final image = img.Image(width: 5, height: 5, numChannels: 4);
      for (int y = 0; y < 5; y++) {
        for (int x = 0; x < 5; x++) {
          image.setPixelRgba(x, y, 200, 100, 50, 175);
        }
      }

      final payload = Uint8List.fromList([0xAA, 0x55, 0xFF]);
      LsbBitStream.embed(image: image, payloadBytes: payload);

      for (int y = 0; y < 5; y++) {
        for (int x = 0; x < 5; x++) {
          expect(image.getPixel(x, y).a, equals(175));
        }
      }
    });

    test('exact capacity boundary test', () {
      // 8x8 image = 64 pixels * 3 bits = 192 bits = 24 bytes exact!
      final image = img.Image(width: 8, height: 8);
      final exactCapacity = LsbBitStream.rawCapacityBytes(8, 8);
      expect(exactCapacity, equals(24));

      final payload = Uint8List.fromList(List.generate(24, (i) => i ^ 0xAA));
      LsbBitStream.embed(image: image, payloadBytes: payload);

      final extracted = LsbBitStream.extract(image: image, byteCount: 24);
      expect(extracted, equals(payload));
    });

    test('one byte over capacity throws InsufficientCapacityException', () {
      // 8x8 image = 24 bytes capacity
      final image = img.Image(width: 8, height: 8);
      final oversizedPayload = Uint8List(25);

      expect(
        () => LsbBitStream.embed(image: image, payloadBytes: oversizedPayload),
        throwsA(isA<InsufficientCapacityException>().having(
          (e) => e.requiredBytes,
          'requiredBytes',
          equals(25),
        )),
      );
    });

    test('extracting more bytes than carrier capacity throws InsufficientCapacityException', () {
      final image = img.Image(width: 4, height: 4); // 4*4*3 = 48 bits = 6 bytes
      expect(
        () => LsbBitStream.extract(image: image, byteCount: 7),
        throwsA(isA<InsufficientCapacityException>()),
      );
    });
  });
}
