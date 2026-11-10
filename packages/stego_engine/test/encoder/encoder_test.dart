import 'dart:typed_data';
import 'package:image/image.dart' as img;
import 'package:stego_engine/stego_engine.dart';
import 'package:test/test.dart';

void main() {
  late StegoEncoder encoder;
  late Uint8List testCarrierBytes;

  setUp(() {
    encoder = StegoEncoder();

    // 20x20 image = 400 px * 3 bits = 1200 bits = 150 bytes raw capacity
    final image = img.Image(width: 20, height: 20, numChannels: 4);
    for (int y = 0; y < 20; y++) {
      for (int x = 0; x < 20; x++) {
        image.setPixelRgba(x, y, 100, 150, 200, 255);
      }
    }
    testCarrierBytes = ImageCarrier.encode(image);
  });

  group('StegoEncoder', () {
    test('calculateCapacity accurately reports raw and usable capacities', () {
      final unencryptedCap = encoder.calculateCapacity(width: 20, height: 20, isEncrypted: false);
      expect(unencryptedCap.rawCapacityBytes, equals(150));
      expect(unencryptedCap.usableTextCapacityBytes, equals(150 - 13)); // 137 B
      expect(unencryptedCap.usableFileCapacityBytes, equals(150 - 17)); // 133 B

      final encryptedCap = encoder.calculateCapacity(width: 20, height: 20, isEncrypted: true);
      expect(encryptedCap.rawCapacityBytes, equals(150));
      expect(encryptedCap.usableTextCapacityBytes, equals(150 - 57)); // 93 B
      expect(encryptedCap.usableFileCapacityBytes, equals(150 - 61)); // 89 B
    });

    test('encode unencrypted text produces valid PNG', () async {
      final request = EncodeRequest.text(
        carrierBytes: testCarrierBytes,
        text: 'Secret payload message',
      );

      final encoded = await encoder.encode(request);
      expect(ImageCarrier.isPng(encoded), isTrue);
      final decoded = ImageCarrier.decode(encoded);
      expect(decoded.width, equals(20));
      expect(decoded.height, equals(20));
    });

    test('encode encrypted text produces valid PNG', () async {
      final request = EncodeRequest.text(
        carrierBytes: testCarrierBytes,
        text: 'Confidential encrypted message',
        password: 'TestPassword123!',
      );

      final encoded = await encoder.encode(request);
      expect(ImageCarrier.isPng(encoded), isTrue);
    });

    test('encode unencrypted file produces valid PNG', () async {
      final fileData = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
      final request = EncodeRequest.file(
        carrierBytes: testCarrierBytes,
        fileBytes: fileData,
        filename: 'data.bin',
        mediaType: 'application/octet-stream',
      );

      final encoded = await encoder.encode(request);
      expect(ImageCarrier.isPng(encoded), isTrue);
    });

    test('encode encrypted file produces valid PNG', () async {
      final fileData = Uint8List.fromList([10, 20, 30, 40]);
      final request = EncodeRequest.file(
        carrierBytes: testCarrierBytes,
        fileBytes: fileData,
        filename: 'secret.dat',
        password: 'SafePassword99',
      );

      final encoded = await encoder.encode(request);
      expect(ImageCarrier.isPng(encoded), isTrue);
    });

    test('payload exceeding carrier capacity throws InsufficientCapacityException', () async {
      // 150 bytes capacity, payload of 200 chars text
      final longText = 'A' * 200;
      final request = EncodeRequest.text(
        carrierBytes: testCarrierBytes,
        text: longText,
      );

      expect(
        () async => await encoder.encode(request),
        throwsA(isA<InsufficientCapacityException>()),
      );
    });

    test('empty text payload throws InvalidInputException', () async {
      expect(
        () => EncodeRequest.text(
          carrierBytes: testCarrierBytes,
          text: '',
        ),
        returnsNormally,
      );

      final request = EncodeRequest.text(
        carrierBytes: testCarrierBytes,
        text: '',
      );

      expect(
        () async => await encoder.encode(request),
        throwsA(isA<InvalidInputException>()),
      );
    });

    test('empty password for encrypted payload throws InvalidInputException', () async {
      final request = EncodeRequest.text(
        carrierBytes: testCarrierBytes,
        text: 'Sample',
        password: '',
      );

      // Empty password means encrypt = false in constructor
      expect(request.encrypt, isFalse);
    });
  });
}

