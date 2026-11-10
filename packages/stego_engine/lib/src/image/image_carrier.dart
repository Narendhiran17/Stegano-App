import 'dart:typed_data';
import 'package:image/image.dart' as img;

import '../algorithms/lsb/lsb_bit_stream.dart';
import '../errors/stego_errors.dart';
import '../models/engine_models.dart';
import '../validation/limits.dart';

/// Handles PNG image validation, decoding, inspection, and encoding.
class ImageCarrier {
  ImageCarrier._();

  /// Standard 8-byte PNG file signature.
  static const List<int> pngSignature = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

  /// Checks if the provided [bytes] begin with the standard PNG file signature.
  static bool isPng(List<int> bytes) {
    if (bytes.length < 8) return false;
    for (int i = 0; i < 8; i++) {
      if (bytes[i] != pngSignature[i]) return false;
    }
    return true;
  }

  /// Decodes and validates a PNG carrier image from raw [bytes].
  ///
  /// Throws [CarrierValidationException] or [ResourceLimitExceededException] if
  /// the format is not PNG, decoding fails, or dimensions exceed limits.
  static img.Image decode(Uint8List bytes) {
    StegoLimits.validateCarrierSize(bytes.length);

    if (!isPng(bytes)) {
      throw const CarrierValidationException(
        'Unsupported image format. Only lossless PNG images are supported as carriers.',
      );
    }

    img.Image? image;
    try {
      image = img.decodePng(bytes);
    } catch (e) {
      throw CarrierValidationException('Malformed PNG data could not be decoded: $e');
    }

    if (image == null) {
      throw const CarrierValidationException('Malformed PNG data could not be decoded.');
    }

    StegoLimits.validateDimensions(image.width, image.height);
    return image;
  }

  /// Re-encodes an [image] into lossless PNG bytes.
  static Uint8List encode(img.Image image) {
    final encoded = img.encodePng(image);
    return Uint8List.fromList(encoded);
  }

  /// Inspects a PNG carrier without altering it, returning structured [CarrierInfo].
  static CarrierInfo inspect(Uint8List bytes) {
    final image = decode(bytes);
    final rawCapacity = LsbBitStream.rawCapacityBytes(image.width, image.height);

    return CarrierInfo(
      width: image.width,
      height: image.height,
      totalPixels: image.width * image.height,
      rawCapacityBytes: rawCapacity,
      hasAlpha: image.hasAlpha,
      format: 'PNG',
    );
  }
}
