import 'dart:typed_data';
import 'package:image/image.dart' as img;

import '../../errors/stego_errors.dart';

/// Manages bit-level reading and writing of payload bytes into the RGB channels
/// of a 2D image according to the LSB-V1 specification.
class LsbBitStream {
  LsbBitStream._();

  /// Calculates raw bit storage capacity for an image of dimensions [width] x [height].
  static int rawCapacityBits(int width, int height) => width * height * 3;

  /// Calculates raw byte storage capacity for an image of dimensions [width] x [height].
  static int rawCapacityBytes(int width, int height) => (width * height * 3) ~/ 8;

  /// Embeds [payloadBytes] into the RGB channels of [image] using 1-bit LSB substitution.
  ///
  /// Traversal is strictly row-by-row (top-to-bottom), column-by-column (left-to-right),
  /// channel-by-channel (R, then G, then B). Bits are embedded MSB-first.
  /// Alpha channel is left untouched.
  ///
  /// Throws [InsufficientCapacityException] if [payloadBytes] exceeds capacity.
  static void embed({
    required img.Image image,
    required Uint8List payloadBytes,
  }) {
    final availableBytes = rawCapacityBytes(image.width, image.height);
    if (payloadBytes.length > availableBytes) {
      throw InsufficientCapacityException(
        requiredBytes: payloadBytes.length,
        availableBytes: availableBytes,
      );
    }

    final totalBits = payloadBytes.length * 8;
    int bitIndex = 0;

    for (int y = 0; y < image.height; y++) {
      for (int x = 0; x < image.width; x++) {
        if (bitIndex >= totalBits) return;

        final pixel = image.getPixel(x, y);
        num r = pixel.r;
        num g = pixel.g;
        num b = pixel.b;
        final num a = pixel.a;

        // 1. Red channel
        if (bitIndex < totalBits) {
          final bit = _getBit(payloadBytes, bitIndex++);
          r = (r.toInt() & ~1) | bit;
        }

        // 2. Green channel
        if (bitIndex < totalBits) {
          final bit = _getBit(payloadBytes, bitIndex++);
          g = (g.toInt() & ~1) | bit;
        }

        // 3. Blue channel
        if (bitIndex < totalBits) {
          final bit = _getBit(payloadBytes, bitIndex++);
          b = (b.toInt() & ~1) | bit;
        }

        image.setPixelRgba(x, y, r, g, b, a);
      }
    }
  }

  /// Extracts [byteCount] bytes embedded in the RGB channels of [image].
  ///
  /// Traversal and bit ordering mirror [embed] exactly: row-by-row, column-by-column,
  /// R -> G -> B, MSB-first.
  ///
  /// Throws [InsufficientCapacityException] if [byteCount] exceeds total raw image capacity.
  static Uint8List extract({
    required img.Image image,
    required int byteCount,
  }) {
    final availableBytes = rawCapacityBytes(image.width, image.height);
    if (byteCount > availableBytes) {
      throw InsufficientCapacityException(
        requiredBytes: byteCount,
        availableBytes: availableBytes,
      );
    }

    final result = Uint8List(byteCount);
    final totalBits = byteCount * 8;
    int bitIndex = 0;
    int currentByte = 0;
    int bytePos = 0;

    for (int y = 0; y < image.height; y++) {
      for (int x = 0; x < image.width; x++) {
        if (bitIndex >= totalBits) return result;

        final pixel = image.getPixel(x, y);

        // 1. Red channel
        if (bitIndex < totalBits) {
          final bit = pixel.r.toInt() & 1;
          currentByte = (currentByte << 1) | bit;
          bitIndex++;
          if (bitIndex % 8 == 0) {
            result[bytePos++] = currentByte;
            currentByte = 0;
          }
        }

        // 2. Green channel
        if (bitIndex < totalBits) {
          final bit = pixel.g.toInt() & 1;
          currentByte = (currentByte << 1) | bit;
          bitIndex++;
          if (bitIndex % 8 == 0) {
            result[bytePos++] = currentByte;
            currentByte = 0;
          }
        }

        // 3. Blue channel
        if (bitIndex < totalBits) {
          final bit = pixel.b.toInt() & 1;
          currentByte = (currentByte << 1) | bit;
          bitIndex++;
          if (bitIndex % 8 == 0) {
            result[bytePos++] = currentByte;
            currentByte = 0;
          }
        }
      }
    }

    return result;
  }

  /// Extracts the bit at global [bitIndex] from [bytes], MSB-first.
  static int _getBit(Uint8List bytes, int bitIndex) {
    final bytePos = bitIndex >> 3; // bitIndex ~/ 8
    final bitInByte = 7 - (bitIndex & 7); // 7 - (bitIndex % 8)
    return (bytes[bytePos] >> bitInByte) & 1;
  }
}

