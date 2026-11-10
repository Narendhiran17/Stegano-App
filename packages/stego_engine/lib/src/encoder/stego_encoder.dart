import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:image/image.dart' as img;

import '../algorithms/lsb/lsb_bit_stream.dart';
import '../crypto/stego_crypto.dart';
import '../errors/stego_errors.dart';
import '../image/image_carrier.dart';
import '../models/engine_models.dart';
import '../models/payload_type.dart';
import '../payload/container_header.dart';
import '../payload/container_serializer.dart';

/// Provides encoding and capacity calculation operations for StegoEngine.
class StegoEncoder {
  final StegoCrypto _crypto;

  StegoEncoder({StegoCrypto? crypto}) : _crypto = crypto ?? StegoCrypto();

  /// Total framing overhead in bytes for an unencrypted text container.
  static const int unencryptedTextOverhead = 13;

  /// Base framing overhead in bytes for an unencrypted file container (excluding filename and media type).
  static const int unencryptedFileBaseOverhead = 17;

  /// Total framing overhead in bytes for an encrypted text container (41-byte header + 16-byte auth tag).
  static const int encryptedTextOverhead = 57;

  /// Base framing overhead in bytes for an encrypted file container (excluding filename and media type).
  static const int encryptedFileBaseOverhead = 61;

  /// Calculates capacity metrics for carrier dimensions of [width] x [height].
  CapacityInfo calculateCapacity({
    required int width,
    required int height,
    bool isEncrypted = false,
  }) {
    final rawCapacity = LsbBitStream.rawCapacityBytes(width, height);
    final textOverhead = isEncrypted ? encryptedTextOverhead : unencryptedTextOverhead;
    final fileOverhead = isEncrypted ? encryptedFileBaseOverhead : unencryptedFileBaseOverhead;

    final usableText = max(0, rawCapacity - textOverhead);
    final usableFile = max(0, rawCapacity - fileOverhead);

    return CapacityInfo(
      width: width,
      height: height,
      rawCapacityBytes: rawCapacity,
      usableTextCapacityBytes: usableText,
      usableFileCapacityBytes: usableFile,
      isEncrypted: isEncrypted,
    );
  }

  /// Calculates capacity metrics for a decoded [image].
  CapacityInfo calculateCapacityForImage({
    required img.Image image,
    bool isEncrypted = false,
  }) {
    return calculateCapacity(
      width: image.width,
      height: image.height,
      isEncrypted: isEncrypted,
    );
  }

  /// Calculates capacity metrics directly from carrier PNG [carrierBytes].
  CapacityInfo calculateCapacityFromBytes({
    required Uint8List carrierBytes,
    bool isEncrypted = false,
  }) {
    final info = ImageCarrier.inspect(carrierBytes);
    return calculateCapacity(
      width: info.width,
      height: info.height,
      isEncrypted: isEncrypted,
    );
  }

  /// Encodes a payload into a carrier image according to [request].
  ///
  /// Returns lossless PNG bytes containing the embedded payload container.
  /// Throws [CarrierValidationException], [InsufficientCapacityException],
  /// or [InvalidInputException] on failure.
  Future<Uint8List> encode(EncodeRequest request) async {
    // 1. Decode and validate carrier image
    final carrierImage = ImageCarrier.decode(request.carrierBytes);

    // 2. Prepare container bytes
    final Uint8List containerBytes;

    if (request.encrypt) {
      final password = request.password;
      if (password == null || password.isEmpty) {
        throw const InvalidInputException('Password cannot be empty when encryption is enabled.');
      }

      final Uint8List plaintextBytes;
      if (request.payloadType == PayloadType.text) {
        final text = request.text;
        if (text == null || text.isEmpty) {
          throw const InvalidInputException('Text payload cannot be empty.');
        }
        plaintextBytes = Uint8List.fromList(utf8.encode(text));
      } else {
        final fileBytes = request.fileBytes;
        final filename = request.filename;
        if (fileBytes == null || fileBytes.isEmpty) {
          throw const InvalidInputException('File payload cannot be empty.');
        }
        if (filename == null || filename.isEmpty) {
          throw const InvalidInputException('Filename cannot be empty for file payload.');
        }
        plaintextBytes = ContainerSerializer.packFilePayload(
          filename: filename,
          mediaType: request.mediaType ?? 'application/octet-stream',
          fileBytes: fileBytes,
        );
      }

      // Generate fresh salt and nonce
      final salt = _crypto.generateSalt();
      final nonce = _crypto.generateNonce();
      final key = await _crypto.deriveKey(password: password, salt: salt);

      // Construct header for AAD
      final header = ContainerHeader(
        flags: ContainerHeader.flagEncrypted,
        payloadType: request.payloadType,
        salt: salt,
        nonce: nonce,
        payloadLength: plaintextBytes.length,
      );

      final aad = header.buildAad();
      final encrypted = await _crypto.encrypt(
        plaintext: plaintextBytes,
        key: key,
        nonce: nonce,
        aad: aad,
      );

      containerBytes = ContainerSerializer.serializeEncrypted(
        payloadType: request.payloadType,
        salt: salt,
        nonce: nonce,
        ciphertext: encrypted.ciphertext,
        tag: encrypted.tag,
      );
    } else {
      // Unencrypted
      if (request.payloadType == PayloadType.text) {
        final text = request.text;
        if (text == null || text.isEmpty) {
          throw const InvalidInputException('Text payload cannot be empty.');
        }
        containerBytes = ContainerSerializer.serializeUnencryptedText(text);
      } else {
        final fileBytes = request.fileBytes;
        final filename = request.filename;
        if (fileBytes == null || fileBytes.isEmpty) {
          throw const InvalidInputException('File payload cannot be empty.');
        }
        if (filename == null || filename.isEmpty) {
          throw const InvalidInputException('Filename cannot be empty for file payload.');
        }
        containerBytes = ContainerSerializer.serializeUnencryptedFile(
          filename: filename,
          mediaType: request.mediaType ?? 'application/octet-stream',
          fileBytes: fileBytes,
        );
      }
    }

    // 3. Check capacity before modifying image
    final availableBytes = LsbBitStream.rawCapacityBytes(carrierImage.width, carrierImage.height);
    if (containerBytes.length > availableBytes) {
      throw InsufficientCapacityException(
        requiredBytes: containerBytes.length,
        availableBytes: availableBytes,
      );
    }

    // 4. Clone image to avoid in-place mutation of caller buffer
    final outputImage = img.Image.from(carrierImage);

    // 5. Embed payload container bits
    LsbBitStream.embed(
      image: outputImage,
      payloadBytes: containerBytes,
    );

    // 6. Encode into lossless PNG bytes
    return ImageCarrier.encode(outputImage);
  }
}

