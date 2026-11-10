import 'dart:convert';
import 'dart:typed_data';
import 'package:image/image.dart' as img;

import '../algorithms/lsb/lsb_bit_stream.dart';
import '../crypto/stego_crypto.dart';
import '../errors/stego_errors.dart';
import '../image/image_carrier.dart';
import '../models/engine_models.dart';
import '../models/payload_type.dart';
import '../payload/container_header.dart';
import '../payload/container_parser.dart';
import '../validation/limits.dart';

/// Provides payload inspection, validation, and extraction operations for StegoEngine.
class StegoDecoder {
  final StegoCrypto _crypto;

  StegoDecoder({StegoCrypto? crypto}) : _crypto = crypto ?? StegoCrypto();

  /// Inspects basic carrier image properties without reading embedded bits.
  CarrierInfo inspectCarrier(Uint8List carrierBytes) {
    return ImageCarrier.inspect(carrierBytes);
  }

  /// Inspects an image carrier for a supported steganographic payload.
  ///
  /// Safely extracts and checks header signatures without allocating memory for
  /// large payload bodies.
  InspectionResult inspectPayload(Uint8List carrierBytes) {
    final img.Image image;
    try {
      image = ImageCarrier.decode(carrierBytes);
    } on StegoException catch (e) {
      return InvalidCarrierInspection(e.message);
    } catch (e) {
      return InvalidCarrierInspection('Failed to decode carrier image: $e');
    }

    final capacity = LsbBitStream.rawCapacityBytes(image.width, image.height);
    if (capacity < ContainerHeader.prefixLength) {
      return const NoSupportedPayloadInspection('Image capacity too small for container header.');
    }

    // 1. Read first 7 bytes to inspect magic, version, flags, and type
    final prefixBytes = LsbBitStream.extract(image: image, byteCount: ContainerHeader.prefixLength);
    if (!ContainerHeader.hasMagic(prefixBytes)) {
      return const NoSupportedPayloadInspection();
    }

    final ({int version, int flags, PayloadType payloadType, bool isEncrypted, bool isScattered, bool isDeniable}) prefix;
    try {
      prefix = ContainerHeader.parsePrefix(prefixBytes);
    } on ContainerParsingException catch (e) {
      if (e.message.contains('Unsupported container version')) {
        return UnsupportedVersionInspection(
          detectedVersion: prefixBytes[4],
          reason: e.message,
        );
      }
      return CorruptPayloadInspection(e.message);
    }

    final headerLength = prefix.isEncrypted
        ? ContainerHeader.encryptedHeaderLength
        : ContainerHeader.unencryptedHeaderLength;

    if (capacity < headerLength) {
      return CorruptPayloadInspection(
        'Carrier capacity ($capacity B) too small for full container header ($headerLength B).',
      );
    }

    final fullHeaderBytes = LsbBitStream.extract(image: image, byteCount: headerLength);
    final ContainerHeader fullHeader;
    try {
      fullHeader = ContainerHeader.parse(fullHeaderBytes);
    } catch (e) {
      return CorruptPayloadInspection('Failed to parse container header: $e');
    }

    final totalRequired = fullHeader.headerByteLength +
        fullHeader.payloadLength +
        (fullHeader.isEncrypted ? StegoCrypto.authTagLength : 0);

    if (totalRequired > capacity || fullHeader.payloadLength > StegoLimits.maxPayloadSize) {
      return CorruptPayloadInspection(
        'Declared payload length (${fullHeader.payloadLength} B) exceeds carrier capacity ($capacity B).',
      );
    }

    return SupportedPayloadInspection(
      payloadType: fullHeader.payloadType,
      isEncrypted: fullHeader.isEncrypted,
      isScattered: fullHeader.isScattered,
      isDeniable: fullHeader.isDeniable,
      declaredPayloadLength: fullHeader.payloadLength,
      formatVersion: fullHeader.version,
      saltLength: fullHeader.salt.length,
      nonceLength: fullHeader.nonce.length,
    );
  }

  /// Extracts and decodes a payload from [carrierBytes].
  ///
  /// If the payload is encrypted, [password] must be provided.
  /// Never returns unauthenticated or partially decrypted plaintext.
  Future<ExtractionResult> extract({
    required Uint8List carrierBytes,
    String? password,
  }) async {
    final img.Image image;
    try {
      image = ImageCarrier.decode(carrierBytes);
    } on StegoException catch (e) {
      return ExtractionFailure(e);
    } catch (e) {
      return ExtractionFailure(CarrierValidationException('Failed to decode carrier image: $e'));
    }

    final capacity = LsbBitStream.rawCapacityBytes(image.width, image.height);
    if (capacity < ContainerHeader.prefixLength) {
      return ExtractionFailure(
        const ContainerParsingException('Carrier capacity too small for container header.'),
      );
    }

    // 1. Read header prefix
    final prefixBytes = LsbBitStream.extract(image: image, byteCount: ContainerHeader.prefixLength);
    if (!ContainerHeader.hasMagic(prefixBytes)) {
      return ExtractionFailure(
        const ContainerParsingException('No supported payload signature found.'),
      );
    }

    final ({int version, int flags, PayloadType payloadType, bool isEncrypted, bool isScattered, bool isDeniable}) prefix;
    try {
      prefix = ContainerHeader.parsePrefix(prefixBytes);
    } on ContainerParsingException catch (e) {
      return ExtractionFailure(e);
    }

    // 2. Determine header size based on encryption flag
    final headerLength = prefix.isEncrypted
        ? ContainerHeader.encryptedHeaderLength
        : ContainerHeader.unencryptedHeaderLength;

    if (capacity < headerLength) {
      return ExtractionFailure(
        ContainerParsingException(
          'Carrier capacity ($capacity B) too small for full container header ($headerLength B).',
        ),
      );
    }

    final fullHeaderBytes = LsbBitStream.extract(image: image, byteCount: headerLength);
    final ContainerHeader fullHeader;
    try {
      fullHeader = ContainerHeader.parse(fullHeaderBytes);
    } on ContainerParsingException catch (e) {
      return ExtractionFailure(e);
    }

    // 3. Extract and decode based on encryption flag
    if (fullHeader.isEncrypted) {
      if (password == null || password.isEmpty) {
        return ExtractionFailure(
          const InvalidInputException('Password is required to decrypt this protected payload.'),
        );
      }

      final totalContainerLength = fullHeader.headerByteLength +
          fullHeader.payloadLength +
          StegoCrypto.authTagLength;

      if (totalContainerLength > capacity) {
        return ExtractionFailure(
          ContainerParsingException(
            'Declared encrypted container ($totalContainerLength B) exceeds carrier capacity ($capacity B).',
          ),
        );
      }

      // Read entire container (header + ciphertext + tag)
      final allBytes = LsbBitStream.extract(image: image, byteCount: totalContainerLength);
      final EncryptedContainerParts parts;
      try {
        parts = ContainerParser.parseEncrypted(allBytes);
      } on ContainerParsingException catch (e) {
        return ExtractionFailure(e);
      }

      // Derive key and decrypt with AAD verification
      try {
        final key = await _crypto.deriveKey(
          password: password,
          salt: parts.header.salt,
        );

        final aad = parts.header.buildAad();
        final clearBytes = await _crypto.decrypt(
          ciphertext: parts.ciphertext,
          key: key,
          nonce: parts.header.nonce,
          tag: parts.authTag,
          aad: aad,
        );

        if (parts.header.payloadType == PayloadType.text) {
          final text = utf8.decode(clearBytes, allowMalformed: false);
          return TextExtractionSuccess(text: text, isEncrypted: true);
        } else {
          final filePayload = ContainerParser.unpackFilePayload(clearBytes);
          return FileExtractionSuccess(
            filename: filePayload.filename,
            mediaType: filePayload.mediaType,
            fileBytes: filePayload.fileBytes,
            isEncrypted: true,
          );
        }
      } on StegoException catch (e) {
        return ExtractionFailure(e);
      } catch (e) {
        return ExtractionFailure(AuthenticationException('Decryption failed: $e'));
      }
    } else {
      // Unencrypted
      final totalContainerLength = fullHeader.headerByteLength + fullHeader.payloadLength;
      if (totalContainerLength > capacity) {
        return ExtractionFailure(
          ContainerParsingException(
            'Declared container ($totalContainerLength B) exceeds carrier capacity ($capacity B).',
          ),
        );
      }

      final allBytes = LsbBitStream.extract(image: image, byteCount: totalContainerLength);
      final UnencryptedContainerParts parts;
      try {
        parts = ContainerParser.parseUnencrypted(allBytes);
      } on ContainerParsingException catch (e) {
        return ExtractionFailure(e);
      }

      if (parts.header.payloadType == PayloadType.text) {
        try {
          final text = utf8.decode(parts.payloadBytes, allowMalformed: false);
          return TextExtractionSuccess(text: text, isEncrypted: false);
        } catch (e) {
          return ExtractionFailure(ContainerParsingException('Malformed UTF-8 text payload: $e'));
        }
      } else {
        try {
          final filePayload = ContainerParser.unpackFilePayload(parts.payloadBytes);
          return FileExtractionSuccess(
            filename: filePayload.filename,
            mediaType: filePayload.mediaType,
            fileBytes: filePayload.fileBytes,
            isEncrypted: false,
          );
        } on ContainerParsingException catch (e) {
          return ExtractionFailure(e);
        }
      }
    }
  }
}
