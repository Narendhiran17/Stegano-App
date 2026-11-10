import 'dart:convert';
import 'dart:typed_data';

import '../crypto/stego_crypto.dart';
import '../errors/stego_errors.dart';
import '../validation/limits.dart';
import 'container_header.dart';

/// Parsed elements of an encrypted container.
class EncryptedContainerParts {
  final ContainerHeader header;
  final Uint8List ciphertext;
  final Uint8List authTag;

  const EncryptedContainerParts({
    required this.header,
    required this.ciphertext,
    required this.authTag,
  });
}

/// Parsed elements of an unencrypted container.
class UnencryptedContainerParts {
  final ContainerHeader header;
  final Uint8List payloadBytes;

  const UnencryptedContainerParts({
    required this.header,
    required this.payloadBytes,
  });
}

/// Parsed file metadata and content.
class ParsedFilePayload {
  final String filename;
  final String mediaType;
  final Uint8List fileBytes;

  const ParsedFilePayload({
    required this.filename,
    required this.mediaType,
    required this.fileBytes,
  });
}

/// Handles validation and parsing of serialized StegoEngine containers.
class ContainerParser {
  ContainerParser._();

  /// Inspects bytes for a valid container header without reading or allocating the full payload.
  ///
  /// Returns `null` if the data does not begin with the supported magic signature.
  /// Throws [ContainerParsingException] if the magic signature matches but the header is invalid.
  static ContainerHeader? inspectHeader(Uint8List bytes) {
    if (bytes.length < 4) return null;

    // Fast check for magic bytes
    for (int i = 0; i < 4; i++) {
      if (bytes[i] != ContainerHeader.magicBytes[i]) {
        return null;
      }
    }

    if (bytes.length < ContainerHeader.minHeaderLength) {
      throw const ContainerParsingException('Container header is truncated.');
    }

    return ContainerHeader.parse(bytes);
  }

  /// Parses unencrypted container data.
  static UnencryptedContainerParts parseUnencrypted(Uint8List bytes) {
    final header = ContainerHeader.parse(bytes);
    if (header.isEncrypted) {
      throw const ContainerParsingException('Container is encrypted; cannot parse as unencrypted.');
    }

    final headerLen = header.headerByteLength;
    final totalExpected = headerLen + header.payloadLength;

    if (header.payloadLength > StegoLimits.maxPayloadSize) {
      throw ResourceLimitExceededException('Declared payload size (${header.payloadLength} B) exceeds maximum limit.');
    }

    if (bytes.length < totalExpected) {
      throw ContainerParsingException(
        'Container payload is truncated. Expected $totalExpected bytes, got ${bytes.length}.',
      );
    }

    final payloadBytes = Uint8List.sublistView(bytes, headerLen, totalExpected);
    return UnencryptedContainerParts(
      header: header,
      payloadBytes: payloadBytes,
    );
  }

  /// Parses encrypted container data into header, ciphertext, and 16-byte authentication tag.
  static EncryptedContainerParts parseEncrypted(Uint8List bytes) {
    final header = ContainerHeader.parse(bytes);
    if (!header.isEncrypted) {
      throw const ContainerParsingException('Container is unencrypted; cannot parse as encrypted.');
    }

    final headerLen = header.headerByteLength;
    final totalExpected = headerLen + header.payloadLength + StegoCrypto.authTagLength;

    if (header.payloadLength > StegoLimits.maxPayloadSize) {
      throw ResourceLimitExceededException('Declared ciphertext size (${header.payloadLength} B) exceeds maximum limit.');
    }

    if (bytes.length < totalExpected) {
      throw ContainerParsingException(
        'Encrypted container is truncated. Expected $totalExpected bytes, got ${bytes.length}.',
      );
    }

    final ciphertext = Uint8List.sublistView(bytes, headerLen, headerLen + header.payloadLength);
    final authTag = Uint8List.sublistView(bytes, headerLen + header.payloadLength, totalExpected);

    return EncryptedContainerParts(
      header: header,
      ciphertext: ciphertext,
      authTag: authTag,
    );
  }

  /// Unpacks a file payload body into its filename, media type, and raw file bytes.
  static ParsedFilePayload unpackFilePayload(Uint8List bytes) {
    if (bytes.length < 4) {
      throw const ContainerParsingException('File payload framing too short.');
    }

    final byteData = ByteData.sublistView(bytes);
    int offset = 0;

    // 1. Filename length (uint16)
    final filenameLen = byteData.getUint16(offset, Endian.big);
    offset += 2;

    if (filenameLen > StegoLimits.maxFilenameLength) {
      throw ContainerParsingException('Declared filename length ($filenameLen) exceeds limit.');
    }
    if (offset + filenameLen > bytes.length) {
      throw const ContainerParsingException('File payload truncated while reading filename.');
    }

    final filenameBytes = Uint8List.sublistView(bytes, offset, offset + filenameLen);
    offset += filenameLen;

    final filename = utf8.decode(filenameBytes, allowMalformed: true);
    final cleanFilename = StegoLimits.sanitizeFilename(filename);

    // 2. Media type length (uint16)
    if (offset + 2 > bytes.length) {
      throw const ContainerParsingException('File payload truncated before reading media type length.');
    }
    final mediaTypeLen = byteData.getUint16(offset, Endian.big);
    offset += 2;

    if (mediaTypeLen > StegoLimits.maxMediaTypeLength) {
      throw ContainerParsingException('Declared media type length ($mediaTypeLen) exceeds limit.');
    }
    if (offset + mediaTypeLen > bytes.length) {
      throw const ContainerParsingException('File payload truncated while reading media type.');
    }

    final mediaTypeBytes = Uint8List.sublistView(bytes, offset, offset + mediaTypeLen);
    offset += mediaTypeLen;

    final mediaType = utf8.decode(mediaTypeBytes, allowMalformed: true);
    final cleanMediaType = StegoLimits.sanitizeMediaType(mediaType);

    // 3. Raw file bytes
    final fileBytes = Uint8List.sublistView(bytes, offset);

    return ParsedFilePayload(
      filename: cleanFilename,
      mediaType: cleanMediaType,
      fileBytes: fileBytes,
    );
  }
}

