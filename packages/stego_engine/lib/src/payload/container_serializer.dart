import 'dart:convert';
import 'dart:typed_data';

import '../crypto/stego_crypto.dart';
import '../errors/stego_errors.dart';
import '../models/payload_type.dart';
import '../validation/limits.dart';
import 'container_header.dart';

/// Handles binary framing and serialization of StegoEngine payload containers.
class ContainerSerializer {
  ContainerSerializer._();

  /// Packs a file payload body (filename metadata + media type metadata + raw file bytes).
  static Uint8List packFilePayload({
    required String filename,
    required String mediaType,
    required List<int> fileBytes,
  }) {
    final cleanFilename = StegoLimits.sanitizeFilename(filename);
    final cleanMediaType = StegoLimits.sanitizeMediaType(mediaType);

    final filenameBytes = utf8.encode(cleanFilename);
    final mediaTypeBytes = utf8.encode(cleanMediaType);

    if (filenameBytes.length > StegoLimits.maxFilenameLength) {
      throw const InvalidInputException('Filename exceeds maximum allowed length.');
    }
    if (mediaTypeBytes.length > StegoLimits.maxMediaTypeLength) {
      throw const InvalidInputException('Media type exceeds maximum allowed length.');
    }

    final totalLength = 2 + filenameBytes.length + 2 + mediaTypeBytes.length + fileBytes.length;
    if (totalLength > StegoLimits.maxPayloadSize) {
      throw ResourceLimitExceededException('File payload exceeds maximum payload limit of ${StegoLimits.maxPayloadSize} bytes.');
    }

    final builder = BytesBuilder(copy: true);

    // 1. Filename length (uint16) + Filename
    final fnLenBuf = ByteData(2)..setUint16(0, filenameBytes.length, Endian.big);
    builder.add(fnLenBuf.buffer.asUint8List());
    builder.add(filenameBytes);

    // 2. Media type length (uint16) + Media type
    final mtLenBuf = ByteData(2)..setUint16(0, mediaTypeBytes.length, Endian.big);
    builder.add(mtLenBuf.buffer.asUint8List());
    builder.add(mediaTypeBytes);

    // 3. Raw file bytes
    builder.add(fileBytes);

    return builder.toBytes();
  }

  /// Serializes an unencrypted UTF-8 text payload container.
  static Uint8List serializeUnencryptedText(String text) {
    if (text.isEmpty) {
      throw const InvalidInputException('Payload text cannot be empty.');
    }
    final textBytes = Uint8List.fromList(utf8.encode(text));
    if (textBytes.length > StegoLimits.maxPayloadSize) {
      throw ResourceLimitExceededException('Text payload exceeds maximum size limit of ${StegoLimits.maxPayloadSize} bytes.');
    }

    final header = ContainerHeader(
      flags: 0,
      payloadType: PayloadType.text,
      salt: Uint8List(0),
      nonce: Uint8List(0),
      payloadLength: textBytes.length,
    );

    final builder = BytesBuilder(copy: false);
    builder.add(header.toBytes());
    builder.add(textBytes);
    return builder.toBytes();
  }

  /// Serializes an unencrypted file payload container.
  static Uint8List serializeUnencryptedFile({
    required String filename,
    required String mediaType,
    required List<int> fileBytes,
  }) {
    if (fileBytes.isEmpty) {
      throw const InvalidInputException('File payload cannot be empty.');
    }

    final packedBody = packFilePayload(
      filename: filename,
      mediaType: mediaType,
      fileBytes: fileBytes,
    );

    final header = ContainerHeader(
      flags: 0,
      payloadType: PayloadType.file,
      salt: Uint8List(0),
      nonce: Uint8List(0),
      payloadLength: packedBody.length,
    );

    final builder = BytesBuilder(copy: false);
    builder.add(header.toBytes());
    builder.add(packedBody);
    return builder.toBytes();
  }

  /// Serializes an encrypted container given ciphertext and authentication tag.
  static Uint8List serializeEncrypted({
    required PayloadType payloadType,
    required Uint8List salt,
    required Uint8List nonce,
    required Uint8List ciphertext,
    required Uint8List tag,
  }) {
    if (salt.length != StegoCrypto.saltLength) {
      throw InvalidInputException('Salt must be exactly ${StegoCrypto.saltLength} bytes.');
    }
    if (nonce.length != StegoCrypto.nonceLength) {
      throw InvalidInputException('Nonce must be exactly ${StegoCrypto.nonceLength} bytes.');
    }
    if (tag.length != StegoCrypto.authTagLength) {
      throw InvalidInputException('Authentication tag must be exactly ${StegoCrypto.authTagLength} bytes.');
    }
    if (ciphertext.isEmpty) {
      throw const InvalidInputException('Ciphertext cannot be empty.');
    }

    final header = ContainerHeader(
      flags: ContainerHeader.flagEncrypted,
      payloadType: payloadType,
      salt: salt,
      nonce: nonce,
      payloadLength: ciphertext.length,
    );

    final builder = BytesBuilder(copy: false);
    builder.add(header.toBytes());
    builder.add(ciphertext);
    builder.add(tag);
    return builder.toBytes();
  }
}
