import 'dart:typed_data';
import '../errors/stego_errors.dart';
import '../models/payload_type.dart';

/// Represents the header of a StegoEngine container.
class ContainerHeader {
  /// 4-byte magic signature: ASCII 'STEG' (0x53, 0x54, 0x45, 0x47).
  static const List<int> magicBytes = [0x53, 0x54, 0x45, 0x47];

  /// Current format version (1).
  static const int currentVersion = 1;

  /// Flag bitmask for encryption.
  static const int flagEncrypted = 0x01;

  /// Reserved flag bits mask (must be 0 in V1).
  static const int reservedFlagsMask = 0xFE;

  /// Length of initial prefix: magic(4) + ver(1) + flags(1) + type(1) = 7 bytes.
  static const int prefixLength = 7;

  /// Standard length for unencrypted header in bytes.
  static const int unencryptedHeaderLength = 13;

  /// Standard length for encrypted header in bytes (with 16B salt + 12B nonce).
  static const int encryptedHeaderLength = 41;

  /// Minimum header length in bytes (unencrypted: 13 bytes).
  static const int minHeaderLength = 13;

  final int version;
  final int flags;
  final PayloadType payloadType;
  final Uint8List salt;
  final Uint8List nonce;
  final int payloadLength;

  const ContainerHeader({
    this.version = currentVersion,
    required this.flags,
    required this.payloadType,
    required this.salt,
    required this.nonce,
    required this.payloadLength,
  });

  bool get isEncrypted => (flags & flagEncrypted) != 0;

  /// Total byte length of this serialized header.
  int get headerByteLength =>
      4 + // magic
      1 + // version
      1 + // flags
      1 + // payload type
      1 + // salt length
      salt.length +
      1 + // nonce length
      nonce.length +
      4; // payload length

  /// Serializes this header into big-endian bytes.
  Uint8List toBytes() {
    final byteData = ByteData(headerByteLength);
    int offset = 0;

    // 1. Magic (4 bytes)
    for (int i = 0; i < 4; i++) {
      byteData.setUint8(offset++, magicBytes[i]);
    }

    // 2. Version (1 byte)
    byteData.setUint8(offset++, version);

    // 3. Flags (1 byte)
    byteData.setUint8(offset++, flags);

    // 4. Payload type (1 byte)
    byteData.setUint8(offset++, payloadType.id);

    // 5. Salt length (1 byte) + Salt
    byteData.setUint8(offset++, salt.length);
    for (int i = 0; i < salt.length; i++) {
      byteData.setUint8(offset++, salt[i]);
    }

    // 6. Nonce length (1 byte) + Nonce
    byteData.setUint8(offset++, nonce.length);
    for (int i = 0; i < nonce.length; i++) {
      byteData.setUint8(offset++, nonce[i]);
    }

    // 7. Payload length (4 bytes uint32 big-endian)
    byteData.setUint32(offset, payloadLength, Endian.big);

    return byteData.buffer.asUint8List();
  }

  /// Builds the Associated Authenticated Data (AAD) for AES-256-GCM.
  Uint8List buildAad() => toBytes();

  /// Checks if [bytes] starts with the magic 'STEG' signature.
  static bool hasMagic(List<int> bytes) {
    if (bytes.length < 4) return false;
    for (int i = 0; i < 4; i++) {
      if (bytes[i] != magicBytes[i]) return false;
    }
    return true;
  }

  /// Parses the leading 7 bytes of a container header prefix.
  static ({int version, int flags, PayloadType payloadType, bool isEncrypted}) parsePrefix(Uint8List bytes) {
    if (bytes.length < prefixLength) {
      throw const ContainerParsingException('Data too short for container prefix.');
    }

    if (!hasMagic(bytes)) {
      throw const ContainerParsingException('Magic signature mismatch. Not a supported container.');
    }

    final version = bytes[4];
    if (version != currentVersion) {
      throw ContainerParsingException('Unsupported container version: $version (expected $currentVersion).');
    }

    final flags = bytes[5];
    if ((flags & reservedFlagsMask) != 0) {
      throw ContainerParsingException('Container has unknown reserved flags set: 0x${flags.toRadixString(16)}.');
    }

    final typeId = bytes[6];
    final payloadType = PayloadType.fromId(typeId);
    if (payloadType == null) {
      throw ContainerParsingException('Unknown payload type ID: $typeId.');
    }

    final isEncrypted = (flags & flagEncrypted) != 0;
    return (version: version, flags: flags, payloadType: payloadType, isEncrypted: isEncrypted);
  }

  /// Parses a [ContainerHeader] from binary [bytes].
  static ContainerHeader parse(Uint8List bytes) {
    final prefix = parsePrefix(bytes);

    final byteData = ByteData.sublistView(bytes);
    int offset = prefixLength;

    // 5. Salt length & Salt
    if (offset >= bytes.length) {
      throw const ContainerParsingException('Truncated header before reading salt length.');
    }
    final saltLen = byteData.getUint8(offset++);
    if (offset + saltLen > bytes.length) {
      throw const ContainerParsingException('Truncated header while reading salt.');
    }
    final salt = Uint8List.sublistView(bytes, offset, offset + saltLen);
    offset += saltLen;

    // 6. Nonce length & Nonce
    if (offset >= bytes.length) {
      throw const ContainerParsingException('Truncated header before reading nonce length.');
    }
    final nonceLen = byteData.getUint8(offset++);
    if (offset + nonceLen > bytes.length) {
      throw const ContainerParsingException('Truncated header while reading nonce.');
    }
    final nonce = Uint8List.sublistView(bytes, offset, offset + nonceLen);
    offset += nonceLen;

    // 7. Payload length (4 bytes uint32 big-endian)
    if (offset + 4 > bytes.length) {
      throw const ContainerParsingException('Truncated header before reading payload length.');
    }
    final payloadLength = byteData.getUint32(offset, Endian.big);

    if (prefix.isEncrypted) {
      if (saltLen == 0 || nonceLen == 0) {
        throw const ContainerParsingException('Encrypted container missing salt or nonce.');
      }
    } else {
      if (saltLen != 0 || nonceLen != 0) {
        throw const ContainerParsingException('Unencrypted container contains unexpected salt or nonce.');
      }
    }

    return ContainerHeader(
      version: prefix.version,
      flags: prefix.flags,
      payloadType: prefix.payloadType,
      salt: salt,
      nonce: nonce,
      payloadLength: payloadLength,
    );
  }
}
