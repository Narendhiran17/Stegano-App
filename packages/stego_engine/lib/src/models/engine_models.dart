import 'dart:typed_data';
import 'package:meta/meta.dart';

import '../errors/stego_errors.dart';
import 'payload_type.dart';

/// Metadata regarding a carrier image.
@immutable
class CarrierInfo {
  final int width;
  final int height;
  final int totalPixels;
  final int rawCapacityBytes;
  final bool hasAlpha;
  final String format;

  const CarrierInfo({
    required this.width,
    required this.height,
    required this.totalPixels,
    required this.rawCapacityBytes,
    required this.hasAlpha,
    required this.format,
  });

  @override
  String toString() =>
      'CarrierInfo(${width}x$height, format: $format, rawCapacity: $rawCapacityBytes bytes, alpha: $hasAlpha)';
}

/// Calculated capacity metrics for a given carrier.
@immutable
class CapacityInfo {
  final int width;
  final int height;
  final int rawCapacityBytes;
  final int usableTextCapacityBytes;
  final int usableFileCapacityBytes;
  final bool isEncrypted;

  const CapacityInfo({
    required this.width,
    required this.height,
    required this.rawCapacityBytes,
    required this.usableTextCapacityBytes,
    required this.usableFileCapacityBytes,
    required this.isEncrypted,
  });

  @override
  String toString() =>
      'CapacityInfo(raw: $rawCapacityBytes B, text: $usableTextCapacityBytes B, file: $usableFileCapacityBytes B, encrypted: $isEncrypted)';
}

/// Structured inspection outcome when checking an image for supported payloads.
sealed class InspectionResult {
  const InspectionResult();
}

/// A supported, valid payload signature was found in the carrier.
class SupportedPayloadInspection extends InspectionResult {
  final PayloadType payloadType;
  final bool isEncrypted;
  final bool isScattered;
  final bool isDeniable;
  final int declaredPayloadLength;
  final int formatVersion;
  final int saltLength;
  final int nonceLength;

  const SupportedPayloadInspection({
    required this.payloadType,
    required this.isEncrypted,
    this.isScattered = false,
    this.isDeniable = false,
    required this.declaredPayloadLength,
    required this.formatVersion,
    required this.saltLength,
    required this.nonceLength,
  });

  @override
  String toString() =>
      'SupportedPayloadInspection(version: $formatVersion, type: $payloadType, encrypted: $isEncrypted, len: $declaredPayloadLength)';
}

/// No supported payload magic marker was found.
class NoSupportedPayloadInspection extends InspectionResult {
  final String reason;
  const NoSupportedPayloadInspection([this.reason = 'No supported steganography signature found.']);

  @override
  String toString() => 'NoSupportedPayloadInspection: $reason';
}

/// The magic signature matched, but the format version is unsupported by this engine.
class UnsupportedVersionInspection extends InspectionResult {
  final int detectedVersion;
  final String reason;

  const UnsupportedVersionInspection({
    required this.detectedVersion,
    this.reason = 'Format version is not supported by this engine build.',
  });

  @override
  String toString() => 'UnsupportedVersionInspection(detected: $detectedVersion): $reason';
}

/// A payload signature was recognized, but the framing, length, or flags are corrupted.
class CorruptPayloadInspection extends InspectionResult {
  final String reason;
  const CorruptPayloadInspection(this.reason);

  @override
  String toString() => 'CorruptPayloadInspection: $reason';
}

/// The carrier image itself could not be decoded or violates format boundaries.
class InvalidCarrierInspection extends InspectionResult {
  final String reason;
  const InvalidCarrierInspection(this.reason);

  @override
  String toString() => 'InvalidCarrierInspection: $reason';
}

/// Result returned from payload extraction operations.
sealed class ExtractionResult {
  const ExtractionResult();
}

/// Successfully extracted a UTF-8 text payload.
class TextExtractionSuccess extends ExtractionResult {
  final String text;
  final bool isEncrypted;

  const TextExtractionSuccess({
    required this.text,
    required this.isEncrypted,
  });

  @override
  String toString() => 'TextExtractionSuccess(len: ${text.length}, encrypted: $isEncrypted)';
}

/// Successfully extracted a file payload.
class FileExtractionSuccess extends ExtractionResult {
  final String filename;
  final String mediaType;
  final Uint8List fileBytes;
  final bool isEncrypted;

  const FileExtractionSuccess({
    required this.filename,
    required this.mediaType,
    required this.fileBytes,
    required this.isEncrypted,
  });

  @override
  String toString() =>
      'FileExtractionSuccess(file: "$filename", type: "$mediaType", bytes: ${fileBytes.length}, encrypted: $isEncrypted)';
}

/// Extraction failed due to authentication failure, corruption, or unsupported format.
class ExtractionFailure extends ExtractionResult {
  final StegoException exception;
  final String message;

  ExtractionFailure(this.exception) : message = exception.message;

  @override
  String toString() => 'ExtractionFailure($exception)';
}

/// Request parameters for encoding a payload into a carrier image.
class EncodeRequest {
  final Uint8List carrierBytes;
  final PayloadType payloadType;
  final String? text;
  final Uint8List? fileBytes;
  final String? filename;
  final String? mediaType;
  final String? password;
  final bool encrypt;

  EncodeRequest.text({
    required this.carrierBytes,
    required this.text,
    this.password,
  })  : payloadType = PayloadType.text,
        fileBytes = null,
        filename = null,
        mediaType = null,
        encrypt = password != null && password.isNotEmpty;

  EncodeRequest.file({
    required this.carrierBytes,
    required this.fileBytes,
    required this.filename,
    String? mediaType,
    this.password,
  })  : payloadType = PayloadType.file,
        text = null,
        mediaType = mediaType ?? 'application/octet-stream',
        encrypt = password != null && password.isNotEmpty;
}
