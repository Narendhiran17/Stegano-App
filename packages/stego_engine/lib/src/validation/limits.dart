import '../errors/stego_errors.dart';

/// Resource limits and constraints enforced across StegoEngine operations.
class StegoLimits {
  StegoLimits._();

  /// Maximum allowed width or height for carrier images (pixels).
  static const int maxImageDimension = 8192;

  /// Maximum allowed total pixel count (width * height).
  static const int maxDecodedPixels = 8192 * 4096; // 33,554,432 pixels (~33.5 MP)

  /// Maximum allowed carrier file size in bytes (128 MB).
  static const int maxCarrierFileSize = 128 * 1024 * 1024;

  /// Maximum allowed payload size in bytes (64 MB).
  static const int maxPayloadSize = 64 * 1024 * 1024;

  /// Maximum allowed length for embedded filenames (bytes).
  static const int maxFilenameLength = 255;

  /// Maximum allowed length for embedded media type (MIME) strings (bytes).
  static const int maxMediaTypeLength = 127;

  /// Validates carrier dimensions against security limits.
  static void validateDimensions(int width, int height) {
    if (width <= 0 || height <= 0) {
      throw const CarrierValidationException(
        'Image dimensions must be positive integers.',
      );
    }
    if (width > maxImageDimension || height > maxImageDimension) {
      throw ResourceLimitExceededException(
        'Image dimensions ($width x $height) exceed the maximum allowed limit of $maxImageDimension x $maxImageDimension.',
      );
    }
    final int pixelCount = width * height;
    if (pixelCount > maxDecodedPixels) {
      throw ResourceLimitExceededException(
        'Total pixel count ($pixelCount) exceeds maximum allowable limit of $maxDecodedPixels.',
      );
    }
  }

  /// Validates carrier file byte size.
  static void validateCarrierSize(int byteLength) {
    if (byteLength == 0) {
      throw const CarrierValidationException('Carrier image data is empty.');
    }
    if (byteLength > maxCarrierFileSize) {
      throw ResourceLimitExceededException(
        'Carrier file size ($byteLength bytes) exceeds maximum allowable limit of $maxCarrierFileSize bytes.',
      );
    }
  }

  /// Sanitizes a filename, preventing directory traversal and removing illegal characters.
  ///
  /// Returns a clean basename, or `unnamed_file` if the resulting name is empty.
  static String sanitizeFilename(String filename) {
    if (filename.isEmpty) return 'unnamed_file';

    // Normalize slashes and remove directory paths
    String clean = filename.replaceAll('\\', '/');
    if (clean.contains('/')) {
      clean = clean.split('/').last;
    }

    // Strip control characters, null bytes, and path traversal tokens
    clean = clean.replaceAll(RegExp(r'[\x00-\x1F\x7F]'), '');
    clean = clean.replaceAll('..', '_');

    // Replace Windows-reserved characters: < > : " / \ | ? *
    clean = clean.replaceAll(RegExp(r'[<>:"/\\|?*]'), '_').trim();

    if (clean.isEmpty || clean == '.' || clean == '..') {
      return 'unnamed_file';
    }

    if (clean.length > maxFilenameLength) {
      clean = clean.substring(0, maxFilenameLength);
    }
    return clean;
  }

  /// Sanitizes and validates a MIME media type string.
  static String sanitizeMediaType(String mediaType) {
    if (mediaType.isEmpty) return 'application/octet-stream';
    String clean = mediaType.trim().toLowerCase();
    clean = clean.replaceAll(RegExp(r'[\x00-\x1F\x7F]'), '');
    if (clean.length > maxMediaTypeLength) {
      clean = clean.substring(0, maxMediaTypeLength);
    }
    return clean.isEmpty ? 'application/octet-stream' : clean;
  }
}

