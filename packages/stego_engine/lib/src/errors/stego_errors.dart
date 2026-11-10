/// Base exception for all StegoEngine operations.
sealed class StegoException implements Exception {
  final String message;
  const StegoException(this.message);

  @override
  String toString() => '$runtimeType: $message';
}

/// Thrown when the carrier image cannot be parsed, has invalid dimensions,
/// is an unsupported format, or exceeds security limits.
class CarrierValidationException extends StegoException {
  const CarrierValidationException(super.message);
}

/// Thrown when the payload exceeds available carrier capacity.
class InsufficientCapacityException extends StegoException {
  final int requiredBytes;
  final int availableBytes;

  const InsufficientCapacityException({
    required this.requiredBytes,
    required this.availableBytes,
    String? message,
  }) : super(
          message ??
              'Payload requires $requiredBytes bytes but carrier only accommodates $availableBytes bytes.',
        );
}

/// Thrown when the container header or framing is malformed, truncated,
/// or contains unsupported version/flags.
class ContainerParsingException extends StegoException {
  const ContainerParsingException(super.message);
}

/// Thrown when authentication or decryption fails (wrong password, tampered
/// ciphertext, altered header AAD, or corrupted auth tag).
///
/// Intentionally generic to prevent side-channel information leaks.
class AuthenticationException extends StegoException {
  const AuthenticationException([
    super.message = 'Authentication failed. Incorrect password or corrupted payload.',
  ]);
}

/// Thrown when input arguments are invalid (e.g., empty payload, null/empty password
/// when encryption is enabled, or invalid metadata).
class InvalidInputException extends StegoException {
  const InvalidInputException(super.message);
}

/// Thrown when an image, pixel count, or payload exceeds configured safety limits.
class ResourceLimitExceededException extends StegoException {
  const ResourceLimitExceededException(super.message);
}

