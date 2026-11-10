/// Shared Steganography Engine library.
///
/// Provides carrier image validation, capacity calculation, LSB embedding,
/// binary container framing, authenticated AES-256-GCM encryption, Argon2id
/// key derivation, and extraction for Flutter and Dart applications.
library stego_engine;

// Public models
export 'src/models/engine_models.dart';
export 'src/models/payload_type.dart';

// Public error types
export 'src/errors/stego_errors.dart';

// Public validation and resource bounds
export 'src/validation/limits.dart';

// High-level operations
export 'src/encoder/stego_encoder.dart';
export 'src/decoder/stego_decoder.dart';

// Cryptographic primitives
export 'src/crypto/stego_crypto.dart';

// Low-level carrier operations
export 'src/image/image_carrier.dart';
export 'src/algorithms/lsb/lsb_bit_stream.dart';

