# StegoEngine

A robust, offline-first, pure Dart steganography library that provides deterministic carrier validation, capacity calculation, least-significant-bit (LSB) embedding, versioned binary framing, and authenticated encryption (AES-256-GCM + Argon2id).

`stego_engine` serves as the single source of truth for both **Image Preparer** (encoder) and **Message Extractor** (decoder) applications.

---

## Features

- **Format Support:** Lossless PNG image carrier decoding, dimension validation, and encoding.
- **LSB Embedding (V1):** 1-bit substitution across RGB channels (R, G, B order), strictly preserving alpha.
- **Authenticated Encryption:** AES-256-GCM with fresh 12-byte CSPRNG nonces and full container header authenticated as Associated Additional Data (AAD).
- **Password-Based Key Derivation:** Argon2id with fresh 16-byte random salts.
- **Structured Binary Framing:** Versioned container (`STEG`), explicit big-endian layout, safe length validation, and reserved flag enforcement.
- **Typed Outcomes:** Sealed class results (`SupportedPayloadInspection`, `TextExtractionSuccess`, `FileExtractionSuccess`, `ExtractionFailure`) ensuring safe, pattern-matched handling.
- **Safe Error Handling:** Generic authentication failures preventing side-channel leakage; automatic filename sanitization preventing directory traversal.

---

## Getting Started

Add `stego_engine` to your `pubspec.yaml`:

```yaml
dependencies:
  stego_engine:
    path: ../../packages/stego_engine
```

Import the package:

```dart
import 'package:stego_engine/stego_engine.dart';
```

---

## Usage Examples

### 1. Calculate Carrier Capacity

```dart
final encoder = StegoEncoder();

// Check capacity from raw dimensions
final capacity = encoder.calculateCapacity(
  width: 800,
  height: 600,
  isEncrypted: true,
);

print('Raw Capacity: ${capacity.rawCapacityBytes} bytes');
print('Usable Text Capacity: ${capacity.usableTextCapacityBytes} bytes');
print('Usable File Capacity: ${capacity.usableFileCapacityBytes} bytes');
```

### 2. Embed a Text Payload (Image Preparer Flow)

```dart
final encoder = StegoEncoder();

// Embed password-encrypted text
final encodedPngBytes = await encoder.encode(
  EncodeRequest.text(
    carrierBytes: carrierPngBytes,
    text: 'Confidential message to hide',
    password: 'UserStrongPassword123',
  ),
);
```

### 3. Embed an Arbitrary File Payload

```dart
final encodedPngBytes = await encoder.encode(
  EncodeRequest.file(
    carrierBytes: carrierPngBytes,
    fileBytes: documentBytes,
    filename: 'statement.pdf',
    mediaType: 'application/pdf',
    password: 'UserStrongPassword123',
  ),
);
```

### 4. Inspect an Image Carrier (Message Extractor Flow)

```dart
final decoder = StegoDecoder();

final inspection = decoder.inspectPayload(suspectImageBytes);

switch (inspection) {
  case SupportedPayloadInspection(:final payloadType, :final isEncrypted):
    print('Found supported payload! Type: $payloadType, Encrypted: $isEncrypted');
  case NoSupportedPayloadInspection():
    print('No supported steganography signature found.');
  case UnsupportedVersionInspection(:final detectedVersion):
    print('Payload version $detectedVersion is not supported by this app.');
  case CorruptPayloadInspection(:final reason):
    print('Payload header corrupt: $reason');
  case InvalidCarrierInspection(:final reason):
    print('Invalid image: $reason');
}
```

### 5. Extract and Decrypt a Payload

```dart
final result = await decoder.extract(
  carrierBytes: stegoPngBytes,
  password: 'UserStrongPassword123',
);

switch (result) {
  case TextExtractionSuccess(:final text):
    print('Decoded Text: $text');
  case FileExtractionSuccess(:final filename, :final mediaType, :final fileBytes):
    print('Decoded File: $filename ($mediaType, ${fileBytes.length} bytes)');
  case ExtractionFailure(:final exception, :final message):
    print('Extraction failed: $message');
}
```

---

## Security & Detectability Considerations

- **LSB Detectability:** Least Significant Bit embedding introduces statistical anomalies in the distribution of low-order bits. While visually imperceptible, it is detectable by specialized statistical stegananalysis (e.g. Chi-Square, RS analysis). Do not claim universal undetectability.
- **Lossy Compression Fragility:** Converting a stego PNG image to lossy formats (JPEG, lossy WebP, or social media image pipelines) will overwrite pixel bits and destroy the embedded container.
- **No Unauthenticated Plaintext:** The decoder guarantees that unverified or tampered ciphertext is never exposed to the caller.

---

## Documentation

Full architectural and algorithmic documentation is located under `docs/`:
- `docs/algorithms/payload-format.md` — Binary container specification.
- `docs/algorithms/lsb-v1.md` — Traversal and LSB pixel substitution rules.
- `docs/security/cryptography.md` — AES-256-GCM and Argon2id cryptographic parameters.
- `docs/security/threat-model.md` — Threat boundaries and resource limits.

