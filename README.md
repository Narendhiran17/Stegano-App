# StegoSuite — Cryptographic Steganography Monorepo

[![Engine Tests](https://img.shields.io/badge/Dart%20Engine%20Tests-54%20Passing-brightgreen)]()
[![Platform](https://img.shields.io/badge/Platform-Android%20%7C%20Dart-blue)]()
[![Security](https://img.shields.io/badge/Crypto-Argon2id%20%2B%20AES--256--GCM-teal)]()
[![License](https://img.shields.io/badge/License-MIT-lightgrey)]()

A production-grade, offline-first steganography application suite featuring bit-exact 1-LSB RGB image embedding, authenticated encryption, artifact heatmaps, carrier capacity analysis, and an Android client.

---

## Architecture Overview

```
.
├── apps/
│   └── stego_app/                  # Native Android application (StegoSuite)
│       ├── app/src/main/
│       │   ├── assets/index.html   # Zero-dependency, offline-capable UI
│       │   ├── kotlin/             # StegoEngine (LSB + BouncyCastle crypto) & JS Bridge
│       │   └── res/                # Vector adaptive & multi-density launcher icons
│       └── build.gradle.kts        # Android build configuration (compileSdk 36, Java 21)
├── packages/
│   └── stego_engine/               # Core Dart/Flutter Steganography & Crypto Engine
│       ├── lib/                    # Bit streams, framing, validation, Argon2id & AES-GCM
│       ├── bin/server.dart         # Local standalone HTTP engine server
│       └── test/                   # Comprehensive 54-test suite (100% passing)
├── docs/                           # Cryptographic & algorithm specifications
│   ├── algorithms/                 # LSB sequential order and container framing format
│   └── security/                   # Threat model, capacity limits, and Argon2id specs
└── .gitignore                      # Comprehensive build, SDK, and binary exclusion rules
```

---

## Key Features

1. **Deterministic 1-LSB Embedding**:
   - Embeds into the least significant bit of Red, Green, and Blue channels in sequential row-major order: `(0,0) R -> G -> B -> (1,0) R...`
   - Preserves Alpha channel unconditionally (`A = 255`) to prevent rendering artifacts and color corruption.

2. **Authenticated Security (Argon2id + AES-256-GCM)**:
   - High-entropy salt (16 bytes) and nonce/IV (12 bytes) uniquely generated per payload using cryptographically secure random sources (`SecureRandom`).
   - Memory-hard key derivation via **Argon2id** (64 MB memory, 3 iterations, 4 lanes).
   - Authenticated encryption using **AES-256-GCM** with 128-bit authentication tag.
   - Header framing authenticated as Additional Authenticated Data (AAD) to prevent tampering.

3. **StegoSuite Android Application**:
   - 100% offline-capable on device with zero telemetry or network calls.
   - Real-time carrier inspection with exact capacity metrics.
   - Interactive 128×128 pixel alteration heatmap to visualize modified carrier pixels.
   - Interactive split comparison slider (original vs encoded carrier).
   - One-tap gallery export and Android native system share sheet integration.
   - Custom branded adaptive security emblem launcher icon.

---

## Container Framing Protocol (`STEG` V1)

Every payload embedded in an image is packed with the following binary framing:

| Offset (Bytes) | Length | Field | Description |
|:---|:---|:---|:---|
| `0..3` | 4 | Magic | ASCII `'STEG'` (`0x53 0x54 0x45 0x47`) |
| `4` | 1 | Version | Container version (`0x01`) |
| `5` | 1 | Payload Type | `0x01` = Plaintext, `0x02` = Arbitrary File |
| `6` | 1 | Encryption Flag | `0x00` = None, `0x01` = AES-256-GCM + Argon2id |
| `7` | 1 | Reserved | Reserved for future padding (`0x00`) |
| `8..11` | 4 | Payload Length | 32-bit big-endian unsigned integer |
| `12..27` | 16 | Salt | Cryptographic salt (all `0x00` if unencrypted) |
| `28..39` | 12 | Nonce / IV | GCM initialization vector (all `0x00` if unencrypted) |
| `40..55` | 16 | Auth Tag | 128-bit GCM authentication tag |
| `56..N-1` | Var | Filename (Optional) | Present only if Payload Type is File |
| `N..End` | Var | Payload Data | Ciphertext or raw payload |

---

## Verification & Testing

### Running the Dart Engine Test Suite
All 54 unit and integration tests verify framing, bitstream boundary edges, cryptographic derivation, tampering resistance, and end-to-end round trips:

```bash
cd packages/stego_engine
dart test
```

### Building the Android APK
```bash
cd apps/stego_app
./gradlew clean assembleDebug
```
The compiled APK will be generated at `apps/stego_app/app/build/outputs/apk/debug/app-debug.apk`.

---

## Documentation Links

- [LSB Algorithm Specification](docs/algorithms/lsb-v1.md)
- [Binary Payload Layout](docs/algorithms/payload-format.md)
- [Cryptographic Architecture](docs/security/cryptography.md)
- [Threat Model & Limits](docs/security/threat-model.md)

---

## License

MIT License. See [LICENSE](LICENSE) for details.
