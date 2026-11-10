# StegoEngine V1 Payload Container Format Specification

## 1. Overview

The **StegoEngine V1** payload container format is a versioned, deterministic binary container designed for steganographic embedding within lossless carrier images (specifically PNG). The format supports UTF-8 plain text and arbitrary binary files with safe metadata. When password protection is enabled, the container provides authenticated encryption via AES-256-GCM with Argon2id password-based key derivation.

All multi-byte integer fields are encoded in **network byte order (big-endian)**.

---

## 2. Binary Layout

The container is divided into a **Container Header**, optional **Cryptographic Metadata**, a **Payload Body** (either ciphertext or plaintext), and an optional **Authentication Tag**.

```
+-------------------+-----------------+----------------+--------------------+
| Magic (4 bytes)   | Version (1 byte)| Flags (1 byte) | PayloadType (1 B)  |
+-------------------+-----------------+----------------+--------------------+
| Salt Len (1 byte) | Salt (S bytes)  | Nonce Len (1 B)| Nonce (N bytes)    |
+-------------------+-----------------+----------------+--------------------+
| Payload Length (4 bytes, Big-Endian uint32)                               |
+---------------------------------------------------------------------------+
| Payload Body (L bytes): Plaintext OR Ciphertext                           |
+---------------------------------------------------------------------------+
| [Optional] AES-GCM Authentication Tag (16 bytes, if encrypted)            |
+---------------------------------------------------------------------------+
```

### 2.1 Field Definitions

| Field | Type / Width | Description |
|---|---|---|
| `magic` | 4 bytes ASCII | Magic signature: `0x53, 0x54, 0x45, 0x47` (`"STEG"`). Identifies the file as a supported steganography container. |
| `version` | 1 byte `uint8` | Container format version. Currently `0x01` (Version 1). |
| `flags` | 1 byte `uint8` | Bitfield for container options: <br>• Bit 0 (`0x01`): `IS_ENCRYPTED` (0 = unencrypted, 1 = encrypted).<br>• Bits 1-7: Reserved (must be `0`). Any non-zero reserved bits cause immediate rejection. |
| `payload_type` | 1 byte `uint8` | Payload content type: <br>• `0x01`: UTF-8 Text (`PayloadType.text`)<br>• `0x02`: Binary File (`PayloadType.file`)<br>• Other values: Rejected as unsupported. |
| `salt_length` | 1 byte `uint8` | Length of the cryptographic salt in bytes. <br>• Unencrypted: `0`<br>• Encrypted: `16` (128-bit salt). |
| `salt` | `salt_length` bytes | Cryptographically secure random salt used with Argon2id. Present only if `salt_length > 0`. |
| `nonce_length` | 1 byte `uint8` | Length of the initialization vector / nonce in bytes. <br>• Unencrypted: `0`<br>• Encrypted: `12` (96-bit AES-GCM standard nonce). |
| `nonce` | `nonce_length` bytes | Cryptographically secure random nonce used with AES-256-GCM. Present only if `nonce_length > 0`. |
| `payload_length` | 4 bytes `uint32` | Big-endian length of the following payload data (`L` bytes). For unencrypted containers, this is the plaintext length. For encrypted containers, this is the ciphertext length (excluding the 16-byte auth tag). Must not exceed image carrier capacity or engine resource limits (default max 64 MB). |
| `payload_data` | `payload_length` bytes | The payload content: <br>• Unencrypted: raw plaintext body (see §2.2).<br>• Encrypted: AES-256-GCM ciphertext. |
| `auth_tag` | 16 bytes | AES-256-GCM 128-bit authentication tag. Present **only** when `IS_ENCRYPTED` flag is set. |

---

## 2.2 Payload Body Formatting

### Case A: Text Payload (`payload_type = 0x01`)

- **Unencrypted:** `payload_data` consists of raw UTF-8 encoded bytes of the text message.
- **Encrypted:** The plaintext input to AES-256-GCM is the raw UTF-8 bytes. The ciphertext is stored in `payload_data`.

### Case B: File Payload (`payload_type = 0x02`)

For binary files, structured metadata precedes the raw file bytes:

```
+------------------------------------+--------------------------------------+
| Filename Length (2 bytes, uint16)  | Filename (F bytes, UTF-8)            |
+------------------------------------+--------------------------------------+
| Media Type Length (2 bytes, uint16)| Media Type (M bytes, UTF-8 ASCII)    |
+------------------------------------+--------------------------------------+
| File Data (Remaining bytes)                                               |
+---------------------------------------------------------------------------+
```

| Field | Type / Width | Description |
|---|---|---|
| `filename_len` | 2 bytes `uint16` | Big-endian length of the filename string. Max 255 bytes. |
| `filename` | `filename_len` bytes | UTF-8 encoded original filename (sanitized; path separators rejected). |
| `media_type_len` | 2 bytes `uint16` | Big-endian length of the MIME media type string. Max 127 bytes. |
| `media_type` | `media_type_len` bytes | ASCII/UTF-8 MIME type string (e.g., `image/png`, `application/pdf`). |
| `file_bytes` | `L - 4 - filename_len - media_type_len` bytes | Raw file payload bytes. |

- **Encrypted File:** The structured metadata block above + `file_bytes` forms the plaintext input to AES-256-GCM. The encrypted output is stored in `payload_data`.

---

## 3. Authenticated Additional Data (AAD)

To prevent tampering with container parameters (such as changing payload type, forging version, or modifying declared lengths), the **entire header up to and including `payload_length`** is authenticated as AES-GCM Associated Data (AAD):

$$\text{AAD} = \text{magic} \parallel \text{version} \parallel \text{flags} \parallel \text{payload\_type} \parallel \text{salt\_len} \parallel \text{salt} \parallel \text{nonce\_len} \parallel \text{nonce} \parallel \text{payload\_length}$$

Any modification to the header bits causes AES-GCM authentication failure, protecting the container against header tampering and truncation attacks.

---

## 4. Container Overhead Summary

| Scenario | Header Overhead | Auth Tag | Total Container Framing Overhead |
|---|---|---|---|
| Unencrypted Text | 13 bytes | 0 bytes | **13 bytes** |
| Unencrypted File | 13 bytes + 4 + filename_len + media_type_len | 0 bytes | **17 + F + M bytes** |
| Encrypted Text | 41 bytes | 16 bytes | **57 bytes** |
| Encrypted File | 41 bytes + 4 + filename_len + media_type_len | 16 bytes | **61 + F + M bytes** |

---

## 5. Forward Compatibility and Error Handling

1. **Magic Signature Mismatch:** If the first 4 bytes do not equal `STEG`, the parser returns `NoSupportedPayloadResult`.
2. **Unsupported Version:** If `version != 0x01`, the parser returns `UnsupportedVersionResult(detectedVersion: version)`.
3. **Reserved Flags:** If any bits in `flags & 0xFE` are set, the parser returns `MalformedContainerResult("Reserved flags set")`.
4. **Declared Length Validation:** Before reading or allocating `payload_data`, `payload_length` is compared against the carrier's available byte capacity and maximum payload limit (64 MB). If `payload_length` exceeds capacity, `MalformedContainerResult("Declared length exceeds carrier capacity")` is returned.
5. **Truncation:** If the carrier ends before all declared bytes or the auth tag can be read, `MalformedContainerResult("Truncated payload")` is returned.
