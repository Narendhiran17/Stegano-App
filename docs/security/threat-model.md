# Security & Threat Model

## 1. System Overview

StegoEngine is an offline, client-side Dart engine for steganographic embedding and extraction of hidden data in lossless PNG images.

The primary security goals are:
1. **Confidentiality:** Hidden payloads protected by a password must remain confidential against adversaries who obtain the carrier image.
2. **Integrity & Authenticity:** Payloads cannot be forged, truncated, or tampered with without detection.
3. **Application & System Safety:** Untrusted carrier images and payloads must not cause buffer overflows, uncontrolled allocations (DoS), path traversal, or remote code execution.

---

## 2. Threat Actors & Capabilities

| Threat Actor | Capabilities | Objectives | Mitigations |
|---|---|---|---|
| **Passive Network / Storage Observer** | Inspects transmitted PNG files on network or disk. | Detect communication or extract plaintext. | LSB embedding visually hides data; AES-256-GCM + Argon2id ensures confidentiality even if detected. |
| **Active Man-in-the-Middle / Carrier Tamperer** | Modifies pixels or headers of transmitted carrier images. | Alter payload, forge messages, or cause crashes in recipient. | AES-256-GCM authenticated encryption with header AAD ensures any tampering triggers safe authentication failure. |
| **Malicious Carrier Provider** | Crafts deliberately malformed PNG files (decompression bombs, invalid chunk lengths, huge declared dimensions). | Cause Denial of Service (DoS), crash, or exploit memory safety. | Strict carrier dimension limits (max $8192 \times 8192$), pixel limits ($33.5 \text{ MP}$), and safe Dart memory management. |
| **Malicious Embedded Payload Author** | Crafts embedded files with path traversal filenames (`../../etc/passwd`), null bytes, or dangerous scripts. | Overwrite arbitrary system files or execute malicious payloads. | Strict filename sanitization, rejection of path separators (`/`, `\`), and explicit policy that engine and apps never auto-execute extracted files. |

---

## 3. Security Boundaries and Mitigations

### 3.1 Input Validation & Resource Bounds

| Parameter | Default Limit | Enforcement Mechanism |
|---|---|---|
| Max Image Dimensions | $8192 \times 8192$ px | Checked immediately upon image decode. |
| Max Carrier File Size | 128 MB | Checked before decoding carrier image. |
| Max Decoded Pixels | $33,554,432$ ($33.5$ MP) | Checked prior to bit allocation. |
| Max Payload Size | 64 MB | Checked against declared container length before allocation. |
| Max Filename Length | 255 bytes | Checked during file payload parsing. |
| Max Media Type Length | 127 bytes | Checked during file payload parsing. |

### 3.2 Safe Memory Allocation

In steganography engines, an attacker could embed a crafted header with `payload_length = 0xFFFFFFFF` (4 GB) in a small $100 \times 100$ image. StegoEngine enforces:

$$\text{payload\_length} \le \text{Raw Available Carrier Bytes}$$

If `payload_length` exceeds what the carrier can physically contain, the container is rejected immediately without allocating memory for the declared size.

### 3.3 Safe File Handling

- Extracted filenames are stripped of directories, drive letters, and dangerous characters.
- Extracted payloads are returned as raw byte buffers; they are never automatically executed or written to disk without explicit user confirmation.

---

## 4. Known Non-Goals & Limitations

- **Universal Undetectability:** LSB steganography is statistically detectable by specialized stegananalysis tools. StegoEngine makes no claim of absolute covertness.
- **Robustness Against Lossy Processing:** LSB modifications cannot survive JPEG conversion, lossy recompression, or social media re-encoding.

