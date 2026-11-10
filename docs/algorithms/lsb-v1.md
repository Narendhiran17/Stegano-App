# Least Significant Bit (LSB) Embedding Specification (V1)

## 1. Overview

The V1 embedding algorithm utilizes **1-bit Least Significant Bit (LSB)** substitution on the Red, Green, and Blue (RGB) color channels of each pixel in a lossless PNG image. The Alpha channel is strictly preserved and never modified.

---

## 2. Traversal and Bit Ordering

### 2.1 Coordinate Traversal Order

The carrier image is traversed sequentially:
1. **Row-by-row** from top to bottom: $y \in [0, \text{height} - 1]$
2. **Column-by-column** from left to right: $x \in [0, \text{width} - 1]$

### 2.2 Channel Traversal Order

For each pixel at coordinate $(x, y)$, channels are accessed in standard RGB order:
1. **Red** (R) channel
2. **Green** (G) channel
3. **Blue** (B) channel

*(The Alpha channel is skipped completely).*

Each pixel provides exactly **3 bits** of raw storage capacity.

### 2.3 Bit Serialization Order

Bytes from the serialized payload container are unpacked and embedded **Most Significant Bit (MSB) first**:
- Bit 7 ($\text{byte} \ \& \ 0\text{x}80 \gg 7$)
- Bit 6 ($\text{byte} \ \& \ 0\text{x}40 \gg 6$)
- Bit 5 ($\text{byte} \ \& \ 0\text{x}20 \gg 5$)
- Bit 4 ($\text{byte} \ \& \ 0\text{x}10 \gg 4$)
- Bit 3 ($\text{byte} \ \& \ 0\text{x}08 \gg 3$)
- Bit 2 ($\text{byte} \ \& \ 0\text{x}04 \gg 2$)
- Bit 1 ($\text{byte} \ \& \ 0\text{x}02 \gg 1$)
- Bit 0 ($\text{byte} \ \& \ 0\text{x}01$)

During extraction, bits are read in the exact same channel sequence and bit order, shifting incoming bits into accumulator bytes from MSB down to LSB.

---

## 3. Pixel Modification Function

For a color channel with 8-bit value $C \in [0, 255]$ and a target bit $b \in \{0, 1\}$:

$$C' = (C \ \& \ \sim 1) \ | \ b$$

Alpha is preserved unmodified:

$$A' = A$$

---

## 4. Capacity Calculation

### 4.1 Raw Capacity

$$\text{Raw Capacity (bits)} = \text{width} \times \text{height} \times 3$$

$$\text{Raw Capacity (bytes)} = \left\lfloor \frac{\text{width} \times \text{height} \times 3}{8} \right\rfloor$$

Any fractional remaining bits $((\text{width} \times \text{height} \times 3) \pmod 8)$ are ignored.

### 4.2 Usable Payload Capacity

$$\text{Usable Capacity} = \text{Raw Capacity (bytes)} - \text{Framing Overhead}$$

Where framing overhead is defined in `payload-format.md`:
- Unencrypted text: 13 bytes
- Unencrypted file: $17 + \text{filename\_length} + \text{mediatype\_length}$ bytes
- Encrypted text: 57 bytes
- Encrypted file: $61 + \text{filename\_length} + \text{mediatype\_length}$ bytes

---

## 5. Security & Detectability Considerations

LSB steganography introduces minimal perceptual degradation (changes of $\pm 1$ per 8-bit color intensity are invisible to the human eye). However:
1. **Detectability:** LSB modification alter the statistical distribution of low-order bits (e.g. Chi-Square analysis, Sample Pair Analysis, RS stegananalysis). LSB is **not undetectable** against statistical inspection.
2. **Fragility:** LSB encoding is strictly fragile. Any lossy re-encoding (e.g. converting to JPEG, WebP lossy, social media resizing, or color quantization) destroys the embedded payload. PNG lossless transmission is required.
