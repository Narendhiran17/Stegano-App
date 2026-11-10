package com.example.stegosuite

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

enum class PayloadType(val code: Byte) {
    TEXT(0x01),
    FILE(0x02);

    companion object {
        fun fromCode(code: Byte): PayloadType {
            return entries.firstOrNull { it.code == code }
                ?: throw IllegalArgumentException("Unsupported payload type: $code")
        }
    }
}

data class CapacityInfo(
    val width: Int,
    val height: Int,
    val rawCapacityBytes: Int,
    val usableTextCapacityBytes: Int,
    val usableFileCapacityBytes: Int,
    val isEncrypted: Boolean
)

data class InspectionInfo(
    val status: String,
    val formatVersion: Int = 0,
    val payloadType: String = "",
    val isEncrypted: Boolean = false,
    val declaredPayloadLength: Int = 0,
    val message: String = ""
)

data class ExtractionInfo(
    val success: Boolean,
    val type: String = "",
    val text: String? = null,
    val filename: String? = null,
    val mediaType: String? = null,
    val fileBase64: String? = null,
    val fileSize: Int = 0,
    val isEncrypted: Boolean = false,
    val error: String? = null
)

object StegoEngine {
    private val MAGIC = byteArrayOf(0x53, 0x54, 0x45, 0x47) // "STEG"
    private const val VERSION: Byte = 0x01
    private const val FLAG_ENCRYPTED: Byte = 0x01
    private const val SALT_LENGTH = 16
    private const val NONCE_LENGTH = 12
    private const val AUTH_TAG_LENGTH = 16
    private const val MIN_HEADER_LENGTH = 13
    private const val ENCRYPTED_HEADER_LENGTH = 41

    private val secureRandom = SecureRandom()

    fun calculateCapacity(width: Int, height: Int, isEncrypted: Boolean): CapacityInfo {
        val totalChannels = width * height * 3
        val rawBytes = totalChannels / 8
        val overhead = if (isEncrypted) ENCRYPTED_HEADER_LENGTH + AUTH_TAG_LENGTH else MIN_HEADER_LENGTH
        val usableText = maxOf(0, rawBytes - overhead)
        val fileOverhead = overhead + 4
        val usableFile = maxOf(0, rawBytes - fileOverhead)
        return CapacityInfo(width, height, rawBytes, usableText, usableFile, isEncrypted)
    }

    fun deriveKey(password: String, salt: ByteArray): ByteArray {
        val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withIterations(2)
            .withMemoryAsKB(19456)
            .withParallelism(1)
            .withSalt(salt)
            .build()
        val generator = Argon2BytesGenerator()
        generator.init(params)
        val result = ByteArray(32)
        generator.generateBytes(password.toByteArray(Charsets.UTF_8), result)
        return result
    }

    fun encode(
        carrierBytes: ByteArray,
        payloadType: PayloadType,
        text: String?,
        fileBytes: ByteArray?,
        filename: String?,
        mediaType: String?,
        password: String?
    ): ByteArray {
        val bitmap = BitmapFactory.decodeByteArray(carrierBytes, 0, carrierBytes.size)
            ?: throw IllegalArgumentException("Invalid PNG carrier image")

        val width = bitmap.width
        val height = bitmap.height
        val encrypt = !password.isNullOrEmpty()

        val bodyBytes = when (payloadType) {
            PayloadType.TEXT -> (text ?: "").toByteArray(Charsets.UTF_8)
            PayloadType.FILE -> {
                val fBytes = fileBytes ?: ByteArray(0)
                val fName = (filename ?: "file.bin").toByteArray(Charsets.UTF_8)
                val mType = (mediaType ?: "application/octet-stream").toByteArray(Charsets.UTF_8)
                val bb = ByteBuffer.allocate(2 + fName.size + 2 + mType.size + fBytes.size).order(ByteOrder.BIG_ENDIAN)
                bb.putShort(fName.size.toShort())
                bb.put(fName)
                bb.putShort(mType.size.toShort())
                bb.put(mType)
                bb.put(fBytes)
                bb.array()
            }
        }

        val salt = if (encrypt) ByteArray(SALT_LENGTH).also { secureRandom.nextBytes(it) } else ByteArray(0)
        val nonce = if (encrypt) ByteArray(NONCE_LENGTH).also { secureRandom.nextBytes(it) } else ByteArray(0)

        val headerLen = if (encrypt) ENCRYPTED_HEADER_LENGTH else MIN_HEADER_LENGTH
        val headerBuf = ByteBuffer.allocate(headerLen).order(ByteOrder.BIG_ENDIAN)
        headerBuf.put(MAGIC)
        headerBuf.put(VERSION)
        headerBuf.put(if (encrypt) FLAG_ENCRYPTED else 0x00)
        headerBuf.put(payloadType.code)
        headerBuf.put(salt.size.toByte())
        headerBuf.put(nonce.size.toByte())
        headerBuf.putInt(bodyBytes.size)
        if (encrypt) {
            headerBuf.put(salt)
            headerBuf.put(nonce)
        }
        val headerBytes = headerBuf.array()

        val finalPayload: ByteArray
        if (encrypt) {
            val key = deriveKey(password!!, salt)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            cipher.updateAAD(headerBytes)
            val cipherAndTag = cipher.doFinal(bodyBytes)
            finalPayload = ByteArray(headerBytes.size + cipherAndTag.size)
            System.arraycopy(headerBytes, 0, finalPayload, 0, headerBytes.size)
            System.arraycopy(cipherAndTag, 0, finalPayload, headerBytes.size, cipherAndTag.size)
        } else {
            finalPayload = ByteArray(headerBytes.size + bodyBytes.size)
            System.arraycopy(headerBytes, 0, finalPayload, 0, headerBytes.size)
            System.arraycopy(bodyBytes, 0, finalPayload, headerBytes.size, bodyBytes.size)
        }

        val totalChannels = width * height * 3
        if (finalPayload.size * 8 > totalChannels) {
            throw IllegalArgumentException("Payload (${finalPayload.size} bytes) exceeds carrier capacity (${totalChannels / 8} bytes)")
        }

        val pixels = IntArray(width * height)
        bitmap.getPixels(pixels, 0, width, 0, 0, width, height)

        var byteIdx = 0
        var bitIdx = 7

        fun nextBit(): Int {
            if (byteIdx >= finalPayload.size) return -1
            val bit = (finalPayload[byteIdx].toInt() shr bitIdx) and 1
            bitIdx--
            if (bitIdx < 0) {
                bitIdx = 7
                byteIdx++
            }
            return bit
        }

        for (i in pixels.indices) {
            val pixel = pixels[i]
            val a = (pixel ushr 24) and 0xFF
            var r = (pixel ushr 16) and 0xFF
            var g = (pixel ushr 8) and 0xFF
            var b = pixel and 0xFF

            val bR = nextBit()
            if (bR != -1) r = (r and 0xFE) or bR

            val bG = nextBit()
            if (bG != -1) g = (g and 0xFE) or bG

            val bB = nextBit()
            if (bB != -1) b = (b and 0xFE) or bB

            pixels[i] = (a shl 24) or (r shl 16) or (g shl 8) or b

            if (bR == -1 && bG == -1 && bB == -1) break
        }

        val outBitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
        outBitmap.setPixels(pixels, 0, width, 0, 0, width, height)

        val bos = ByteArrayOutputStream()
        outBitmap.compress(Bitmap.CompressFormat.PNG, 100, bos)
        return bos.toByteArray()
    }

    private fun extractBits(pixels: IntArray, numBytes: Int): ByteArray {
        val out = ByteArray(numBytes)
        var byteIdx = 0
        var bitIdx = 7
        var currentByte = 0

        for (pixel in pixels) {
            val r = (pixel ushr 16) and 1
            val g = (pixel ushr 8) and 1
            val b = pixel and 1

            for (bit in intArrayOf(r, g, b)) {
                currentByte = currentByte or (bit shl bitIdx)
                bitIdx--
                if (bitIdx < 0) {
                    out[byteIdx++] = currentByte.toByte()
                    if (byteIdx == numBytes) return out
                    bitIdx = 7
                    currentByte = 0
                }
            }
        }
        return out
    }

    fun inspect(carrierBytes: ByteArray): InspectionInfo {
        val bitmap = BitmapFactory.decodeByteArray(carrierBytes, 0, carrierBytes.size)
            ?: return InspectionInfo(status = "invalid_image", message = "Invalid carrier image")

        val pixels = IntArray(bitmap.width * bitmap.height)
        bitmap.getPixels(pixels, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)

        val prefix = extractBits(pixels, 7)
        if (prefix[0] != MAGIC[0] || prefix[1] != MAGIC[1] || prefix[2] != MAGIC[2] || prefix[3] != MAGIC[3]) {
            return InspectionInfo(status = "no_payload", message = "No valid STEG signature detected.")
        }

        val version = prefix[4].toInt()
        val flags = prefix[5].toInt()
        val typeCode = prefix[6]
        val isEncrypted = (flags and FLAG_ENCRYPTED.toInt()) != 0
        val pType = try { PayloadType.fromCode(typeCode).name.lowercase() } catch (_: Exception) { "unknown" }

        val headerLen = if (isEncrypted) ENCRYPTED_HEADER_LENGTH else MIN_HEADER_LENGTH
        val headerBytes = extractBits(pixels, headerLen)
        val buf = ByteBuffer.wrap(headerBytes).order(ByteOrder.BIG_ENDIAN)
        buf.position(9)
        val declaredLen = buf.int

        return InspectionInfo(
            status = "supported",
            formatVersion = version,
            payloadType = pType,
            isEncrypted = isEncrypted,
            declaredPayloadLength = declaredLen,
            message = "Validated container signature with ${if (isEncrypted) "AES-256-GCM encrypted" else "unencrypted"} $pType framing."
        )
    }

    fun extract(carrierBytes: ByteArray, password: String?): ExtractionInfo {
        val bitmap = BitmapFactory.decodeByteArray(carrierBytes, 0, carrierBytes.size)
            ?: return ExtractionInfo(success = false, error = "Invalid image carrier")

        val pixels = IntArray(bitmap.width * bitmap.height)
        bitmap.getPixels(pixels, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)

        val prefix = extractBits(pixels, 7)
        if (prefix[0] != MAGIC[0] || prefix[1] != MAGIC[1] || prefix[2] != MAGIC[2] || prefix[3] != MAGIC[3]) {
            return ExtractionInfo(success = false, error = "No STEG container found")
        }

        val flags = prefix[5].toInt()
        val typeCode = prefix[6]
        val isEncrypted = (flags and FLAG_ENCRYPTED.toInt()) != 0
        val payloadType = PayloadType.fromCode(typeCode)

        val headerLen = if (isEncrypted) ENCRYPTED_HEADER_LENGTH else MIN_HEADER_LENGTH
        val headerBytes = extractBits(pixels, headerLen)
        val buf = ByteBuffer.wrap(headerBytes).order(ByteOrder.BIG_ENDIAN)
        buf.position(7)
        val saltLen = buf.get().toInt() and 0xFF
        val nonceLen = buf.get().toInt() and 0xFF
        val declaredLen = buf.int
        val salt = ByteArray(saltLen).also { buf.get(it) }
        val nonce = ByteArray(nonceLen).also { buf.get(it) }

        val totalContainerBytes = headerLen + declaredLen + (if (isEncrypted) AUTH_TAG_LENGTH else 0)
        val fullContainer = extractBits(pixels, totalContainerBytes)

        val bodyCipherAndTag = ByteArray(declaredLen + (if (isEncrypted) AUTH_TAG_LENGTH else 0))
        System.arraycopy(fullContainer, headerLen, bodyCipherAndTag, 0, bodyCipherAndTag.size)

        val plainBytes: ByteArray
        if (isEncrypted) {
            if (password.isNullOrEmpty()) {
                return ExtractionInfo(success = false, error = "Passphrase required for encrypted container")
            }
            try {
                val key = deriveKey(password, salt)
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
                cipher.updateAAD(headerBytes)
                plainBytes = cipher.doFinal(bodyCipherAndTag)
            } catch (e: Exception) {
                return ExtractionInfo(success = false, error = "Decryption failed: Incorrect passphrase or tampered bits (${e.message})")
            }
        } else {
            plainBytes = bodyCipherAndTag
        }

        return when (payloadType) {
            PayloadType.TEXT -> {
                val text = String(plainBytes, Charsets.UTF_8)
                ExtractionInfo(success = true, type = "text", text = text, isEncrypted = isEncrypted)
            }
            PayloadType.FILE -> {
                val b = ByteBuffer.wrap(plainBytes).order(ByteOrder.BIG_ENDIAN)
                val fnLen = b.short.toInt() and 0xFFFF
                val fnBytes = ByteArray(fnLen).also { b.get(it) }
                val filename = String(fnBytes, Charsets.UTF_8)

                val mtLen = b.short.toInt() and 0xFFFF
                val mtBytes = ByteArray(mtLen).also { b.get(it) }
                val mediaType = String(mtBytes, Charsets.UTF_8)

                val fileData = ByteArray(b.remaining()).also { b.get(it) }
                val base64 = android.util.Base64.encodeToString(fileData, android.util.Base64.NO_WRAP)

                ExtractionInfo(
                    success = true,
                    type = "file",
                    filename = filename,
                    mediaType = mediaType,
                    fileBase64 = base64,
                    fileSize = fileData.size,
                    isEncrypted = isEncrypted
                )
            }
        }
    }
}
