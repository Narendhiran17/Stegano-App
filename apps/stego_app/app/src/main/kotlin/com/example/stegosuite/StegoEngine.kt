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
import kotlin.math.abs

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
    val isScattered: Boolean = false,
    val isDeniable: Boolean = false,
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
    val isScattered: Boolean = false,
    val isDeniable: Boolean = false,
    val isDecoy: Boolean = false,
    val error: String? = null
)

object StegoEngine {
    private val MAGIC = byteArrayOf(0x53, 0x54, 0x45, 0x47) // "STEG"
    private const val VERSION: Byte = 0x01
    private const val FLAG_ENCRYPTED: Byte = 0x01
    private const val FLAG_SCATTERED: Byte = 0x02
    private const val FLAG_DENIABLE: Byte = 0x04

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

    private fun gcd(a: Long, b: Long): Long {
        var x = a
        var y = b
        while (y != 0L) {
            val t = y
            y = x % y
            x = t
        }
        return x
    }

    private fun getCoprimeStride(m: Long, seed: Long): Long {
        if (m <= 2) return 1L
        var stride = (abs(seed) % (m - 1)) + 1L
        if (stride % 2L == 0L) stride++
        while (gcd(stride, m) != 1L) {
            stride = (stride + 2L) % m
            if (stride <= 1L) stride = 3L
        }
        return stride
    }

    fun encode(
        carrierBytes: ByteArray,
        payloadType: PayloadType,
        text: String?,
        fileBytes: ByteArray?,
        filename: String?,
        mediaType: String?,
        password: String?,
        isScattered: Boolean = false,
        decoyText: String? = null,
        decoyPassword: String? = null
    ): ByteArray {
        val bitmap = BitmapFactory.decodeByteArray(carrierBytes, 0, carrierBytes.size)
            ?: throw IllegalArgumentException("Invalid PNG carrier image")

        val width = bitmap.width
        val height = bitmap.height
        val encrypt = !password.isNullOrEmpty()
        val isDeniable = encrypt && !decoyText.isNullOrEmpty() && !decoyPassword.isNullOrEmpty()

        val trueBodyBytes = when (payloadType) {
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

        var flags: Byte = 0
        if (encrypt) flags = (flags.toInt() or FLAG_ENCRYPTED.toInt()).toByte()
        if (isScattered) flags = (flags.toInt() or FLAG_SCATTERED.toInt()).toByte()
        if (isDeniable) flags = (flags.toInt() or FLAG_DENIABLE.toInt()).toByte()

        val headerLen = if (encrypt) ENCRYPTED_HEADER_LENGTH else MIN_HEADER_LENGTH
        val finalPayload: ByteArray

        if (isDeniable) {
            // Plausible Deniability: Build dual-slot body
            val decoyBytes = (decoyText ?: "").toByteArray(Charsets.UTF_8)
            val dSalt = ByteArray(SALT_LENGTH).also { secureRandom.nextBytes(it) }
            val dNonce = ByteArray(NONCE_LENGTH).also { secureRandom.nextBytes(it) }
            val dKey = deriveKey(decoyPassword!!, dSalt)
            val dCipher = Cipher.getInstance("AES/GCM/NoPadding")
            dCipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(dKey, "AES"), GCMParameterSpec(128, dNonce))
            val dCipherAndTag = dCipher.doFinal(decoyBytes)

            val dSlotBuf = ByteBuffer.allocate(SALT_LENGTH + NONCE_LENGTH + dCipherAndTag.size)
            dSlotBuf.put(dSalt)
            dSlotBuf.put(dNonce)
            dSlotBuf.put(dCipherAndTag)
            val dSlotBytes = dSlotBuf.array()

            // True Slot
            val tKey = deriveKey(password!!, salt)
            val tCipher = Cipher.getInstance("AES/GCM/NoPadding")
            tCipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(tKey, "AES"), GCMParameterSpec(128, nonce))
            val tCipherAndTag = tCipher.doFinal(trueBodyBytes)

            val tSlotBuf = ByteBuffer.allocate(SALT_LENGTH + NONCE_LENGTH + tCipherAndTag.size)
            tSlotBuf.put(salt)
            tSlotBuf.put(nonce)
            tSlotBuf.put(tCipherAndTag)
            val tSlotBytes = tSlotBuf.array()

            // Combined dual-slot body: [decoyLen(4)][decoyBytes][trueLen(4)][trueBytes]
            val dualBody = ByteBuffer.allocate(4 + dSlotBytes.size + 4 + tSlotBytes.size).order(ByteOrder.BIG_ENDIAN)
            dualBody.putInt(dSlotBytes.size)
            dualBody.put(dSlotBytes)
            dualBody.putInt(tSlotBytes.size)
            dualBody.put(tSlotBytes)
            val dualBodyBytes = dualBody.array()

            val headerBuf = ByteBuffer.allocate(headerLen).order(ByteOrder.BIG_ENDIAN)
            headerBuf.put(MAGIC)
            headerBuf.put(VERSION)
            headerBuf.put(flags)
            headerBuf.put(payloadType.code)
            headerBuf.put(salt.size.toByte())
            headerBuf.put(nonce.size.toByte())
            headerBuf.putInt(dualBodyBytes.size)
            headerBuf.put(salt)
            headerBuf.put(nonce)
            val headerBytes = headerBuf.array()

            finalPayload = ByteArray(headerBytes.size + dualBodyBytes.size)
            System.arraycopy(headerBytes, 0, finalPayload, 0, headerBytes.size)
            System.arraycopy(dualBodyBytes, 0, finalPayload, headerBytes.size, dualBodyBytes.size)
        } else if (encrypt) {
            val key = deriveKey(password!!, salt)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))

            val headerBuf = ByteBuffer.allocate(headerLen).order(ByteOrder.BIG_ENDIAN)
            headerBuf.put(MAGIC)
            headerBuf.put(VERSION)
            headerBuf.put(flags)
            headerBuf.put(payloadType.code)
            headerBuf.put(salt.size.toByte())
            headerBuf.put(nonce.size.toByte())
            headerBuf.putInt(trueBodyBytes.size)
            headerBuf.put(salt)
            headerBuf.put(nonce)
            val headerBytes = headerBuf.array()

            cipher.updateAAD(headerBytes)
            val cipherAndTag = cipher.doFinal(trueBodyBytes)

            finalPayload = ByteArray(headerBytes.size + cipherAndTag.size)
            System.arraycopy(headerBytes, 0, finalPayload, 0, headerBytes.size)
            System.arraycopy(cipherAndTag, 0, finalPayload, headerBytes.size, cipherAndTag.size)
        } else {
            val headerBuf = ByteBuffer.allocate(headerLen).order(ByteOrder.BIG_ENDIAN)
            headerBuf.put(MAGIC)
            headerBuf.put(VERSION)
            headerBuf.put(flags)
            headerBuf.put(payloadType.code)
            headerBuf.put(0.toByte())
            headerBuf.put(0.toByte())
            headerBuf.putInt(trueBodyBytes.size)
            val headerBytes = headerBuf.array()

            finalPayload = ByteArray(headerBytes.size + trueBodyBytes.size)
            System.arraycopy(headerBytes, 0, finalPayload, 0, headerBytes.size)
            System.arraycopy(trueBodyBytes, 0, finalPayload, headerBytes.size, trueBodyBytes.size)
        }

        val totalChannels = width * height * 3
        if (finalPayload.size * 8 > totalChannels) {
            throw IllegalArgumentException("Payload (${finalPayload.size} bytes) exceeds carrier capacity (${totalChannels / 8} bytes)")
        }

        val pixels = IntArray(width * height)
        bitmap.getPixels(pixels, 0, width, 0, 0, width, height)

        val headerBitLength = headerLen * 8
        val payloadBitLength = (finalPayload.size - headerLen) * 8
        val remainingSlots = (totalChannels - headerBitLength).toLong()

        // 1. Embed Header (Fixed slots for discovery)
        for (i in 0 until headerBitLength) {
            val byteIndex = i / 8
            val bitInByte = 7 - (i % 8)
            val bit = (finalPayload[byteIndex].toInt() shr bitInByte) and 1

            val pixelIndex = i / 3
            val channel = i % 3
            var pixel = pixels[pixelIndex]

            val a = (pixel ushr 24) and 0xFF
            var r = (pixel ushr 16) and 0xFF
            var g = (pixel ushr 8) and 0xFF
            var b = pixel and 0xFF

            when (channel) {
                0 -> r = (r and 0xFE) or bit
                1 -> g = (g and 0xFE) or bit
                2 -> b = (b and 0xFE) or bit
            }
            pixels[pixelIndex] = (a shl 24) or (r shl 16) or (g shl 8) or b
        }

        // 2. Embed Payload (Sequential or PRNG Scattered)
        val seed = if (encrypt) ByteBuffer.wrap(salt).order(ByteOrder.BIG_ENDIAN).long else 0x5445474F53554954L
        val stride = if (isScattered) getCoprimeStride(remainingSlots, seed) else 1L
        val offset = if (isScattered) abs(seed ushr 16) % remainingSlots else 0L

        for (i in 0 until payloadBitLength) {
            val byteIndex = headerLen + (i / 8)
            val bitInByte = 7 - (i % 8)
            val bit = (finalPayload[byteIndex].toInt() shr bitInByte) and 1

            val slotOffset = if (isScattered) ((offset + i * stride) % remainingSlots).toInt() else i
            val globalSlot = headerBitLength + slotOffset
            val pixelIndex = globalSlot / 3
            val channel = globalSlot % 3
            var pixel = pixels[pixelIndex]

            val a = (pixel ushr 24) and 0xFF
            var r = (pixel ushr 16) and 0xFF
            var g = (pixel ushr 8) and 0xFF
            var b = pixel and 0xFF

            when (channel) {
                0 -> r = (r and 0xFE) or bit
                1 -> g = (g and 0xFE) or bit
                2 -> b = (b and 0xFE) or bit
            }
            pixels[pixelIndex] = (a shl 24) or (r shl 16) or (g shl 8) or b
        }

        val outBitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
        outBitmap.setPixels(pixels, 0, width, 0, 0, width, height)

        val bos = ByteArrayOutputStream()
        outBitmap.compress(Bitmap.CompressFormat.PNG, 100, bos)
        return bos.toByteArray()
    }

    private fun extractHeaderBytes(pixels: IntArray, numBytes: Int): ByteArray {
        val out = ByteArray(numBytes)
        var byteIdx = 0
        var bitIdx = 7
        var currentByte = 0
        val totalBits = numBytes * 8

        for (i in 0 until totalBits) {
            val pixelIndex = i / 3
            val channel = i % 3
            val pixel = pixels[pixelIndex]

            val bit = when (channel) {
                0 -> (pixel ushr 16) and 1
                1 -> (pixel ushr 8) and 1
                else -> pixel and 1
            }

            currentByte = currentByte or (bit shl bitIdx)
            bitIdx--
            if (bitIdx < 0) {
                out[byteIdx++] = currentByte.toByte()
                bitIdx = 7
                currentByte = 0
            }
        }
        return out
    }

    private fun extractPayloadBytes(
        pixels: IntArray,
        headerLen: Int,
        numPayloadBytes: Int,
        totalChannels: Int,
        isScattered: Boolean,
        salt: ByteArray
    ): ByteArray {
        val out = ByteArray(numPayloadBytes)
        val headerBitLength = headerLen * 8
        val payloadBitLength = numPayloadBytes * 8
        val remainingSlots = (totalChannels - headerBitLength).toLong()

        val seed = if (salt.isNotEmpty()) ByteBuffer.wrap(salt).order(ByteOrder.BIG_ENDIAN).long else 0x5445474F53554954L
        val stride = if (isScattered) getCoprimeStride(remainingSlots, seed) else 1L
        val offset = if (isScattered) abs(seed ushr 16) % remainingSlots else 0L

        var byteIdx = 0
        var bitIdx = 7
        var currentByte = 0

        for (i in 0 until payloadBitLength) {
            val slotOffset = if (isScattered) ((offset + i * stride) % remainingSlots).toInt() else i
            val globalSlot = headerBitLength + slotOffset
            val pixelIndex = globalSlot / 3
            val channel = globalSlot % 3
            val pixel = pixels[pixelIndex]

            val bit = when (channel) {
                0 -> (pixel ushr 16) and 1
                1 -> (pixel ushr 8) and 1
                else -> pixel and 1
            }

            currentByte = currentByte or (bit shl bitIdx)
            bitIdx--
            if (bitIdx < 0) {
                out[byteIdx++] = currentByte.toByte()
                bitIdx = 7
                currentByte = 0
            }
        }
        return out
    }

    fun inspect(carrierBytes: ByteArray): InspectionInfo {
        val isJpeg = carrierBytes.size >= 3 &&
                (carrierBytes[0].toInt() and 0xFF) == 0xFF &&
                (carrierBytes[1].toInt() and 0xFF) == 0xD8 &&
                (carrierBytes[2].toInt() and 0xFF) == 0xFF

        val bitmap = BitmapFactory.decodeByteArray(carrierBytes, 0, carrierBytes.size)
            ?: return InspectionInfo(status = "invalid_image", message = "Invalid carrier image")

        val pixels = IntArray(bitmap.width * bitmap.height)
        bitmap.getPixels(pixels, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)

        val prefix = extractHeaderBytes(pixels, 7)
        if (prefix[0] != MAGIC[0] || prefix[1] != MAGIC[1] || prefix[2] != MAGIC[2] || prefix[3] != MAGIC[3]) {
            if (isJpeg) {
                return InspectionInfo(
                    status = "jpeg_compressed",
                    message = "WhatsApp / Social Media Photo Compression Detected! WhatsApp recompressed this image into a lossy JPEG, which erased the hidden steganographic bits. You must send and receive as a Document."
                )
            }
            return InspectionInfo(status = "no_payload", message = "No valid STEG signature detected.")
        }

        val version = prefix[4].toInt()
        val flags = prefix[5].toInt()
        val typeCode = prefix[6]
        val isEncrypted = (flags and FLAG_ENCRYPTED.toInt()) != 0
        val isScattered = (flags and FLAG_SCATTERED.toInt()) != 0
        val isDeniable = (flags and FLAG_DENIABLE.toInt()) != 0
        val pType = try { PayloadType.fromCode(typeCode).name.lowercase() } catch (_: Exception) { "unknown" }

        val headerLen = if (isEncrypted) ENCRYPTED_HEADER_LENGTH else MIN_HEADER_LENGTH
        val headerBytes = extractHeaderBytes(pixels, headerLen)
        val buf = ByteBuffer.wrap(headerBytes).order(ByteOrder.BIG_ENDIAN)
        buf.position(9)
        val declaredLen = buf.int

        var features = if (isEncrypted) "AES-256-GCM encrypted" else "unencrypted"
        if (isScattered) features += " + PRNG scattered"
        if (isDeniable) features += " + Plausible Deniability"

        return InspectionInfo(
            status = "supported",
            formatVersion = version,
            payloadType = pType,
            isEncrypted = isEncrypted,
            isScattered = isScattered,
            isDeniable = isDeniable,
            declaredPayloadLength = declaredLen,
            message = "Validated container signature with $features $pType framing."
        )
    }

    fun extract(carrierBytes: ByteArray, password: String?): ExtractionInfo {
        val isJpeg = carrierBytes.size >= 3 &&
                (carrierBytes[0].toInt() and 0xFF) == 0xFF &&
                (carrierBytes[1].toInt() and 0xFF) == 0xD8 &&
                (carrierBytes[2].toInt() and 0xFF) == 0xFF

        val bitmap = BitmapFactory.decodeByteArray(carrierBytes, 0, carrierBytes.size)
            ?: return ExtractionInfo(success = false, error = "Invalid image carrier")

        val totalChannels = bitmap.width * bitmap.height * 3
        val pixels = IntArray(bitmap.width * bitmap.height)
        bitmap.getPixels(pixels, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)

        val prefix = extractHeaderBytes(pixels, 7)
        if (prefix[0] != MAGIC[0] || prefix[1] != MAGIC[1] || prefix[2] != MAGIC[2] || prefix[3] != MAGIC[3]) {
            if (isJpeg) {
                return ExtractionInfo(
                    success = false,
                    error = "WhatsApp / Social Media photo compression detected! WhatsApp recompressed this image into a lossy JPEG, which erased all hidden data bits. To receive secret messages on WhatsApp, the sender must send the PNG as a 'Document' (📎 Paperclip -> Document)."
                )
            }
            return ExtractionInfo(success = false, error = "No STEG container found")
        }

        val flags = prefix[5].toInt()
        val typeCode = prefix[6]
        val isEncrypted = (flags and FLAG_ENCRYPTED.toInt()) != 0
        val isScattered = (flags and FLAG_SCATTERED.toInt()) != 0
        val isDeniable = (flags and FLAG_DENIABLE.toInt()) != 0
        val payloadType = PayloadType.fromCode(typeCode)

        val headerLen = if (isEncrypted) ENCRYPTED_HEADER_LENGTH else MIN_HEADER_LENGTH
        val headerBytes = extractHeaderBytes(pixels, headerLen)
        val buf = ByteBuffer.wrap(headerBytes).order(ByteOrder.BIG_ENDIAN)
        buf.position(7)
        val saltLen = buf.get().toInt() and 0xFF
        val nonceLen = buf.get().toInt() and 0xFF
        val declaredLen = buf.int
        val salt = ByteArray(saltLen).also { buf.get(it) }
        val nonce = ByteArray(nonceLen).also { buf.get(it) }

        val payloadBytesToRead = declaredLen + (if (isEncrypted && !isDeniable) AUTH_TAG_LENGTH else 0)
        val rawPayload = extractPayloadBytes(
            pixels = pixels,
            headerLen = headerLen,
            numPayloadBytes = payloadBytesToRead,
            totalChannels = totalChannels,
            isScattered = isScattered,
            salt = salt
        )

        if (isDeniable) {
            if (password.isNullOrEmpty()) {
                return ExtractionInfo(success = false, error = "Passphrase required for encrypted container")
            }

            val dBuf = ByteBuffer.wrap(rawPayload).order(ByteOrder.BIG_ENDIAN)
            val dSlotLen = dBuf.int
            val dSlotBytes = ByteArray(dSlotLen).also { dBuf.get(it) }
            val tSlotLen = dBuf.int
            val tSlotBytes = ByteArray(tSlotLen).also { dBuf.get(it) }

            // 1. Try True Slot first
            val tBuf = ByteBuffer.wrap(tSlotBytes)
            val tSalt = ByteArray(SALT_LENGTH).also { tBuf.get(it) }
            val tNonce = ByteArray(NONCE_LENGTH).also { tBuf.get(it) }
            val tCipherAndTag = ByteArray(tBuf.remaining()).also { tBuf.get(it) }

            try {
                val tKey = deriveKey(password, tSalt)
                val tCipher = Cipher.getInstance("AES/GCM/NoPadding")
                tCipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(tKey, "AES"), GCMParameterSpec(128, tNonce))
                val plainBytes = tCipher.doFinal(tCipherAndTag)

                return parsePlainBytes(plainBytes, payloadType, isEncrypted, isScattered, isDeniable = true, isDecoy = false)
            } catch (_: Exception) {
                // True slot authentication failed, try Decoy slot next
            }

            // 2. Try Decoy Slot
            val decBuf = ByteBuffer.wrap(dSlotBytes)
            val dSalt = ByteArray(SALT_LENGTH).also { decBuf.get(it) }
            val dNonce = ByteArray(NONCE_LENGTH).also { decBuf.get(it) }
            val dCipherAndTag = ByteArray(decBuf.remaining()).also { decBuf.get(it) }

            try {
                val dKey = deriveKey(password, dSalt)
                val dCipher = Cipher.getInstance("AES/GCM/NoPadding")
                dCipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(dKey, "AES"), GCMParameterSpec(128, dNonce))
                val decoyPlainBytes = dCipher.doFinal(dCipherAndTag)

                val decoyText = String(decoyPlainBytes, Charsets.UTF_8)
                return ExtractionInfo(
                    success = true,
                    type = "text",
                    text = decoyText,
                    isEncrypted = true,
                    isScattered = isScattered,
                    isDeniable = true,
                    isDecoy = true
                )
            } catch (_: Exception) {
                return ExtractionInfo(success = false, error = "Decryption failed: Incorrect passphrase")
            }
        }

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
                plainBytes = cipher.doFinal(rawPayload)
            } catch (e: Exception) {
                return ExtractionInfo(success = false, error = "Decryption failed: Incorrect passphrase or tampered bits")
            }
        } else {
            plainBytes = rawPayload
        }

        return parsePlainBytes(plainBytes, payloadType, isEncrypted, isScattered, isDeniable = false, isDecoy = false)
    }

    private fun parsePlainBytes(
        plainBytes: ByteArray,
        payloadType: PayloadType,
        isEncrypted: Boolean,
        isScattered: Boolean,
        isDeniable: Boolean,
        isDecoy: Boolean
    ): ExtractionInfo {
        return when (payloadType) {
            PayloadType.TEXT -> {
                val text = String(plainBytes, Charsets.UTF_8)
                ExtractionInfo(
                    success = true,
                    type = "text",
                    text = text,
                    isEncrypted = isEncrypted,
                    isScattered = isScattered,
                    isDeniable = isDeniable,
                    isDecoy = isDecoy
                )
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
                    isEncrypted = isEncrypted,
                    isScattered = isScattered,
                    isDeniable = isDeniable,
                    isDecoy = isDecoy
                )
            }
        }
    }
}
