package com.example.stegosuite

import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.util.Base64
import android.webkit.JavascriptInterface
import android.widget.Toast
import androidx.core.content.FileProvider
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream

class StegoBridge(private val context: Context) {

    @JavascriptInterface
    fun launchCamera() {
        (context as? MainActivity)?.runOnUiThread {
            (context as? MainActivity)?.requestCameraAndCapture()
        }
    }

    @JavascriptInterface
    fun calculateCapacity(carrierBase64: String, isEncrypted: Boolean): String {
        return try {
            val bytes = Base64.decode(carrierBase64, Base64.DEFAULT)
            val bitmap = BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                ?: return JSONObject().put("success", false).put("error", "Invalid PNG image").toString()

            val cap = StegoEngine.calculateCapacity(bitmap.width, bitmap.height, isEncrypted)
            JSONObject().apply {
                put("success", true)
                put("width", cap.width)
                put("height", cap.height)
                put("rawCapacityBytes", cap.rawCapacityBytes)
                put("usableTextCapacityBytes", cap.usableTextCapacityBytes)
                put("usableFileCapacityBytes", cap.usableFileCapacityBytes)
                put("isEncrypted", cap.isEncrypted)
            }.toString()
        } catch (e: Exception) {
            JSONObject().put("success", false).put("error", e.message).toString()
        }
    }

    @JavascriptInterface
    fun inspect(carrierBase64: String): String {
        return try {
            val bytes = Base64.decode(carrierBase64, Base64.DEFAULT)
            val bitmap = BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                ?: return JSONObject().put("status", "invalid_image").put("message", "Invalid image").toString()

            val info = StegoEngine.inspect(bytes)
            JSONObject().apply {
                put("status", info.status)
                put("message", info.message)
                if (info.status == "supported") {
                    put("payload", JSONObject().apply {
                        put("formatVersion", info.formatVersion)
                        put("type", info.payloadType)
                        put("isEncrypted", info.isEncrypted)
                        put("isScattered", info.isScattered)
                        put("isDeniable", info.isDeniable)
                        put("declaredPayloadLength", info.declaredPayloadLength)
                    })
                    put("carrier", JSONObject().apply {
                        put("width", bitmap.width)
                        put("height", bitmap.height)
                    })
                }
            }.toString()
        } catch (e: Exception) {
            JSONObject().put("status", "error").put("message", e.message).toString()
        }
    }

    @JavascriptInterface
    fun encode(
        carrierBase64: String,
        type: String,
        text: String?,
        fileBase64: String?,
        filename: String?,
        mediaType: String?,
        password: String?,
        isScattered: Boolean,
        decoyText: String?,
        decoyPassword: String?
    ): String {
        return try {
            val carrierBytes = Base64.decode(carrierBase64, Base64.DEFAULT)
            val payloadType = if (type == "file") PayloadType.FILE else PayloadType.TEXT
            val fileBytes = if (fileBase64 != null) Base64.decode(fileBase64, Base64.DEFAULT) else null

            val stegoBytes = StegoEngine.encode(
                carrierBytes = carrierBytes,
                payloadType = payloadType,
                text = text,
                fileBytes = fileBytes,
                filename = filename,
                mediaType = mediaType,
                password = password,
                isScattered = isScattered,
                decoyText = decoyText,
                decoyPassword = decoyPassword
            )

            val base64Stego = Base64.encodeToString(stegoBytes, Base64.NO_WRAP)
            JSONObject().apply {
                put("success", true)
                put("stegoImageBase64", base64Stego)
                put("fileSize", stegoBytes.size)
            }.toString()
        } catch (e: Exception) {
            JSONObject().put("success", false).put("message", e.message).toString()
        }
    }

    @JavascriptInterface
    fun encode(
        carrierBase64: String,
        type: String,
        text: String?,
        fileBase64: String?,
        filename: String?,
        mediaType: String?,
        password: String?
    ): String {
        return encode(
            carrierBase64 = carrierBase64,
            type = type,
            text = text,
            fileBase64 = fileBase64,
            filename = filename,
            mediaType = mediaType,
            password = password,
            isScattered = false,
            decoyText = null,
            decoyPassword = null
        )
    }

    @JavascriptInterface
    fun extract(carrierBase64: String, password: String?): String {
        return try {
            val carrierBytes = Base64.decode(carrierBase64, Base64.DEFAULT)
            val res = StegoEngine.extract(carrierBytes, password)

            JSONObject().apply {
                put("success", res.success)
                if (res.success) {
                    put("type", res.type)
                    put("isEncrypted", res.isEncrypted)
                    put("isScattered", res.isScattered)
                    put("isDeniable", res.isDeniable)
                    put("isDecoy", res.isDecoy)
                    if (res.type == "text") {
                        put("text", res.text)
                    } else {
                        put("filename", res.filename)
                        put("mediaType", res.mediaType)
                        put("fileBase64", res.fileBase64)
                        put("fileSize", res.fileSize)
                    }
                } else {
                    put("message", res.error)
                }
            }.toString()
        } catch (e: Exception) {
            JSONObject().put("success", false).put("message", e.message).toString()
        }
    }

    @JavascriptInterface
    fun saveImageToGallery(base64Png: String, filename: String): Boolean {
        return try {
            val bytes = Base64.decode(base64Png, Base64.DEFAULT)
            val name = if (filename.endsWith(".png")) filename else "$filename.png"

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val values = ContentValues().apply {
                    put(MediaStore.Images.Media.DISPLAY_NAME, name)
                    put(MediaStore.Images.Media.MIME_TYPE, "image/png")
                    put(MediaStore.Images.Media.RELATIVE_PATH, Environment.DIRECTORY_PICTURES + "/StegoSuite")
                    put(MediaStore.Images.Media.IS_PENDING, 1)
                }
                val uri = context.contentResolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, values)
                    ?: return false
                context.contentResolver.openOutputStream(uri)?.use { it.write(bytes) }
                values.clear()
                values.put(MediaStore.Images.Media.IS_PENDING, 0)
                context.contentResolver.update(uri, values, null, null)
            } else {
                val dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_PICTURES)
                val stegoDir = File(dir, "StegoSuite").also { if (!it.exists()) it.mkdirs() }
                val file = File(stegoDir, name)
                FileOutputStream(file).use { it.write(bytes) }
            }

            Toast.makeText(context, "Saved to Pictures/StegoSuite", Toast.LENGTH_SHORT).show()
            true
        } catch (e: Exception) {
            Toast.makeText(context, "Save failed: ${e.message}", Toast.LENGTH_LONG).show()
            false
        }
    }

    @JavascriptInterface
    fun saveExtractedFile(fileBase64: String, filename: String, mimeType: String): Boolean {
        return try {
            val bytes = Base64.decode(fileBase64, Base64.DEFAULT)
            val cleanName = filename.ifEmpty { "extracted_secret.bin" }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val values = ContentValues().apply {
                    put(MediaStore.Downloads.DISPLAY_NAME, cleanName)
                    put(MediaStore.Downloads.MIME_TYPE, mimeType.ifEmpty { "application/octet-stream" })
                    put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/StegoSuite")
                    put(MediaStore.Downloads.IS_PENDING, 1)
                }
                val uri = context.contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                    ?: return false
                context.contentResolver.openOutputStream(uri)?.use { it.write(bytes) }
                values.clear()
                values.put(MediaStore.Downloads.IS_PENDING, 0)
                context.contentResolver.update(uri, values, null, null)
            } else {
                val dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
                val stegoDir = File(dir, "StegoSuite").also { if (!it.exists()) it.mkdirs() }
                val file = File(stegoDir, cleanName)
                FileOutputStream(file).use { it.write(bytes) }
            }

            Toast.makeText(context, "File saved to Downloads/StegoSuite/$cleanName", Toast.LENGTH_LONG).show()
            true
        } catch (e: Exception) {
            Toast.makeText(context, "Save failed: ${e.message}", Toast.LENGTH_LONG).show()
            false
        }
    }

    @JavascriptInterface
    fun shareFile(base64Data: String, filename: String, mimeType: String) {
        try {
            val bytes = Base64.decode(base64Data, Base64.DEFAULT)
            val cacheFile = File(context.cacheDir, filename)
            FileOutputStream(cacheFile).use { it.write(bytes) }

            val uri = FileProvider.getUriForFile(
                context,
                "${context.packageName}.fileprovider",
                cacheFile
            )

            val shareIntent = Intent(Intent.ACTION_SEND).apply {
                type = mimeType.ifEmpty { "*/*" }
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            context.startActivity(Intent.createChooser(shareIntent, "Share Stego File").apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            })
        } catch (e: Exception) {
            Toast.makeText(context, "Share error: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }
}
