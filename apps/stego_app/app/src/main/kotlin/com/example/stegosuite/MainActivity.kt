package com.example.stegosuite

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Matrix
import android.media.ExifInterface
import android.net.Uri
import android.os.Bundle
import android.provider.MediaStore
import android.util.Base64
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import java.io.ByteArrayOutputStream
import java.io.File

class MainActivity : ComponentActivity() {

    private lateinit var webView: WebView
    private var filePathCallback: ValueCallback<Array<Uri>>? = null
    private var photoFile: File? = null
    private var photoUri: Uri? = null

    private val filePickerLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            val data = result.data
            var uris = WebChromeClient.FileChooserParams.parseResult(result.resultCode, data)
            if (uris == null && photoUri != null && photoFile != null && photoFile!!.exists() && photoFile!!.length() > 0) {
                uris = arrayOf(photoUri!!)
            }
            filePathCallback?.onReceiveValue(uris)
        } else {
            filePathCallback?.onReceiveValue(null)
        }
        filePathCallback = null
        photoUri = null
    }

    private val cameraPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        if (isGranted) {
            launchNativeCamera()
        } else {
            Toast.makeText(this, "Camera permission is required to capture photos", Toast.LENGTH_SHORT).show()
        }
    }

    private val nativeCameraLauncher = registerForActivityResult(
        ActivityResultContracts.TakePicture()
    ) { success ->
        val file = photoFile
        if (success && file != null && file.exists() && file.length() > 0) {
            processAndDeliverCapturedPhoto(file)
        } else {
            Toast.makeText(this, "No photo captured", Toast.LENGTH_SHORT).show()
        }
    }

    fun requestCameraAndCapture() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
            launchNativeCamera()
        } else {
            cameraPermissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    private fun launchNativeCamera() {
        try {
            val file = File(cacheDir, "camera_carrier.jpg")
            if (file.exists()) file.delete()
            file.createNewFile()
            photoFile = file

            photoUri = FileProvider.getUriForFile(
                this,
                "${packageName}.fileprovider",
                file
            )

            nativeCameraLauncher.launch(photoUri!!)
        } catch (e: Exception) {
            Toast.makeText(this, "Failed to launch camera: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun processAndDeliverCapturedPhoto(file: File) {
        try {
            var bitmap = BitmapFactory.decodeFile(file.absolutePath)
                ?: throw IllegalStateException("Could not decode camera image")

            // Correct EXIF orientation
            try {
                val exif = ExifInterface(file.absolutePath)
                val orientation = exif.getAttributeInt(ExifInterface.TAG_ORIENTATION, ExifInterface.ORIENTATION_NORMAL)
                val rotationAngle = when (orientation) {
                    ExifInterface.ORIENTATION_ROTATE_90 -> 90f
                    ExifInterface.ORIENTATION_ROTATE_180 -> 180f
                    ExifInterface.ORIENTATION_ROTATE_270 -> 270f
                    else -> 0f
                }

                if (rotationAngle != 0f) {
                    val matrix = Matrix().apply { postRotate(rotationAngle) }
                    bitmap = Bitmap.createBitmap(bitmap, 0, 0, bitmap.width, bitmap.height, matrix, true)
                }
            } catch (_: Exception) {}

            // Cap dimensions to 2560px for fast embedding and optimal memory
            val maxDim = maxOf(bitmap.width, bitmap.height)
            if (maxDim > 2560) {
                val scale = 2560f / maxDim
                bitmap = Bitmap.createScaledBitmap(
                    bitmap,
                    (bitmap.width * scale).toInt(),
                    (bitmap.height * scale).toInt(),
                    true
                )
            }

            val bos = ByteArrayOutputStream()
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, bos)
            val bytes = bos.toByteArray()
            val base64 = Base64.encodeToString(bytes, Base64.NO_WRAP)

            runOnUiThread {
                webView.evaluateJavascript("window.setCarrierFromDataUrl('data:image/png;base64,$base64')", null)
                Toast.makeText(this, "Photo captured: ${bitmap.width}x${bitmap.height} px", Toast.LENGTH_SHORT).show()
            }
        } catch (e: Exception) {
            Toast.makeText(this, "Photo processing error: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        webView = WebView(this).apply {
            settings.apply {
                javaScriptEnabled = true
                domStorageEnabled = true
                allowFileAccess = true
                allowContentAccess = true
                useWideViewPort = true
                loadWithOverviewMode = true
                cacheMode = WebSettings.LOAD_DEFAULT
            }

            webViewClient = WebViewClient()
            webChromeClient = object : WebChromeClient() {
                override fun onShowFileChooser(
                    webView: WebView?,
                    filePathCallback: ValueCallback<Array<Uri>>?,
                    fileChooserParams: FileChooserParams?
                ): Boolean {
                    this@MainActivity.filePathCallback?.onReceiveValue(null)
                    this@MainActivity.filePathCallback = filePathCallback

                    val isCapture = fileChooserParams?.isCaptureEnabled == true
                    if (isCapture) {
                        requestCameraAndCapture()
                        return true
                    }

                    try {
                        val pickIntent = fileChooserParams?.createIntent() ?: Intent(Intent.ACTION_GET_CONTENT).apply {
                            type = "*/*"
                            addCategory(Intent.CATEGORY_OPENABLE)
                        }
                        filePickerLauncher.launch(Intent.createChooser(pickIntent, "Choose File"))
                    } catch (e: Exception) {
                        this@MainActivity.filePathCallback = null
                        return false
                    }
                    return true
                }
            }

            addJavascriptInterface(StegoBridge(this@MainActivity), "AndroidBridge")
            loadUrl("file:///android_asset/index.html")
        }

        setContentView(webView)
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        if (webView.canGoBack()) {
            webView.goBack()
        } else {
            super.onBackPressed()
        }
    }
}
