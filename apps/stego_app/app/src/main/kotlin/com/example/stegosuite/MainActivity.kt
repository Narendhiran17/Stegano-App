package com.example.stegosuite

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.MediaStore
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.FileProvider
import java.io.File

class MainActivity : ComponentActivity() {

    private lateinit var webView: WebView
    private var filePathCallback: ValueCallback<Array<Uri>>? = null
    private var cameraImageUri: Uri? = null

    private val filePickerLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            val data = result.data
            var uris = WebChromeClient.FileChooserParams.parseResult(result.resultCode, data)
            if (uris == null && cameraImageUri != null) {
                val photoFile = File(cacheDir, "camera_capture.png")
                if (photoFile.exists() && photoFile.length() > 0) {
                    uris = arrayOf(cameraImageUri!!)
                }
            }
            filePathCallback?.onReceiveValue(uris)
        } else {
            filePathCallback?.onReceiveValue(null)
        }
        filePathCallback = null
        cameraImageUri = null
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
                    val acceptsImage = fileChooserParams?.acceptTypes?.any { it.contains("image") } == true

                    try {
                        val photoFile = File(cacheDir, "camera_capture.png")
                        if (photoFile.exists()) photoFile.delete()
                        photoFile.createNewFile()

                        cameraImageUri = FileProvider.getUriForFile(
                            this@MainActivity,
                            "${packageName}.fileprovider",
                            photoFile
                        )

                        val takePictureIntent = Intent(MediaStore.ACTION_IMAGE_CAPTURE).apply {
                            putExtra(MediaStore.EXTRA_OUTPUT, cameraImageUri)
                            addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION or Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        }

                        val chooserIntent: Intent
                        if (isCapture) {
                            chooserIntent = takePictureIntent
                        } else {
                            val pickIntent = fileChooserParams?.createIntent() ?: Intent(Intent.ACTION_GET_CONTENT).apply {
                                type = if (acceptsImage) "image/*" else "*/*"
                                addCategory(Intent.CATEGORY_OPENABLE)
                            }
                            chooserIntent = Intent.createChooser(pickIntent, "Choose Carrier or Photo").apply {
                                if (acceptsImage) {
                                    putExtra(Intent.EXTRA_INITIAL_INTENTS, arrayOf(takePictureIntent))
                                }
                            }
                        }

                        filePickerLauncher.launch(chooserIntent)
                    } catch (e: Exception) {
                        this@MainActivity.filePathCallback = null
                        this@MainActivity.cameraImageUri = null
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
