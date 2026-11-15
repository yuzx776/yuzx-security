package com.yuzx.app.security

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.widget.Toast

/**
 * Enterprise-grade secure clipboard manager.
 * - Prevents clipboard preview leaks on Android 13+ (API 33+) via ClipDescription.EXTRA_IS_SENSITIVE.
 * - Automatically scrubs sensitive payloads (PINs, passwords, private keys, secret messages)
 *   from system clipboard after 60 seconds (Audit Problem 356).
 */
object ClipboardSecurityHelper {
    private val mainHandler = Handler(Looper.getMainLooper())

    fun copy(
        context: Context,
        label: String,
        text: String,
        isSensitive: Boolean = false,
        autoClearSeconds: Long = 60L,
        toastMessage: String? = "Copied to clipboard",
    ) {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
        val clip = ClipData.newPlainText(label, text)

        if (isSensitive && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val bundle = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
            clip.description.extras = bundle
        }

        clipboard.setPrimaryClip(clip)

        if (!toastMessage.isNullOrBlank()) {
            Toast.makeText(context, toastMessage, Toast.LENGTH_SHORT).show()
        }

        if (isSensitive && autoClearSeconds > 0) {
            mainHandler.postDelayed({
                try {
                    val currentClip = clipboard.primaryClip
                    if (currentClip != null && currentClip.itemCount > 0) {
                        val currentText = currentClip.getItemAt(0)?.text?.toString()
                        if (currentText == text || currentClip.description.label == label) {
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                                clipboard.clearPrimaryClip()
                            } else {
                                clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
                            }
                        }
                    }
                } catch (ignored: Exception) {
                    // Clipboard access restricted or app backgrounded
                }
            }, autoClearSeconds * 1000L)
        }
    }
}
