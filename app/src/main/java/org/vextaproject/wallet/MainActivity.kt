package org.vextaproject.wallet

import android.app.Activity
import android.graphics.Color
import android.os.Bundle
import android.view.Gravity
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

class MainActivity : Activity() {

    private lateinit var status: TextView

    companion object {
        private const val PORT = 19333
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        if (intent.getBooleanExtra("sync_only", false)) {
            window.setBackgroundDrawableResource(
                android.R.color.transparent
            )

            startSync()
            return
        }

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(48, 100, 48, 100)
            setBackgroundColor(Color.rgb(7, 24, 46))
        }

        val title = TextView(this).apply {
            text = "Vexta Wallet"
            textSize = 32f
            setTextColor(Color.WHITE)
            gravity = Gravity.CENTER
        }

        status = TextView(this).apply {
            text = "\nLoading and verifying cached headers..."
            textSize = 16f
            setTextColor(Color.LTGRAY)
            gravity = Gravity.CENTER
        }

        layout.addView(title)
        layout.addView(status)

        setContentView(
            ScrollView(this).apply {
                addView(layout)
            }
        )

        startSync()
    }

    private fun startSync() {
        Thread {
            try {
                val chain = HeaderSync.loadCachedChain(this)
                val cachedAtStart = chain.last().height

                val peers = listOf(
                    "87.106.99.23",
                    "74.208.53.160"
                )

                val results = mutableListOf<String>()
                var successfulPeerSyncs = 0

                for (peer in peers) {
                    try {
                        val result =
                            HeaderSync.syncFromPeer(peer, chain)

                        if (result.received > 0) {
                            HeaderSync.saveChain(this, chain)
                        }

                        successfulPeerSyncs++

                        results.add(
                            "$peer:$PORT\n" +
                                "Handshake: successful\n" +
                                "Headers received: ${result.received}\n" +
                                "Cached before: ${result.cachedBefore}\n" +
                                "Verified height: ${result.chainHeight}\n" +
                                "Proof of work: valid\n" +
                                "Difficulty rules: valid\n" +
                                "Chain linkage: valid\n\n" +
                                "Tip hash:\n${result.lastHash}"
                        )
                    } catch (e: Exception) {
                        results.add(
                            "$peer:$PORT\nFailed: " +
                                (e.message
                                    ?: e.javaClass.simpleName)
                        )
                    }
                }

                runOnUiThread {
                    if (
                        intent.getBooleanExtra(
                            "sync_only",
                            false
                        )
                    ) {
                        if (
                            successfulPeerSyncs > 0 &&
                            chain.last().height > 0
                        ) {
                            setResult(
                                RESULT_OK,
                                android.content.Intent()
                                    .putExtra(
                                        "verified_height",
                                        chain.last().height
                                    )
                            )
                        } else {
                            setResult(
                                RESULT_CANCELED,
                                android.content.Intent()
                                    .putExtra(
                                        "sync_error",
                                        results.joinToString(
                                            "\n\n"
                                        )
                                    )
                            )
                        }

                        finish()
                    } else {
                        status.text =
                            "\nVexta SPV verification\n\n" +
                                "Initial cached height: " +
                                "$cachedAtStart\n" +
                                "Stored header file: " +
                                "${chain.last().height} blocks\n\n" +
                                results.joinToString(
                                    "\n\n--------------------\n\n"
                                )
                    }
                }
            } catch (e: Exception) {
                runOnUiThread {
                    if (
                        intent.getBooleanExtra(
                            "sync_only",
                            false
                        )
                    ) {
                        setResult(
                            RESULT_CANCELED,
                            android.content.Intent()
                                .putExtra(
                                    "sync_error",
                                    e.message
                                        ?: e.javaClass.simpleName
                                )
                        )

                        finish()
                    } else {
                        status.text =
                            "\nVerification failed\n\n" +
                                (e.message
                                    ?: e.javaClass.simpleName)
                    }
                }
            }
        }.start()
    }
}
