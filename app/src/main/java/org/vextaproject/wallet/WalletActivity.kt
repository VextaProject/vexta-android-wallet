package org.vextaproject.wallet

import androidx.fragment.app.FragmentActivity
import androidx.activity.OnBackPressedCallback
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import android.app.PendingIntent
import android.app.NotificationManager
import android.app.NotificationChannel
import android.app.Notification
import android.Manifest
import android.app.DownloadManager
import android.app.AlertDialog
import android.content.ClipData
import android.content.BroadcastReceiver
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.MotionEvent
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import com.google.zxing.BarcodeFormat
import com.google.zxing.MultiFormatWriter
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import org.bitcoinj.core.Base58
import org.json.JSONObject
import org.bitcoinj.core.ECKey
import org.bitcoinj.core.Sha256Hash
import org.bitcoinj.core.Utils
import org.bitcoinj.crypto.ChildNumber
import org.bitcoinj.crypto.DeterministicHierarchy
import org.bitcoinj.crypto.HDKeyDerivation
import org.bitcoinj.crypto.MnemonicCode
import java.security.KeyStore
import java.security.MessageDigest
import java.math.BigDecimal
import java.math.RoundingMode
import java.net.HttpURLConnection
import java.net.URL
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class WalletActivity : FragmentActivity() {

    companion object {
        private const val PREFS = "vexta_wallet"
        private const val KEY_ALIAS = "vexta_wallet_seed_key"
        private const val PREF_CIPHERTEXT = "seed_ciphertext"
        private const val PREF_IV = "seed_iv"
        private const val PREF_BACKUP_CONFIRMED = "backup_confirmed"
        private const val UPDATE_URL =
            "https://vexta-pool.co.uk/vexta-wallet-version.json"
        private const val REQUEST_HEADER_SYNC = 4101
        private const val REQUEST_NOTIFICATIONS = 4102
        private const val PAYMENT_CHANNEL_ID =
            "vexta_incoming_payments"
        private const val PREF_LAST_CONFIRMED_BALANCE =
            "last_confirmed_balance"
        private const val PREF_BALANCE_INITIALIZED =
            "balance_notification_initialized"
        private const val PREF_KNOWN_INCOMING_TXIDS =
            "known_incoming_txids"
        private const val PREF_TX_NOTIFICATIONS_INITIALIZED =
            "tx_notifications_initialized"
        private const val PREF_RECEIVE_ADDRESS_INDEX =
            "receive_address_index"
        private const val PREF_RESTORE_ADDRESS_DISCOVERY =
            "restore_address_discovery"
        private const val RESTORE_ADDRESS_LOOKAHEAD = 20
    }

    private val backgroundColor = Color.rgb(2, 8, 23)
    private val surfaceColor = Color.rgb(8, 22, 45)
    private val surfaceColorAlt = Color.rgb(13, 38, 67)
    private val accentColor = Color.rgb(0, 210, 255)
    private val accentDark = Color.rgb(0, 119, 255)
    private val neonPurple = Color.rgb(127, 90, 240)
    private val successColor = Color.rgb(36, 220, 151)
    private val textPrimary = Color.rgb(242, 248, 255)
    private val textSecondary = Color.rgb(143, 168, 200)
    private val dangerColor = Color.rgb(255, 73, 106)
    private var sendRecipientInput: EditText? = null
    private var blockchainScanStatus: TextView? = null
    private var walletBalanceView: TextView? = null
    private var walletHistoryView: TextView? = null
    private var latestWalletTransactions =
        emptyList<BlockScanner.WalletTransaction>()
    private var transactionHistoryFilter = "ALL"
    private var transactionHistoryLimit = 50
    private var transactionHistoryVisible = false
    private var mainWalletVisible = false
    private var automaticScanStarted = false
    private var blockchainScanRunning = false
    private var sendInProgress = false
    private var lastExitSwipeAt = 0L
    private var latestSpendableUtxos =
        emptyList<BlockScanner.SpendableUtxo>()

    private val refreshHandler = Handler(Looper.getMainLooper())

    private val refreshRunnable = object : Runnable {
        override fun run() {
            if (
                !isFinishing &&
                !isDestroyed &&
                walletExists() &&
                !blockchainScanRunning
            ) {
                if (hasWindowFocus()) {
                    startHeaderSyncAndScan()
                } else {
                    startBackgroundHeaderSyncAndScan()
                }
            }

            refreshHandler.postDelayed(this, 60_000L)
        }
    }
    private var updateDownloadId = -1L
    private var pendingUpdateUri: Uri? = null
    private var pendingUpdateSha256: String? = null

    private val updateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (
                intent?.action != DownloadManager.ACTION_DOWNLOAD_COMPLETE
            ) {
                return
            }

            val completedId = intent.getLongExtra(
                DownloadManager.EXTRA_DOWNLOAD_ID,
                -1L
            )

            if (completedId != updateDownloadId) {
                return
            }

            val manager = getSystemService(
                DOWNLOAD_SERVICE
            ) as DownloadManager

            val query = DownloadManager.Query()
                .setFilterById(completedId)

            manager.query(query)?.use { cursor ->
                if (!cursor.moveToFirst()) {
                    Toast.makeText(
                        this@WalletActivity,
                        "Downloaded update could not be found",
                        Toast.LENGTH_LONG
                    ).show()
                    return
                }

                val statusIndex = cursor.getColumnIndex(
                    DownloadManager.COLUMN_STATUS
                )

                val status = cursor.getInt(statusIndex)

                if (status != DownloadManager.STATUS_SUCCESSFUL) {
                    Toast.makeText(
                        this@WalletActivity,
                        "Update download failed",
                        Toast.LENGTH_LONG
                    ).show()
                    return
                }

                val downloadedUri =
                    manager.getUriForDownloadedFile(completedId)

                if (downloadedUri == null) {
                    Toast.makeText(
                        this@WalletActivity,
                        "Downloaded update could not be opened",
                        Toast.LENGTH_LONG
                    ).show()
                    return
                }

                val expectedSha256 =
                    pendingUpdateSha256?.trim()?.lowercase()

                if (
                    expectedSha256.isNullOrBlank() ||
                    !verifyDownloadedUpdate(
                        downloadedUri,
                        expectedSha256
                    )
                ) {
                    manager.remove(completedId)
                    pendingUpdateUri = null
                    pendingUpdateSha256 = null

                    AlertDialog.Builder(this@WalletActivity)
                        .setTitle("Update verification failed")
                        .setMessage(
                            "The downloaded APK does not match the " +
                                "official SHA256 checksum and was deleted. " +
                                "The update will not be installed."
                        )
                        .setPositiveButton("Close", null)
                        .show()

                    return
                }

                pendingUpdateUri = downloadedUri
                openDownloadedUpdate()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        onBackPressedDispatcher.addCallback(
            this,
            object : OnBackPressedCallback(true) {
                override fun handleOnBackPressed() {
                    if (!walletExists()) {
                        isEnabled = false
                        onBackPressedDispatcher.onBackPressed()
                        isEnabled = true
                        return
                    }

                    if (!mainWalletVisible) {
                        showMainWallet()
                        return
                    }

                    val now = System.currentTimeMillis()

                    if (now - lastExitSwipeAt <= 2_000L) {
                        stopService(
                            Intent(
                                this@WalletActivity,
                                WalletMonitoringService::class.java
                            )
                        )
                        finishAndRemoveTask()
                    } else {
                        lastExitSwipeAt = now
                        Toast.makeText(
                            this@WalletActivity,
                            "Swipe again to exit",
                            Toast.LENGTH_SHORT
                        ).show()
                    }
                }
            }
        )

        createPaymentNotificationChannel()
        requestNotificationPermission()

        val monitoringIntent =
            Intent(this, WalletMonitoringService::class.java)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(monitoringIntent)
        } else {
            startService(monitoringIntent)
        }

        val filter = IntentFilter(
            DownloadManager.ACTION_DOWNLOAD_COMPLETE
        )

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(
                updateReceiver,
                filter,
                Context.RECEIVER_NOT_EXPORTED
            )
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(updateReceiver, filter)
        }

        if (walletExists()) {
            authenticateWallet(
                title = "Unlock Vexta Wallet",
                subtitle = "Use biometrics or your device screen lock"
            ) {
                showMainWallet()
            }
        } else {
            showWelcome()
        }

        checkForUpdates()
    }

    override fun onResume() {
        super.onResume()

        if (
            Build.VERSION.SDK_INT < Build.VERSION_CODES.O ||
            packageManager.canRequestPackageInstalls()
        ) {
            if (pendingUpdateUri != null) {
                openDownloadedUpdate()
            }
        }

        if (
            walletExists() &&
            mainWalletVisible &&
            !blockchainScanRunning
        ) {
            window.decorView.postDelayed({
                if (
                    !isFinishing &&
                    !isDestroyed &&
                    mainWalletVisible &&
                    !blockchainScanRunning
                ) {
                    startHeaderSyncAndScan()
                }
            }, 400L)
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        if (!walletExists()) {
            super.onBackPressed()
            return
        }

        if (!mainWalletVisible) {
            showMainWallet()
            return
        }

        val now = System.currentTimeMillis()

        if (now - lastExitSwipeAt <= 2_000L) {
            stopService(
                Intent(
                    this,
                    WalletMonitoringService::class.java
                )
            )
            finishAndRemoveTask()
        } else {
            lastExitSwipeAt = now
            Toast.makeText(
                this,
                "Swipe again to exit",
                Toast.LENGTH_SHORT
            ).show()
        }
    }

    override fun onDestroy() {
        refreshHandler.removeCallbacks(refreshRunnable)

        try {
            unregisterReceiver(updateReceiver)
        } catch (_: IllegalArgumentException) {
        }

        super.onDestroy()
    }

    private fun createPaymentNotificationChannel() {
        val manager =
            getSystemService(
                Context.NOTIFICATION_SERVICE
            ) as NotificationManager

        val channel = NotificationChannel(
            PAYMENT_CHANNEL_ID,
            "Incoming VTX payments",
            NotificationManager.IMPORTANCE_HIGH
        ).apply {
            description =
                "Notifications when new confirmed VTX payments arrive"
            enableVibration(true)
        }

        manager.createNotificationChannel(channel)
    }

    private fun requestNotificationPermission() {
        if (
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(
                Manifest.permission.POST_NOTIFICATIONS
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(
                arrayOf(Manifest.permission.POST_NOTIFICATIONS),
                REQUEST_NOTIFICATIONS
            )
        }
    }

    private fun updateIncomingTransactionsAndNotify(
        transactions: List<BlockScanner.WalletTransaction>
    ) {
        val preferences =
            getSharedPreferences(PREFS, Context.MODE_PRIVATE)

        val incoming =
            transactions.filter { it.netSatoshis > 0L }

        val currentTxids =
            incoming.map { it.txid }.toSet()

        val initialized = preferences.getBoolean(
            PREF_TX_NOTIFICATIONS_INITIALIZED,
            false
        )

        if (!initialized) {
            preferences.edit()
                .putBoolean(PREF_TX_NOTIFICATIONS_INITIALIZED, true)
                .putStringSet(
                    PREF_KNOWN_INCOMING_TXIDS,
                    currentTxids
                )
                .apply()
            return
        }

        val knownTxids =
            preferences.getStringSet(
                PREF_KNOWN_INCOMING_TXIDS,
                emptySet()
            )?.toMutableSet() ?: mutableSetOf()

        incoming
            .filter { it.txid !in knownTxids }
            .sortedBy { it.height }
            .forEach { transaction ->
                showIncomingPaymentNotification(
                    transaction.netSatoshis
                )
                knownTxids.add(transaction.txid)
            }

        preferences.edit()
            .putStringSet(
                PREF_KNOWN_INCOMING_TXIDS,
                knownTxids
            )
            .apply()
    }

    private fun showIncomingPaymentNotification(
        receivedSatoshis: Long
    ) {
        if (
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(
                Manifest.permission.POST_NOTIFICATIONS
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            return
        }

        val amount = String.format(
            "%.8f",
            receivedSatoshis.toDouble() / 100_000_000.0
        )

        val openWalletIntent = Intent(
            this,
            WalletActivity::class.java
        ).apply {
            flags =
                Intent.FLAG_ACTIVITY_CLEAR_TOP or
                    Intent.FLAG_ACTIVITY_SINGLE_TOP
        }

        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            openWalletIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or
                PendingIntent.FLAG_IMMUTABLE
        )

        val notification = Notification.Builder(
            this,
            PAYMENT_CHANNEL_ID
        )
            .setSmallIcon(android.R.drawable.stat_notify_more)
            .setContentTitle("VTX payment received")
            .setContentText("$amount VTX has been confirmed")
            .setStyle(
                Notification.BigTextStyle().bigText(
                    "A payment of $amount VTX was received " +
                        "and confirmed in your Vexta Wallet."
                )
            )
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setCategory(Notification.CATEGORY_MESSAGE)
            .build()

        val manager =
            getSystemService(
                Context.NOTIFICATION_SERVICE
            ) as NotificationManager

        manager.notify(
            (System.currentTimeMillis() and 0x7fffffff).toInt(),
            notification
        )
    }

    private fun checkForUpdates() {
        Thread {
            try {
                val connection = (
                    URL(UPDATE_URL).openConnection()
                        as HttpURLConnection
                ).apply {
                    connectTimeout = 8000
                    readTimeout = 8000
                    requestMethod = "GET"
                    useCaches = false
                }

                val responseCode = connection.responseCode

                if (responseCode !in 200..299) {
                    connection.disconnect()
                    return@Thread
                }

                val response = connection.inputStream
                    .bufferedReader()
                    .use { it.readText() }

                connection.disconnect()

                val json = JSONObject(response)
                val latestCode = json.getLong("versionCode")
                val latestName = json.optString(
                    "versionName",
                    latestCode.toString()
                )
                val apkUrl = json.optString(
                    "apkUrl",
                    json.optString("downloadUrl")
                )

                require(apkUrl.isNotBlank()) {
                    "Missing update download URL"
                }
                val sha256 = json.getString("sha256")
                    .trim()
                    .lowercase()

                require(
                    sha256.matches(Regex("^[0-9a-f]{64}$"))
                ) {
                    "Invalid update SHA256"
                }

                val notes = json.optString(
                    "notes",
                    json.optString(
                        "releaseNotes",
                        "A new Vexta Wallet version is available."
                    )
                )

                val currentCode = if (
                    Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
                ) {
                    packageManager.getPackageInfo(
                        packageName,
                        0
                    ).longVersionCode
                } else {
                    @Suppress("DEPRECATION")
                    packageManager.getPackageInfo(
                        packageName,
                        0
                    ).versionCode.toLong()
                }

                if (latestCode <= currentCode) {
                    return@Thread
                }

                runOnUiThread {
                    if (isFinishing || isDestroyed) {
                        return@runOnUiThread
                    }

                    AlertDialog.Builder(this)
                        .setTitle("Wallet update available")
                        .setMessage(
                            "Version $latestName is available.\n\n" +
                                notes
                        )
                        .setNegativeButton("Later", null)
                        .setPositiveButton("Update") { _, _ ->
                            downloadUpdate(
                                apkUrl,
                                latestName,
                                sha256
                            )
                        }
                        .show()
                }
            } catch (_: Exception) {
                // Update checks must never prevent wallet startup.
            }
        }.start()
    }

    private fun downloadUpdate(
        apkUrl: String,
        versionName: String,
        expectedSha256: String
    ) {
        try {
            val manager = getSystemService(
                DOWNLOAD_SERVICE
            ) as DownloadManager

            val request = DownloadManager.Request(
                Uri.parse(apkUrl)
            ).apply {
                setTitle("Vexta Wallet $versionName")
                setDescription("Downloading wallet update")
                setMimeType(
                    "application/vnd.android.package-archive"
                )
                setNotificationVisibility(
                    DownloadManager.Request
                        .VISIBILITY_VISIBLE_NOTIFY_COMPLETED
                )
                setAllowedOverMetered(true)
                setAllowedOverRoaming(false)
                setDestinationInExternalFilesDir(
                    this@WalletActivity,
                    Environment.DIRECTORY_DOWNLOADS,
                    "vexta-wallet-update.apk"
                )
            }

            pendingUpdateSha256 =
                expectedSha256.trim().lowercase()
            pendingUpdateUri = null

            updateDownloadId = manager.enqueue(request)

            Toast.makeText(
                this,
                "Downloading wallet update",
                Toast.LENGTH_LONG
            ).show()
        } catch (error: Exception) {
            Toast.makeText(
                this,
                "Could not start update: ${error.message}",
                Toast.LENGTH_LONG
            ).show()
        }
    }

    private fun verifyDownloadedUpdate(
        apkUri: Uri,
        expectedSha256: String
    ): Boolean {
        return try {
            val digest = MessageDigest.getInstance("SHA-256")

            contentResolver.openInputStream(apkUri)?.use { input ->
                val buffer = ByteArray(64 * 1024)

                while (true) {
                    val count = input.read(buffer)

                    if (count < 0) {
                        break
                    }

                    if (count > 0) {
                        digest.update(buffer, 0, count)
                    }
                }
            } ?: return false

            val actualSha256 = digest.digest()
                .joinToString("") {
                    "%02x".format(it.toInt() and 0xff)
                }

            actualSha256.equals(
                expectedSha256,
                ignoreCase = true
            )
        } catch (_: Exception) {
            false
        }
    }

    private fun openDownloadedUpdate() {
        val apkUri = pendingUpdateUri ?: return

        if (
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
            !packageManager.canRequestPackageInstalls()
        ) {
            AlertDialog.Builder(this)
                .setTitle("Allow wallet updates")
                .setMessage(
                    "Android must allow Vexta Wallet to install " +
                        "updates. Enable “Allow from this source”, " +
                        "then return to the wallet."
                )
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Open settings") { _, _ ->
                    startActivity(
                        Intent(
                            Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                            Uri.parse("package:$packageName")
                        )
                    )
                }
                .show()

            return
        }

        val installIntent = Intent(
            Intent.ACTION_VIEW
        ).apply {
            setDataAndType(
                apkUri,
                "application/vnd.android.package-archive"
            )
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }

        try {
            startActivity(installIntent)
            pendingUpdateUri = null
            pendingUpdateSha256 = null
        } catch (error: Exception) {
            Toast.makeText(
                this,
                "Could not open update installer: ${error.message}",
                Toast.LENGTH_LONG
            ).show()
        }
    }

    private fun startBackgroundHeaderSyncAndScan() {
        if (blockchainScanRunning) {
            return
        }

        blockchainScanRunning = true

        Thread {
            try {
                val chain = HeaderSync.loadCachedChain(this)

                for (peer in listOf("87.106.99.23", "74.208.53.160")) {
                    try {
                        val result = HeaderSync.syncFromPeer(peer, chain)

                        if (result.received > 0) {
                            HeaderSync.saveChain(this, chain)
                        }
                    } catch (_: Exception) {
                    }
                }

                runOnUiThread {
                    runBlockchainScan()
                }
            } catch (_: Exception) {
                runOnUiThread {
                    blockchainScanRunning = false
                }
            }
        }.start()
    }

    private fun startHeaderSyncAndScan() {
        if (blockchainScanRunning) {
            return
        }

        blockchainScanRunning = true

        blockchainScanStatus?.text =
            "Synchronizing block headers..."

        startActivityForResult(
            Intent(
                this,
                MainActivity::class.java
            ).putExtra("sync_only", true),
            REQUEST_HEADER_SYNC
        )

        overridePendingTransition(0, 0)
    }

    override fun onActivityResult(
        requestCode: Int,
        resultCode: Int,
        data: Intent?
    ) {
        if (requestCode == REQUEST_HEADER_SYNC) {
            overridePendingTransition(0, 0)

            if (resultCode == RESULT_OK) {
                val height = data?.getIntExtra(
                    "verified_height",
                    -1
                ) ?: -1

                blockchainScanStatus?.text = if (height >= 0) {
                    "Headers synchronized to block $height.\n" +
                        "Scanning compact filters..."
                } else {
                    "Headers synchronized.\n" +
                        "Scanning compact filters..."
                }

                runBlockchainScan()
            } else {
                blockchainScanRunning = false
                blockchainScanStatus?.text =
                    "Block-header synchronization failed."
            }

            return
        }

        super.onActivityResult(requestCode, resultCode, data)
    }

    private fun currentReceiveAddressIndex(): Int {
        return getSharedPreferences(PREFS, MODE_PRIVATE)
            .getInt(PREF_RECEIVE_ADDRESS_INDEX, 0)
            .coerceAtLeast(0)
    }

    private fun setCurrentReceiveAddressIndex(index: Int) {
        getSharedPreferences(PREFS, MODE_PRIVATE)
            .edit()
            .putInt(PREF_RECEIVE_ADDRESS_INDEX, index.coerceAtLeast(0))
            .apply()
    }

    private fun runBlockchainScan() {
        Thread {
            try {
                val words = loadMnemonic()
                    .trim()
                    .split(Regex("\\s+"))

                val preferences =
                    getSharedPreferences(PREFS, MODE_PRIVATE)
                val restoreAddressDiscovery =
                    preferences.getBoolean(
                        PREF_RESTORE_ADDRESS_DISCOVERY,
                        false
                    )
                val highestAddressIndex =
                    if (restoreAddressDiscovery) {
                        maxOf(
                            currentReceiveAddressIndex(),
                            RESTORE_ADDRESS_LOOKAHEAD
                        )
                    } else {
                        currentReceiveAddressIndex()
                    }

                var highestUsedAddressIndex = -1

                val allUtxos =
                    mutableListOf<BlockScanner.SpendableUtxo>()
                val allTransactions =
                    mutableListOf<BlockScanner.WalletTransaction>()

                var totalFiltersScanned = 0
                var totalRelevantBlocks = 0
                var totalReceivedTransactions = 0
                var totalSpentTransactions = 0

                for (addressIndex in 0..highestAddressIndex) {
                    val scriptPubKey =
                        deriveWitnessScript(words, addressIndex)

                    runOnUiThread {
                        blockchainScanStatus?.text =
                            "Scanning address " +
                                "${addressIndex + 1} of " +
                                "${highestAddressIndex + 1}..."
                    }

                    val filterResult = CompactFilterClient.scan(
                        this@WalletActivity,
                        "87.106.99.23",
                        scriptPubKey
                    ) { scanned, total ->
                        runOnUiThread {
                            blockchainScanStatus?.text =
                                "Address ${addressIndex + 1}/" +
                                    "${highestAddressIndex + 1}\n" +
                                    "Scanning compact filters: " +
                                    "$scanned / $total"
                        }
                    }

                    totalFiltersScanned +=
                        filterResult.scannedFilters

                    val blockResult = BlockScanner.scan(
                        this@WalletActivity,
                        "87.106.99.23",
                        filterResult.matchingHeights,
                        scriptPubKey,
                        addressIndex
                    ) { downloaded, total ->
                        runOnUiThread {
                            blockchainScanStatus?.text =
                                "Address ${addressIndex + 1}/" +
                                    "${highestAddressIndex + 1}\n" +
                                    "Relevant blocks downloaded: " +
                                    "$downloaded / $total"
                        }
                    }

                    allUtxos.addAll(blockResult.utxos)
                    allTransactions.addAll(
                        blockResult.transactions
                    )

                    if (
                        blockResult.receivedTransactions > 0 ||
                        blockResult.spentTransactions > 0 ||
                        blockResult.transactions.isNotEmpty()
                    ) {
                        highestUsedAddressIndex = addressIndex
                    }

                    totalRelevantBlocks +=
                        blockResult.downloadedBlocks
                    totalReceivedTransactions +=
                        blockResult.receivedTransactions
                    totalSpentTransactions +=
                        blockResult.spentTransactions
                }

                val mergedTransactions =
                    allTransactions
                        .groupBy { it.txid }
                        .map { (_, transactions) ->
                            BlockScanner.WalletTransaction(
                                txid = transactions.first().txid,
                                height = transactions.maxOf {
                                    it.height
                                },
                                netSatoshis = transactions.sumOf {
                                    it.netSatoshis
                                }
                            )
                        }
                        .filter { it.netSatoshis != 0L }
                        .sortedWith(
                            compareByDescending<
                                BlockScanner.WalletTransaction
                            > {
                                it.height
                            }.thenByDescending {
                                it.txid
                            }
                        )

                val mergedUtxos =
                    allUtxos
                        .distinctBy {
                            "${it.txid}:${it.outputIndex}"
                        }
                        .sortedWith(
                            compareBy<BlockScanner.SpendableUtxo> {
                                it.height
                            }.thenBy {
                                it.txid
                            }.thenBy {
                                it.outputIndex
                            }
                        )

                val balanceSatoshis =
                    mergedUtxos.sumOf { it.value }

                val balanceText = String.format(
                    "%.8f VTX",
                    balanceSatoshis.toDouble() /
                        100_000_000.0
                )

                // Incoming notifications are handled by WalletMonitoringService.

                if (restoreAddressDiscovery) {
                    setCurrentReceiveAddressIndex(
                        highestUsedAddressIndex.coerceAtLeast(0)
                    )
                    preferences.edit()
                        .putBoolean(
                            PREF_RESTORE_ADDRESS_DISCOVERY,
                            false
                        )
                        .apply()
                }

                runOnUiThread {
                    latestSpendableUtxos = mergedUtxos
                    latestWalletTransactions =
                        mergedTransactions

                    walletBalanceView?.text = balanceText
                    walletHistoryView?.text =
                        formatTransactionHistory(
                            mergedTransactions,
                            limit = 3,
                            showFullTxid = false
                        )

                    if (transactionHistoryVisible) {
                        showTransactionHistory()
                    }

                    blockchainScanStatus?.text =
                        "Addresses scanned: " +
                            "${highestAddressIndex + 1}\n" +
                            "Filters scanned: $totalFiltersScanned\n" +
                            "Relevant blocks: $totalRelevantBlocks\n" +
                            "Received transactions: " +
                            "$totalReceivedTransactions\n" +
                            "Spent transactions: " +
                            "$totalSpentTransactions\n" +
                            "Unspent outputs: " +
                            "${mergedUtxos.size}\n" +
                            "Verified balance: $balanceText"
                }
            } catch (e: Exception) {
                runOnUiThread {
                    blockchainScanStatus?.text =
                        "Blockchain scan failed:\n" +
                            (e.message ?: e.javaClass.simpleName)
                }
            } finally {
                runOnUiThread {
                    blockchainScanRunning = false
                }
            }
        }.start()
    }

    private fun formatTransactionHistory(
        transactions: List<BlockScanner.WalletTransaction>,
        limit: Int,
        showFullTxid: Boolean
    ): String {
        if (transactions.isEmpty()) {
            return "No confirmed transactions yet"
        }

        return transactions
            .take(limit)
            .joinToString("\n\n") { transaction ->
                val received = transaction.netSatoshis > 0L
                val amount = String.format(
                    "%.8f",
                    kotlin.math.abs(
                        transaction.netSatoshis
                    ).toDouble() / 100_000_000.0
                )

                val direction =
                    if (received) "Received" else "Sent"

                val sign =
                    if (received) "+" else "-"

                val txidText =
                    if (showFullTxid) {
                        transaction.txid
                    } else {
                        transaction.txid.take(12) +
                            "..." +
                            transaction.txid.takeLast(12)
                    }

                "$direction  $sign$amount VTX\n" +
                    "Block ${transaction.height}\n" +
                    txidText
            }
    }

    private fun showTransactionHistory() {
        mainWalletVisible = false
        transactionHistoryVisible = true

        val filteredTransactions =
            when (transactionHistoryFilter) {
                "RECEIVED" -> latestWalletTransactions.filter {
                    it.netSatoshis > 0L
                }

                "SENT" -> latestWalletTransactions.filter {
                    it.netSatoshis < 0L
                }

                else -> latestWalletTransactions
            }

        val displayedTransactions =
            filteredTransactions.take(transactionHistoryLimit)

        val content = baseLayout()

        content.addView(space(10))
        content.addView(centeredLogo(64))
        content.addView(space(14))
        content.addView(title("Transaction history"))
        content.addView(
            subtitle(
                "Confirmed received and sent VTX payments"
            )
        )
        content.addView(space(20))

        content.addView(
            card {
                addView(sectionTitle("Filter"))
                addView(space(12))

                val filterRow = LinearLayout(
                    this@WalletActivity
                ).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = Gravity.CENTER
                    layoutParams = LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT
                    )
                }

                fun filterButton(
                    label: String,
                    filter: String
                ): Button {
                    val selected =
                        transactionHistoryFilter == filter

                    return Button(
                        this@WalletActivity
                    ).apply {
                        text = label
                        isAllCaps = false
                        textSize = 14f
                        typeface = Typeface.DEFAULT_BOLD
                        setTextColor(Color.WHITE)
                        setPadding(
                            dp(8),
                            dp(10),
                            dp(8),
                            dp(10)
                        )
                        background = roundedDrawable(
                            if (selected) {
                                accentColor
                            } else {
                                surfaceColorAlt
                            },
                            14
                        )
                        setOnClickListener {
                            transactionHistoryFilter = filter
                            transactionHistoryLimit = 50
                            showTransactionHistory()
                        }
                        layoutParams =
                            LinearLayout.LayoutParams(
                                0,
                                ViewGroup.LayoutParams.WRAP_CONTENT,
                                1f
                            ).apply {
                                marginEnd = dp(5)
                            }
                    }
                }

                filterRow.addView(
                    filterButton("All", "ALL")
                )
                filterRow.addView(
                    filterButton("Received", "RECEIVED")
                )
                filterRow.addView(
                    filterButton("Sent", "SENT")
                )

                addView(filterRow)
            }
        )

        content.addView(space(16))

        content.addView(
            card {
                addView(
                    sectionTitle(
                        when (transactionHistoryFilter) {
                            "RECEIVED" -> "Received payments"
                            "SENT" -> "Sent payments"
                            else -> "All transactions"
                        }
                    )
                )
                addView(space(10))

                addView(
                    smallStatus(
                        formatTransactionHistory(
                            displayedTransactions,
                            limit = displayedTransactions.size,
                            showFullTxid = true
                        )
                    ).apply {
                        gravity = Gravity.START
                        setTextIsSelectable(true)
                    }
                )

                if (
                    filteredTransactions.size >
                    displayedTransactions.size
                ) {
                    addView(space(16))
                    addView(
                        secondaryButton("Load more") {
                            transactionHistoryLimit += 50
                            showTransactionHistory()
                        }
                    )
                    addView(space(8))
                    addView(
                        helpText(
                            "Showing ${displayedTransactions.size} of " +
                                "${filteredTransactions.size}"
                        )
                    )
                } else if (filteredTransactions.isNotEmpty()) {
                    addView(space(10))
                    addView(
                        helpText(
                            "${filteredTransactions.size} transaction" +
                                if (
                                    filteredTransactions.size == 1
                                ) {
                                    ""
                                } else {
                                    "s"
                                }
                        )
                    )
                }
            }
        )

        setContentView(
            scroll(content) {
                showMainWallet()
            }
        )
    }

    private fun currentVersionName(): String {
        return try {
            packageManager.getPackageInfo(
                packageName,
                0
            ).versionName ?: "unknown"
        } catch (_: Exception) {
            "unknown"
        }
    }

    private fun showAboutDialog() {
        val message =
            "Vexta Wallet\n" +
                "Version ${currentVersionName()}\n\n" +
                "Developed for the Vexta Project\n" +
                "© 2026 Vexta Project\n\n" +
                "Website: vextaproject.org\n" +
                "Support: discord.gg/zzpm7ghN3e\n\n" +
                "Vexta Wallet is a non-custodial wallet. " +
                "Your recovery phrase is stored locally and encrypted " +
                "using Android Keystore. Keep your recovery phrase secure. " +
                "Lost recovery phrases cannot be recovered.\n\n" +
                "Open-source components:\n" +
                "• bitcoinj — Apache License 2.0\n" +
                "• ZXing — Apache License 2.0\n" +
                "• Google ML Kit Code Scanner — Google API terms"

        AlertDialog.Builder(this)
            .setTitle("About & Licences")
            .setMessage(message)
            .setPositiveButton("Close", null)
            .show()
    }

    private fun showWelcome() {
        window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)

        val content = baseLayout()

        content.addView(space(12))
        content.addView(centeredLogo(86))
        content.addView(space(18))
        content.addView(title("Vexta Wallet"))
        content.addView(
            subtitle(
                "Lightweight Android wallet for Vexta mainnet\n" +
                    "SPV headers, compact filters and secure local seed storage"
            )
        )
        content.addView(space(24))

        content.addView(
            card {
                addView(sectionTitle("Get started"))
                addView(space(10))
                addView(primaryButton("Create new wallet") {
                    createNewWallet()
                })
                addView(space(12))
                addView(secondaryButton("Restore from 12 words") {
                    showRestoreDialog()
                })
            }
        )

        setContentView(scroll(content))
    }

    private fun createNewWallet() {
        val entropy = ByteArray(16)
        SecureRandom().nextBytes(entropy)

        val words = MnemonicCode.INSTANCE.toMnemonic(entropy)
        saveMnemonic(words.joinToString(" "))

        getSharedPreferences(PREFS, MODE_PRIVATE)
            .edit()
            .putBoolean(PREF_BACKUP_CONFIRMED, false)
            .apply()

        showSeedBackup(words)
    }

    private fun showSeedBackup(words: List<String>) {
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)

        val content = baseLayout()
        content.addView(space(12))
        content.addView(centeredLogo(72))
        content.addView(space(16))
        content.addView(title("Recovery phrase"))
        content.addView(
            subtitle(
                "Write these 12 words down in the correct order.\n" +
                    "Anyone with these words can control your VTX."
            )
        )
        content.addView(space(22))

        content.addView(
            card {
                addView(sectionTitle("Your 12 words"))
                addView(space(14))

                addView(
                    infoBox(
                        words.mapIndexed { index, word ->
                            "${index + 1}. $word"
                        }.joinToString("\n"),
                        19f,
                        Gravity.START
                    )
                )
            }
        )

        content.addView(space(20))
        content.addView(
            primaryButton("I have written it down") {
                getSharedPreferences(PREFS, MODE_PRIVATE)
                    .edit()
                    .putBoolean(PREF_BACKUP_CONFIRMED, true)
                    .apply()

                window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                showMainWallet()
            }
        )

        setContentView(scroll(content))
    }

    private fun showMainWallet() {
        transactionHistoryVisible = false
        mainWalletVisible = true
        window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)

        val mnemonic = try {
            loadMnemonic()
        } catch (e: Exception) {
            showFatalError("Unable to decrypt wallet: ${e.message}")
            return
        }

        if (mnemonic.isBlank()) {
            showWelcome()
            return
        }

        val words = mnemonic.split(" ")
        val addressIndex = currentReceiveAddressIndex()
        val address = deriveAddress(words, addressIndex)

        val content = baseLayout()
        val balanceView = headlineValue("0.00000000 VTX")
        walletBalanceView = balanceView
        val compactFilterStatus = smallStatus("Compact filters: checking peers...")
        val scanStatus = smallStatus("Wallet scan: not started")
        val historyView = smallStatus("No confirmed transactions yet")

        blockchainScanStatus = scanStatus
        walletHistoryView = historyView

        content.addView(space(4))
        content.addView(centeredLogo(76))
        content.addView(space(10))
        content.addView(title("Vexta Wallet"))
        content.addView(
            subtitle("Your gateway to the Vexta network")
        )
        content.addView(space(20))

        content.addView(
            balanceCard {
                addView(
                    TextView(this@WalletActivity).apply {
                        text = "TOTAL BALANCE"
                        textSize = 12f
                        letterSpacing = 0.18f
                        setTextColor(textSecondary)
                        typeface = Typeface.DEFAULT_BOLD
                        gravity = Gravity.CENTER
                    }
                )
                addView(space(12))
                addView(balanceView)
                addView(space(8))
                addView(
                    TextView(this@WalletActivity).apply {
                        text = "VEXTA MAINNET"
                        textSize = 11f
                        letterSpacing = 0.12f
                        setTextColor(accentColor)
                        gravity = Gravity.CENTER
                        typeface = Typeface.DEFAULT_BOLD
                    }
                )
                addView(space(12))
                addView(
                    helpText(
                        "Verified through compact filters and relevant blocks"
                    )
                )
            }
        )

        content.addView(space(16))

        content.addView(
            card {
                addView(sectionTitle("Quick actions"))
                addView(space(14))

                val actionRow = LinearLayout(
                    this@WalletActivity
                ).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = Gravity.CENTER
                    layoutParams = LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT
                    )
                }

                actionRow.addView(
                    compactActionButton(
                        symbol = "↑",
                        label = "Send"
                    ) {
                        showSend(address)
                    }
                )

                actionRow.addView(
                    compactActionButton(
                        symbol = "↓",
                        label = "Receive"
                    ) {
                        showReceive()
                    }
                )

                actionRow.addView(
                    compactActionButton(
                        symbol = "↻",
                        label = "Scan"
                    ) {
                        startHeaderSyncAndScan()
                    }
                )

                addView(actionRow)
            }
        )

        content.addView(space(16))

        content.addView(
            card {
                addView(sectionTitle("Recent transactions"))
                addView(space(10))
                addView(historyView)
                addView(space(12))
                addView(secondaryButton("View all transactions") {
                    showTransactionHistory()
                })
                addView(space(8))
                addView(
                    helpText(
                        "The three most recent confirmed transactions"
                    )
                )
            }
        )

        content.addView(space(16))

        content.addView(
            card {
                addView(sectionTitle("Status"))
                addView(space(10))
                addView(compactFilterStatus)
                addView(space(12))
                addView(scanStatus)
                addView(space(12))
                addView(helpText("Wallet data is encrypted with Android Keystore"))
            }
        )

        content.addView(space(16))

        content.addView(
            card {
                addView(sectionTitle("Security"))
                addView(space(12))
                addView(secondaryButton("Show recovery phrase") {
                    confirmShowSeed()
                })
                addView(space(10))
                addView(secondaryButton("About & Licences") {
                    showAboutDialog()
                })
                addView(space(10))
                addView(dangerButton("Delete wallet") {
                    confirmDeleteWallet()
                })
            }
        )

        content.addView(space(22))
        content.addView(
            smallStatus(
                "Vexta Wallet v${currentVersionName()}\n" +
                    "© 2026 Vexta Project\n" +
                    "Non-custodial wallet"
            ).apply {
                gravity = Gravity.CENTER
            }
        )
        content.addView(space(12))

        setContentView(
            scroll(content) {
                val now = System.currentTimeMillis()

                if (now - lastExitSwipeAt <= 2_000L) {
                    stopService(
                        Intent(
                            this,
                            WalletMonitoringService::class.java
                        )
                    )
                    finishAndRemoveTask()
                } else {
                    lastExitSwipeAt = now
                    Toast.makeText(
                        this,
                        "Swipe again to exit",
                        Toast.LENGTH_SHORT
                    ).show()
                }
            }
        )

        refreshHandler.removeCallbacks(refreshRunnable)
        refreshHandler.postDelayed(refreshRunnable, 60_000L)

        automaticScanStarted = true

        window.decorView.postDelayed({
            if (
                !isFinishing &&
                !isDestroyed &&
                mainWalletVisible &&
                !blockchainScanRunning
            ) {
                startHeaderSyncAndScan()
            }
        }, 500L)


        Thread {
            val peers = listOf("87.106.99.23", "74.208.53.160")
            val results = peers.map { peer ->
                try {
                    CompactFilterClient.check(peer)
                } catch (_: Exception) {
                    null
                }
            }

            runOnUiThread {
                val successful = results.filterNotNull()
                val supported = successful.count {
                    it.servicesCompactFilters && it.filterHashesReceived > 0
                }

                compactFilterStatus.text =
                    "Compact filters: $supported/${peers.size} peers ready" +
                        if (supported == peers.size) {
                            "\nBIP157 connection test: successful"
                        } else {
                            "\nBIP157 connection test: incomplete"
                        }
            }
        }.start()
    }

    private fun showReceive() {
        mainWalletVisible = false
        window.clearFlags(
            WindowManager.LayoutParams.FLAG_SECURE
        )

        val words = try {
            loadMnemonic()
                .trim()
                .split(Regex("\\s+"))
        } catch (error: Exception) {
            showFatalError(
                "Unable to load wallet: " +
                    (error.message ?: error.javaClass.simpleName)
            )
            return
        }

        val addressIndex = currentReceiveAddressIndex()
        val address = deriveAddress(words, addressIndex)

        val content = baseLayout()
        content.addView(space(10))
        content.addView(centeredLogo(72))
        content.addView(space(14))
        content.addView(title("Receive VTX"))
        content.addView(
            subtitle(
                "Share this address or QR code to receive coins"
            )
        )
        content.addView(space(20))

        content.addView(
            card {
                addView(
                    sectionTitle(
                        "Receive address ${addressIndex + 1}"
                    )
                )
                addView(space(14))

                addView(
                    ImageView(this@WalletActivity).apply {
                        setImageBitmap(
                            createQrBitmap(
                                "vexta:$address",
                                720
                            )
                        )
                        adjustViewBounds = true
                        setPadding(
                            dp(16),
                            dp(16),
                            dp(16),
                            dp(16)
                        )
                        background =
                            roundedDrawable(Color.WHITE, 24)
                        layoutParams =
                            LinearLayout.LayoutParams(
                                ViewGroup.LayoutParams.MATCH_PARENT,
                                ViewGroup.LayoutParams.WRAP_CONTENT
                            )
                    }
                )

                addView(space(16))

                val addressView = infoBox(
                    address,
                    16f,
                    Gravity.CENTER
                ).apply {
                    isClickable = true
                    isFocusable = true

                    setOnClickListener {
                        val clipboard = getSystemService(
                            Context.CLIPBOARD_SERVICE
                        ) as ClipboardManager

                        clipboard.setPrimaryClip(
                            ClipData.newPlainText(
                                "Vexta address",
                                address
                            )
                        )

                        Toast.makeText(
                            this@WalletActivity,
                            "Address copied",
                            Toast.LENGTH_SHORT
                        ).show()
                    }
                }

                addView(addressView)
                addView(space(10))
                addView(
                    helpText(
                        "Tap the address to copy it"
                    )
                )
            }
        )

        content.addView(space(16))

        content.addView(
            card {
                addView(sectionTitle("Address management"))
                addView(space(12))
                addView(
                    secondaryButton("Generate new address") {
                        AlertDialog.Builder(
                            this@WalletActivity
                        )
                            .setTitle("Generate new address?")
                            .setMessage(
                                "The current address will remain " +
                                    "valid and the wallet will continue " +
                                    "scanning it. A new address will be " +
                                    "generated from the same recovery phrase."
                            )
                            .setNegativeButton("Cancel", null)
                            .setPositiveButton("Generate") {
                                    _, _ ->
                                setCurrentReceiveAddressIndex(
                                    addressIndex + 1
                                )
                                showReceive()
                            }
                            .show()
                    }
                )
                addView(space(10))
                addView(
                    helpText(
                        "All previously generated addresses remain " +
                            "part of this wallet."
                    )
                )
            }
        )

        setContentView(
            scroll(content) {
                showMainWallet()
            }
        )
    }

    private fun waitForTransactionAcceptance(
        txid: String,
        attempts: Int = 20,
        delayMilliseconds: Long = 1_000L
    ): Boolean {
        repeat(attempts) { attempt ->
            var connection: java.net.HttpURLConnection? = null

            try {
                val encodedTxid =
                    java.net.URLEncoder.encode(txid, "UTF-8")

                connection =
                    java.net.URL(
                        "https://vextaproject.org/explorer/api/tx/$encodedTxid"
                    ).openConnection() as java.net.HttpURLConnection

                connection.requestMethod = "GET"
                connection.connectTimeout = 5_000
                connection.readTimeout = 5_000
                connection.useCaches = false

                if (connection.responseCode == 200) {
                    return true
                }
            } catch (_: Exception) {
            } finally {
                connection?.disconnect()
            }

            if (attempt + 1 < attempts) {
                Thread.sleep(delayMilliseconds)
            }
        }

        return false
    }

    private fun showSend(fromAddress: String) {
        mainWalletVisible = false
        window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)

        val recipientInput = inputField(
            hint = "Recipient address (vtx1... or legacy V...)",
            singleLine = false
        )

        sendRecipientInput = recipientInput

        val amountInput = inputField(
            hint = "Amount in VTX",
            singleLine = true,
            inputType = InputType.TYPE_CLASS_NUMBER or
                InputType.TYPE_NUMBER_FLAG_DECIMAL
        )

        val noteView = smallStatus(
            "Payments are signed locally on this device and broadcast " +
                "directly to the Vexta network."
        )

        val content = baseLayout()
        content.addView(space(10))
        content.addView(centeredLogo(72))
        content.addView(space(14))
        content.addView(title("Send VTX"))
        content.addView(subtitle("Create and broadcast a Vexta payment"))
        content.addView(space(20))

        content.addView(
            card {
                addView(sectionTitle("From"))
                addView(space(10))
                addView(infoBox(fromAddress, 15f, Gravity.CENTER))
            }
        )

        content.addView(space(16))

        content.addView(
            card {
                addView(sectionTitle("Payment details"))
                addView(space(12))
                addView(recipientInput)
                addView(space(10))

                addView(secondaryButton("Scan QR code") {
                    val options = GmsBarcodeScannerOptions.Builder()
                        .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
                        .enableAutoZoom()
                        .build()

                    GmsBarcodeScanning
                        .getClient(this@WalletActivity, options)
                        .startScan()
                        .addOnSuccessListener { barcode ->
                            insertScannedAddress(barcode.rawValue)
                        }
                        .addOnCanceledListener {
                            Toast.makeText(
                                this@WalletActivity,
                                "QR scan cancelled",
                                Toast.LENGTH_SHORT
                            ).show()
                        }
                        .addOnFailureListener { error ->
                            Toast.makeText(
                                this@WalletActivity,
                                "QR scanner failed: ${error.message}",
                                Toast.LENGTH_LONG
                            ).show()
                        }
                })

                addView(space(12))
                addView(amountInput)
                addView(space(14))
                addView(primaryButton("Review payment") {
                    if (sendInProgress) {
                        Toast.makeText(
                            this@WalletActivity,
                            "A transaction is already being sent",
                            Toast.LENGTH_LONG
                        ).show()
                        return@primaryButton
                    }

                    val recipient =
                        recipientInput.text.toString().trim()
                    val amountText =
                        amountInput.text.toString().trim()

                    if (recipient.isBlank()) {
                        Toast.makeText(
                            this@WalletActivity,
                            "Enter a Vexta recipient address",
                            Toast.LENGTH_LONG
                        ).show()
                        return@primaryButton
                    }

                    val amountSatoshis = try {
                        BigDecimal(amountText)
                            .setScale(8, RoundingMode.UNNECESSARY)
                            .movePointRight(8)
                            .longValueExact()
                    } catch (_: Exception) {
                        Toast.makeText(
                            this@WalletActivity,
                            "Enter a valid amount with no more than 8 decimals",
                            Toast.LENGTH_LONG
                        ).show()
                        return@primaryButton
                    }

                    if (amountSatoshis <= 0L) {
                        Toast.makeText(
                            this@WalletActivity,
                            "Amount must be greater than zero",
                            Toast.LENGTH_LONG
                        ).show()
                        return@primaryButton
                    }

                    if (latestSpendableUtxos.isEmpty()) {
                        Toast.makeText(
                            this@WalletActivity,
                            "No verified spendable outputs are loaded. " +
                                "Return to the wallet and scan the blockchain.",
                            Toast.LENGTH_LONG
                        ).show()
                        return@primaryButton
                    }

                    authenticateWallet(
                        title = "Authorize payment",
                        subtitle = "Authenticate before signing this VTX transaction"
                    ) {
                        try {
                            val words = loadMnemonic()
                            .trim()
                            .split(Regex("\\s+"))

                        val privateKeysByIndex =
                            latestSpendableUtxos
                                .map { it.addressIndex }
                                .distinct()
                                .associateWith { index ->
                                    deriveWalletPrivateKey(
                                        words,
                                        index
                                    )
                                }

                        val changePrivateKey =
                            deriveWalletPrivateKey(
                                words,
                                currentReceiveAddressIndex()
                            )

                        val changePubKeyHash =
                            Utils.sha256hash160(
                                changePrivateKey.pubKey
                            )

                        val transaction =
                            VextaTransactionSender.createAndSign(
                                spendableUtxos =
                                    latestSpendableUtxos,
                                recipientAddress = recipient,
                                amountSatoshis = amountSatoshis,
                                privateKeysByIndex =
                                    privateKeysByIndex,
                                changePubKeyHash =
                                    changePubKeyHash
                            )

                        val amountDisplay = String.format(
                            "%.8f",
                            transaction.amount.toDouble() /
                                100_000_000.0
                        )

                        val feeDisplay = String.format(
                            "%.8f",
                            transaction.fee.toDouble() /
                                100_000_000.0
                        )

                        val changeDisplay = String.format(
                            "%.8f",
                            transaction.change.toDouble() /
                                100_000_000.0
                        )

                        AlertDialog.Builder(this@WalletActivity)
                            .setTitle("Confirm VTX payment")
                            .setMessage(
                                "Recipient:\n$recipient\n\n" +
                                    "Amount: $amountDisplay VTX\n" +
                                    "Network fee: $feeDisplay VTX\n" +
                                    "Change: $changeDisplay VTX\n" +
                                    "Inputs: ${transaction.inputCount}\n\n" +
                                    "Check the recipient address carefully. " +
                                    "Blockchain transactions cannot be reversed."
                            )
                            .setNegativeButton("Cancel", null)
                            .setPositiveButton("Send") { _, _ ->
                                sendInProgress = true
                                noteView.text =
                                    "Broadcasting transaction..."

                                Thread {
                                    try {
                                        if (
                                            waitForTransactionAcceptance(
                                                transaction.txid,
                                                attempts = 1,
                                                delayMilliseconds = 0L
                                            )
                                        ) {
                                            throw IllegalStateException(
                                                "This transaction already exists. " +
                                                    "Wait for confirmation and refresh " +
                                                    "the wallet before sending again."
                                            )
                                        }

                                        val peers =
                                            VextaTransactionSender.broadcast(
                                                transaction,
                                                listOf(
                                                    "87.106.99.23",
                                                    "74.208.53.160"
                                                )
                                            )

                                        val accepted =
                                            waitForTransactionAcceptance(
                                                transaction.txid
                                            )

                                        runOnUiThread {
                                            sendInProgress = false
                                            latestSpendableUtxos =
                                                latestSpendableUtxos.filterNot {
                                                    "${it.txid}:${it.outputIndex}" in
                                                        transaction.spentOutpoints
                                                }

                                            noteView.text =
                                                if (accepted) {
                                                    "Transaction accepted by the " +
                                                        "Vexta network.\nTXID:\n" +
                                                        transaction.txid
                                                } else {
                                                    "Transaction submitted to " +
                                                        "$peers peer(s), but network " +
                                                        "acceptance could not yet be " +
                                                        "confirmed.\nTXID:\n" +
                                                        transaction.txid
                                                }

                                            recipientInput.text.clear()
                                            amountInput.text.clear()

                                            val rawTransactionHex =
                                                transaction.rawTransaction
                                                    .joinToString("") {
                                                        "%02x".format(
                                                            it.toInt() and 0xff
                                                        )
                                                    }

                                            AlertDialog.Builder(
                                                this@WalletActivity
                                            )
                                                .setTitle(
                                                    if (accepted) {
                                                        "Transaction accepted"
                                                    } else {
                                                        "Transaction broadcast"
                                                    }
                                                )
                                                .setMessage(
                                                    "TXID:\n" +
                                                        transaction.txid +
                                                        if (accepted) {
                                                            "\n\nThe transaction was " +
                                                                "accepted by the Vexta " +
                                                                "network. Its inputs are now " +
                                                                "locked in this wallet until " +
                                                                "the next blockchain scan."
                                                        } else {
                                                            "\n\nThe transaction was sent " +
                                                                "to peers, but network " +
                                                                "acceptance could not yet " +
                                                                "be confirmed."
                                                        }
                                                )
                                                .setNeutralButton(
                                                    "Copy raw TX"
                                                ) { _, _ ->
                                                    val clipboard =
                                                        getSystemService(
                                                            Context
                                                                .CLIPBOARD_SERVICE
                                                        ) as ClipboardManager

                                                    clipboard.setPrimaryClip(
                                                        ClipData.newPlainText(
                                                            "Vexta raw transaction",
                                                            rawTransactionHex
                                                        )
                                                    )

                                                    Toast.makeText(
                                                        this@WalletActivity,
                                                        "Raw transaction copied",
                                                        Toast.LENGTH_LONG
                                                    ).show()
                                                }
                                                .setPositiveButton(
                                                    "OK",
                                                    null
                                                )
                                                .show()
                                        }
                                    } catch (error: Exception) {
                                        runOnUiThread {
                                            sendInProgress = false
                                            noteView.text =
                                                "Transaction broadcast failed:\n" +
                                                    (
                                                        error.message
                                                            ?: error.javaClass
                                                                .simpleName
                                                    )
                                        }
                                    }
                                }.start()
                            }
                            .show()
                    } catch (error: Exception) {
                        Toast.makeText(
                            this@WalletActivity,
                            "Payment could not be prepared: " +
                                (
                                    error.message
                                        ?: error.javaClass.simpleName
                                ),
                            Toast.LENGTH_LONG
                        ).show()
                        }
                    }
                })
            }
        )

        content.addView(space(16))

        content.addView(
            card {
                addView(sectionTitle("Status"))
                addView(space(10))
                addView(noteView)
            }
        )

        setContentView(
            scroll(content) {
                showMainWallet()
            }
        )
    }

    private fun insertScannedAddress(rawValue: String?) {
        if (rawValue.isNullOrBlank()) {
            Toast.makeText(
                this,
                "QR code is empty",
                Toast.LENGTH_LONG
            ).show()
            return
        }

        val value = rawValue.trim()
        val extractedAddress = when {
            value.startsWith("vexta:", true) -> {
                value.substringAfter(":")
                    .substringBefore("?")
                    .trim()
            }
            else -> value
        }

        val address = if (
            extractedAddress.startsWith("vtx1", true)
        ) {
            extractedAddress.lowercase()
        } else {
            extractedAddress
        }

        if (
            address.startsWith("vtx1") ||
            address.startsWith("V")
        ) {
            sendRecipientInput?.setText(address)

            Toast.makeText(
                this,
                "Address inserted",
                Toast.LENGTH_SHORT
            ).show()
        } else {
            Toast.makeText(
                this,
                "QR code does not contain a Vexta address",
                Toast.LENGTH_LONG
            ).show()
        }
    }

    private fun showRestoreDialog() {
        val input = EditText(this).apply {
            hint = "Enter the 12 recovery words"
            minLines = 5
            gravity = Gravity.TOP
            setTextColor(textPrimary)
            setHintTextColor(textSecondary)
            setPadding(dp(16), dp(16), dp(16), dp(16))
            background = roundedDrawable(surfaceColor, 18)
            inputType =
                InputType.TYPE_CLASS_TEXT or
                    InputType.TYPE_TEXT_FLAG_MULTI_LINE or
                    InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        }

        AlertDialog.Builder(this)
            .setTitle("Restore Vexta Wallet")
            .setMessage("Enter all 12 words separated by spaces.")
            .setView(input)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Restore") { _, _ ->
                restoreWallet(input.text.toString())
            }
            .show()
    }

    private fun restoreWallet(input: String) {
        try {
            val words = input
                .trim()
                .lowercase()
                .split(Regex("\\s+"))
                .filter { it.isNotBlank() }

            if (words.size != 12) {
                throw IllegalArgumentException("Exactly 12 words are required")
            }

            MnemonicCode.INSTANCE.check(words)
            saveMnemonic(words.joinToString(" "))

            getSharedPreferences(PREFS, MODE_PRIVATE)
                .edit()
                .putBoolean(PREF_BACKUP_CONFIRMED, true)
                .putInt(PREF_RECEIVE_ADDRESS_INDEX, 0)
                .putBoolean(
                    PREF_RESTORE_ADDRESS_DISCOVERY,
                    true
                )
                .apply()

            Toast.makeText(this, "Wallet restored", Toast.LENGTH_LONG).show()
            showMainWallet()
        } catch (e: Exception) {
            Toast.makeText(
                this,
                "Invalid recovery phrase: ${e.message}",
                Toast.LENGTH_LONG
            ).show()
        }
    }

    private fun authenticateWallet(
        title: String,
        subtitle: String,
        onSuccess: () -> Unit
    ) {
        val authenticators =
            BiometricManager.Authenticators.BIOMETRIC_WEAK or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL

        val biometricManager = BiometricManager.from(this)

        if (
            biometricManager.canAuthenticate(authenticators) !=
            BiometricManager.BIOMETRIC_SUCCESS
        ) {
            AlertDialog.Builder(this)
                .setTitle("Device security required")
                .setMessage(
                    "Vexta Wallet requires biometrics or a device " +
                        "PIN, pattern, or password. Configure a screen " +
                        "lock in Android security settings and try again."
                )
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Security settings") { _, _ ->
                    startActivity(
                        Intent(Settings.ACTION_SECURITY_SETTINGS)
                    )
                }
                .show()
            return
        }

        val executor = ContextCompat.getMainExecutor(this)

        val prompt = BiometricPrompt(
            this,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult
                ) {
                    super.onAuthenticationSucceeded(result)
                    onSuccess()
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()

                    Toast.makeText(
                        this@WalletActivity,
                        "Authentication not recognized",
                        Toast.LENGTH_SHORT
                    ).show()
                }

                override fun onAuthenticationError(
                    errorCode: Int,
                    errString: CharSequence
                ) {
                    super.onAuthenticationError(
                        errorCode,
                        errString
                    )

                    if (
                        errorCode != BiometricPrompt.ERROR_USER_CANCELED &&
                        errorCode != BiometricPrompt.ERROR_NEGATIVE_BUTTON
                    ) {
                        Toast.makeText(
                            this@WalletActivity,
                            errString,
                            Toast.LENGTH_LONG
                        ).show()
                    }
                }
            }
        )

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setAllowedAuthenticators(authenticators)
            .build()

        prompt.authenticate(promptInfo)
    }

    private fun confirmShowSeed() {
        AlertDialog.Builder(this)
            .setTitle("Security warning")
            .setMessage(
                "Never show your recovery phrase to anyone. " +
                    "Make sure nobody can see your screen."
            )
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Authenticate") { _, _ ->
                authenticateWallet(
                    title = "Show recovery phrase",
                    subtitle = "Authenticate to reveal your recovery phrase"
                ) {
                    val words = loadMnemonic().split(" ")
                    showSeedBackup(words)
                }
            }
            .show()
    }

    private fun confirmDeleteWallet() {
        AlertDialog.Builder(this)
            .setTitle("Delete wallet?")
            .setMessage(
                "This removes the encrypted seed from this phone. " +
                    "The wallet can only be recovered with its 12 words."
            )
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Delete") { _, _ ->
                getSharedPreferences(PREFS, MODE_PRIVATE)
                    .edit()
                    .clear()
                    .apply()

                showWelcome()
            }
            .show()
    }

    private fun walletExists(): Boolean {
        return getSharedPreferences(PREFS, MODE_PRIVATE)
            .contains(PREF_CIPHERTEXT)
    }

    private fun saveMnemonic(mnemonic: String) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateSecretKey())

        val ciphertext = cipher.doFinal(mnemonic.toByteArray(Charsets.UTF_8))
        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)

        prefs.edit()
            .putString(
                PREF_CIPHERTEXT,
                android.util.Base64.encodeToString(
                    ciphertext,
                    android.util.Base64.NO_WRAP
                )
            )
            .putString(
                PREF_IV,
                android.util.Base64.encodeToString(
                    cipher.iv,
                    android.util.Base64.NO_WRAP
                )
            )
            .apply()
    }

    private fun loadMnemonic(): String {
        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)

        val ciphertext = android.util.Base64.decode(
            prefs.getString(PREF_CIPHERTEXT, "") ?: "",
            android.util.Base64.NO_WRAP
        )

        val iv = android.util.Base64.decode(
            prefs.getString(PREF_IV, "") ?: "",
            android.util.Base64.NO_WRAP
        )

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            getOrCreateSecretKey(),
            GCMParameterSpec(128, iv)
        )

        return cipher.doFinal(ciphertext).toString(Charsets.UTF_8)
    }

    private fun getOrCreateSecretKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
        }

        val existing = keyStore.getKey(KEY_ALIAS, null)

        if (existing is SecretKey) {
            return existing
        }

        val generator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            "AndroidKeyStore"
        )

        val specification = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or
                KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .build()

        generator.init(specification)
        return generator.generateKey()
    }

    private fun deriveWalletPrivateKey(
        words: List<String>,
        addressIndex: Int
    ): ECKey {
        MnemonicCode.INSTANCE.check(words)

        val seedBytes = MnemonicCode.toSeed(words, "")
        val masterKey =
            HDKeyDerivation.createMasterPrivateKey(seedBytes)
        val hierarchy = DeterministicHierarchy(masterKey)

        val path = listOf(
            ChildNumber(84, true),
            ChildNumber(0, true),
            ChildNumber(0, true),
            ChildNumber.ZERO,
            ChildNumber(addressIndex, false)
        )

        val deterministicKey =
            hierarchy.get(path, true, true)

        return ECKey.fromPrivate(
            deterministicKey.privKeyBytes,
            true
        )
    }

    private fun deriveWitnessScript(
        words: List<String>,
        addressIndex: Int
    ): ByteArray {
        MnemonicCode.INSTANCE.check(words)

        val seedBytes = MnemonicCode.toSeed(words, "")
        val masterKey = HDKeyDerivation.createMasterPrivateKey(seedBytes)
        val hierarchy = DeterministicHierarchy(masterKey)

        val path = listOf(
            ChildNumber(84, true),
            ChildNumber(0, true),
            ChildNumber(0, true),
            ChildNumber.ZERO,
            ChildNumber(addressIndex, false)
        )

        val deterministicKey = hierarchy.get(path, true, true)
        val ecKey = ECKey.fromPrivate(
            deterministicKey.privKeyBytes,
            true
        )

        val pubKeyHash = Utils.sha256hash160(ecKey.pubKey)
        return byteArrayOf(0x00, 0x14) + pubKeyHash
    }

    private fun deriveAddress(
        words: List<String>,
        addressIndex: Int
    ): String {
        MnemonicCode.INSTANCE.check(words)

        val seedBytes = MnemonicCode.toSeed(words, "")
        val masterKey = HDKeyDerivation.createMasterPrivateKey(seedBytes)
        val hierarchy = DeterministicHierarchy(masterKey)

        val path = listOf(
            ChildNumber(84, true),
            ChildNumber(0, true),
            ChildNumber(0, true),
            ChildNumber.ZERO,
            ChildNumber(addressIndex, false)
        )

        val deterministicKey = hierarchy.get(path, true, true)
        val ecKey = ECKey.fromPrivate(
            deterministicKey.privKeyBytes,
            true
        )

        val pubKeyHash = Utils.sha256hash160(ecKey.pubKey)
        return encodeSegwitAddress("vtx", 0, pubKeyHash)
    }

    private fun encodeSegwitAddress(
        hrp: String,
        witnessVersion: Int,
        witnessProgram: ByteArray
    ): String {
        val data = mutableListOf<Int>()
        data.add(witnessVersion)
        data.addAll(convertBits(witnessProgram, 8, 5, true))

        val checksum = createBech32Checksum(hrp, data)
        val charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

        return hrp + "1" +
            (data + checksum).joinToString("") { charset[it].toString() }
    }

    private fun convertBits(
        input: ByteArray,
        fromBits: Int,
        toBits: Int,
        pad: Boolean
    ): List<Int> {
        var accumulator = 0
        var bits = 0
        val result = mutableListOf<Int>()
        val maxValue = (1 shl toBits) - 1
        val maxAccumulator = (1 shl (fromBits + toBits - 1)) - 1

        for (byte in input) {
            val value = byte.toInt() and 0xff
            accumulator = ((accumulator shl fromBits) or value) and maxAccumulator
            bits += fromBits

            while (bits >= toBits) {
                bits -= toBits
                result.add((accumulator shr bits) and maxValue)
            }
        }

        if (pad && bits > 0) {
            result.add((accumulator shl (toBits - bits)) and maxValue)
        }

        return result
    }

    private fun createBech32Checksum(
        hrp: String,
        data: List<Int>
    ): List<Int> {
        val values = expandBech32Hrp(hrp) + data + List(6) { 0 }
        val polymod = bech32Polymod(values) xor 1

        return (0 until 6).map { index ->
            (polymod shr (5 * (5 - index))) and 31
        }
    }

    private fun expandBech32Hrp(hrp: String): List<Int> {
        return hrp.map { it.code shr 5 } +
            listOf(0) +
            hrp.map { it.code and 31 }
    }

    private fun bech32Polymod(values: List<Int>): Int {
        val generators = intArrayOf(
            0x3b6a57b2,
            0x26508e6d,
            0x1ea119fa,
            0x3d4233dd,
            0x2a1462b3
        )

        var checksum = 1

        for (value in values) {
            val top = checksum ushr 25
            checksum = ((checksum and 0x1ffffff) shl 5) xor value

            for (index in 0..4) {
                if (((top shr index) and 1) != 0) {
                    checksum = checksum xor generators[index]
                }
            }
        }

        return checksum
    }

    private fun createQrBitmap(value: String, size: Int): Bitmap {
        val matrix = MultiFormatWriter().encode(
            value,
            BarcodeFormat.QR_CODE,
            size,
            size
        )

        val bitmap = Bitmap.createBitmap(
            size,
            size,
            Bitmap.Config.RGB_565
        )

        for (x in 0 until size) {
            for (y in 0 until size) {
                bitmap.setPixel(
                    x,
                    y,
                    if (matrix[x, y]) Color.BLACK else Color.WHITE
                )
            }
        }

        return bitmap
    }

    private fun baseLayout(): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(dp(18), dp(52), dp(18), dp(28))
            setBackgroundColor(backgroundColor)
        }
    }

    private fun scroll(
        content: View,
        onSwipeBack: (() -> Unit)? = null
    ): ScrollView {
        return object : ScrollView(this) {
            private var downX = 0f
            private var downY = 0f

            override fun dispatchTouchEvent(event: MotionEvent): Boolean {
                if (onSwipeBack != null) {
                    when (event.actionMasked) {
                        MotionEvent.ACTION_DOWN -> {
                            downX = event.x
                            downY = event.y
                        }

                        MotionEvent.ACTION_UP -> {
                            val dx = event.x - downX
                            val dy = kotlin.math.abs(event.y - downY)

                            if (
                                downX <= width - dp(40) &&
                                dx <= -dp(120) &&
                                dy <= dp(100)
                            ) {
                                onSwipeBack()
                                return true
                            }
                        }
                    }
                }

                return super.dispatchTouchEvent(event)
            }
        }.apply {
            setBackgroundColor(backgroundColor)
            addView(content)
        }
    }

    private fun centeredLogo(sizeDp: Int): ImageView {
        return ImageView(this).apply {
            setImageResource(R.drawable.vexta_logo)
            adjustViewBounds = true
            scaleType = ImageView.ScaleType.FIT_CENTER
            layoutParams = LinearLayout.LayoutParams(dp(sizeDp), dp(sizeDp)).apply {
                gravity = Gravity.CENTER_HORIZONTAL
            }
        }
    }

    private fun card(build: LinearLayout.() -> Unit): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(18), dp(18), dp(18))
            background = glassDrawable(
                surfaceColor,
                24,
                adjustAlpha(accentColor, 0.28f)
            )
            elevation = dp(2).toFloat()
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            build()
        }
    }

    private fun balanceCard(
        build: LinearLayout.() -> Unit
    ): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(dp(22), dp(26), dp(22), dp(24))
            background = GradientDrawable(
                GradientDrawable.Orientation.TL_BR,
                intArrayOf(
                    Color.rgb(12, 47, 87),
                    Color.rgb(10, 27, 60),
                    Color.rgb(35, 20, 82)
                )
            ).apply {
                cornerRadius = dp(28).toFloat()
                setStroke(
                    dp(1),
                    adjustAlpha(accentColor, 0.55f)
                )
            }
            elevation = dp(5).toFloat()
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            build()
        }
    }

    private fun compactActionButton(
        symbol: String,
        label: String,
        action: () -> Unit
    ): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(dp(8), dp(12), dp(8), dp(12))
            background = glassDrawable(
                surfaceColorAlt,
                18,
                adjustAlpha(accentColor, 0.35f)
            )
            isClickable = true
            isFocusable = true
            setOnClickListener { action() }

            addView(
                TextView(this@WalletActivity).apply {
                    text = symbol
                    textSize = 27f
                    setTextColor(accentColor)
                    gravity = Gravity.CENTER
                    typeface = Typeface.DEFAULT_BOLD
                }
            )

            addView(space(5))

            addView(
                TextView(this@WalletActivity).apply {
                    text = label
                    textSize = 13f
                    setTextColor(textPrimary)
                    gravity = Gravity.CENTER
                    typeface = Typeface.DEFAULT_BOLD
                }
            )

            layoutParams = LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f
            ).apply {
                marginStart = dp(4)
                marginEnd = dp(4)
            }
        }
    }

    private fun title(value: String): TextView {
        return TextView(this).apply {
            text = value
            textSize = 30f
            letterSpacing = 0.02f
            setTextColor(textPrimary)
            gravity = Gravity.CENTER
            typeface = Typeface.DEFAULT_BOLD
        }
    }

    private fun subtitle(value: String): TextView {
        return TextView(this).apply {
            text = value
            textSize = 15f
            setTextColor(textSecondary)
            gravity = Gravity.CENTER
        }
    }

    private fun sectionTitle(value: String): TextView {
        return TextView(this).apply {
            text = value.uppercase()
            textSize = 13f
            letterSpacing = 0.12f
            setTextColor(accentColor)
            typeface = Typeface.DEFAULT_BOLD
            gravity = Gravity.START
        }
    }

    private fun headlineValue(value: String): TextView {
        return TextView(this).apply {
            text = value
            textSize = 36f
            letterSpacing = 0.015f
            setTextColor(textPrimary)
            typeface = Typeface.DEFAULT_BOLD
            gravity = Gravity.CENTER
        }
    }

    private fun helpText(value: String): TextView {
        return TextView(this).apply {
            text = value
            textSize = 13f
            setTextColor(textSecondary)
            gravity = Gravity.CENTER
        }
    }

    private fun smallStatus(value: String): TextView {
        return TextView(this).apply {
            text = value
            textSize = 15f
            setTextColor(textPrimary)
            gravity = Gravity.CENTER
        }
    }

    private fun infoBox(
        value: String,
        textSizeValue: Float,
        gravityValue: Int
    ): TextView {
        return TextView(this).apply {
            text = value
            textSize = textSizeValue
            setTextColor(textPrimary)
            gravity = gravityValue
            setPadding(dp(16), dp(16), dp(16), dp(16))
            background = roundedDrawable(surfaceColorAlt, 18)
            setTextIsSelectable(true)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }
    }

    private fun inputField(
        hint: String,
        singleLine: Boolean,
        inputType: Int = InputType.TYPE_CLASS_TEXT
    ): EditText {
        return EditText(this).apply {
            this.hint = hint
            this.inputType = inputType
            this.isSingleLine = singleLine
            setTextColor(textPrimary)
            setHintTextColor(textSecondary)
            setPadding(dp(16), dp(16), dp(16), dp(16))
            background = roundedDrawable(surfaceColorAlt, 18)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }
    }

    private fun primaryButton(
        label: String,
        action: () -> Unit
    ): Button {
        return styledButton(
            label = label,
            background = accentColor,
            textColor = Color.WHITE,
            action = action
        )
    }

    private fun secondaryButton(
        label: String,
        action: () -> Unit
    ): Button {
        return styledButton(
            label = label,
            background = surfaceColorAlt,
            textColor = Color.WHITE,
            action = action
        )
    }

    private fun dangerButton(
        label: String,
        action: () -> Unit
    ): Button {
        return styledButton(
            label = label,
            background = dangerColor,
            textColor = Color.WHITE,
            action = action
        )
    }

    private fun styledButton(
        label: String,
        background: Int,
        textColor: Int,
        action: () -> Unit
    ): Button {
        return Button(this).apply {
            text = label
            isAllCaps = false
            textSize = 16f
            letterSpacing = 0.04f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(textColor)
            setPadding(dp(16), dp(15), dp(16), dp(15))
            this.background = glassDrawable(
                background,
                20,
                adjustAlpha(Color.WHITE, 0.18f)
            )
            elevation = dp(2).toFloat()
            setOnClickListener { action() }
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }
    }

    private fun glassDrawable(
        color: Int,
        radiusDp: Int,
        strokeColor: Int
    ): GradientDrawable {
        return GradientDrawable().apply {
            shape = GradientDrawable.RECTANGLE
            cornerRadius = dp(radiusDp).toFloat()
            setColor(color)
            setStroke(dp(1), strokeColor)
        }
    }

    private fun roundedDrawable(
        color: Int,
        radiusDp: Int
    ): GradientDrawable {
        return GradientDrawable().apply {
            shape = GradientDrawable.RECTANGLE
            cornerRadius = dp(radiusDp).toFloat()
            setColor(color)
            setStroke(dp(1), adjustAlpha(Color.WHITE, 0.08f))
        }
    }

    private fun space(heightDp: Int): View {
        return View(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                1,
                dp(heightDp)
            )
        }
    }

    private fun dp(value: Int): Int {
        return (value * resources.displayMetrics.density).toInt()
    }

    private fun adjustAlpha(color: Int, factor: Float): Int {
        val alpha = (Color.alpha(color) * factor).toInt()
        return Color.argb(alpha, Color.red(color), Color.green(color), Color.blue(color))
    }

    private fun showFatalError(message: String) {
        val content = baseLayout()
        content.addView(space(20))
        content.addView(centeredLogo(72))
        content.addView(space(14))
        content.addView(title("Vexta Wallet"))
        content.addView(space(20))
        content.addView(
            card {
                addView(sectionTitle("Error"))
                addView(space(12))
                addView(
                    TextView(this@WalletActivity).apply {
                        text = message
                        textSize = 16f
                        setTextColor(Color.RED)
                        gravity = Gravity.CENTER
                    }
                )
                addView(space(14))
                addView(dangerButton("Delete wallet data") {
                    getSharedPreferences(PREFS, MODE_PRIVATE)
                        .edit()
                        .clear()
                        .apply()

                    showWelcome()
                })
            }
        )
        setContentView(scroll(content))
    }
}
