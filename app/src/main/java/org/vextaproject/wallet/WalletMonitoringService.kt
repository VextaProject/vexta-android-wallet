package org.vextaproject.wallet

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import org.bitcoinj.core.ECKey
import org.bitcoinj.core.Utils
import org.bitcoinj.crypto.ChildNumber
import org.bitcoinj.crypto.DeterministicHierarchy
import org.bitcoinj.crypto.HDKeyDerivation
import org.bitcoinj.crypto.MnemonicCode
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class WalletMonitoringService : Service() {

    companion object {
        private const val CHANNEL_ID = "vexta_wallet_monitoring"
        private const val PAYMENT_CHANNEL_ID = "vexta_incoming_payments"
        private const val NOTIFICATION_ID = 7001

        private const val PREFS = "vexta_wallet"
        private const val KEY_ALIAS = "vexta_wallet_seed_key"
        private const val PREF_CIPHERTEXT = "seed_ciphertext"
        private const val PREF_IV = "seed_iv"
        private const val PREF_RECEIVE_ADDRESS_INDEX =
            "receive_address_index"
        private const val PREF_KNOWN_INCOMING_TXIDS =
            "known_incoming_txids"
        private const val PREF_TX_NOTIFICATIONS_INITIALIZED =
            "tx_notifications_initialized"
        private const val PREF_LAST_BACKGROUND_SCAN_HEIGHT =
            "last_background_scan_height"
        private const val PREF_BACKGROUND_UTXO_PREFIX =
            "background_utxos_"
        private const val PREF_BACKGROUND_TX_HISTORY =
            "background_transaction_history"
        private const val PREF_BACKGROUND_TX_HISTORY_VERSION =
            "background_transaction_history_version"
        private const val BACKGROUND_TX_HISTORY_VERSION = 1
    }

    private val handler = Handler(Looper.getMainLooper())
    private var scanRunning = false

    private val monitorRunnable = object : Runnable {
        override fun run() {
            startBackgroundScan()
            handler.postDelayed(this, 60_000L)
        }
    }

    override fun onCreate() {
        super.onCreate()

        createChannels()
        startForeground(NOTIFICATION_ID, monitoringNotification())

        handler.postDelayed(monitorRunnable, 5_000L)
    }

    override fun onStartCommand(
        intent: Intent?,
        flags: Int,
        startId: Int
    ): Int {
        return START_STICKY
    }

    override fun onDestroy() {
        handler.removeCallbacks(monitorRunnable)
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun startBackgroundScan() {
        if (scanRunning || !walletExists()) {
            return
        }

        scanRunning = true

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

                val words = loadMnemonic()
                    .trim()
                    .split(Regex("\\s+"))

                val preferences =
                    getSharedPreferences(PREFS, MODE_PRIVATE)

                val highestAddressIndex =
                    preferences
                        .getInt(PREF_RECEIVE_ADDRESS_INDEX, 0)
                        .coerceAtLeast(0)

                val localHeight = chain.last().height

                val previousHeight =
                    preferences
                        .getInt(
                            PREF_LAST_BACKGROUND_SCAN_HEIGHT,
                            0
                        )
                        .coerceAtLeast(0)

                val backgroundCacheAvailable =
                    (0..highestAddressIndex).all { addressIndex ->
                        preferences.contains(
                            PREF_BACKGROUND_UTXO_PREFIX +
                                addressIndex
                        )
                    }

                val transactionHistoryCurrent =
                    preferences.getInt(
                        PREF_BACKGROUND_TX_HISTORY_VERSION,
                        0
                    ) == BACKGROUND_TX_HISTORY_VERSION

                val fullScanRequired =
                    previousHeight <= 0 ||
                        previousHeight > localHeight ||
                        !backgroundCacheAvailable ||
                        !transactionHistoryCurrent

                if (
                    !fullScanRequired &&
                    previousHeight == localHeight
                ) {
                    return@Thread
                }

                val startHeight =
                    if (fullScanRequired) {
                        1
                    } else {
                        previousHeight + 1
                    }

                val allTransactions =
                    mutableListOf<BlockScanner.WalletTransaction>()

                val updatedUtxos =
                    linkedMapOf<Int, List<BlockScanner.SpendableUtxo>>()

                for (addressIndex in 0..highestAddressIndex) {
                    val script =
                        deriveWitnessScript(words, addressIndex)

                    val filters =
                        CompactFilterClient.scan(
                            this,
                            "87.106.99.23",
                            script,
                            startHeight = startHeight
                        ) { _, _ -> }

                    val initialUtxos =
                        if (fullScanRequired) {
                            emptyList()
                        } else {
                            loadBackgroundUtxos(
                                preferences,
                                addressIndex
                            )
                        }

                    val blocks =
                        BlockScanner.scan(
                            this,
                            "87.106.99.23",
                            filters.matchingHeights,
                            script,
                            addressIndex,
                            initialUtxos = initialUtxos
                        ) { _, _ -> }

                    allTransactions.addAll(blocks.transactions)

                    updatedUtxos[addressIndex] =
                        blocks.utxos
                }

                val mergedTransactions =
                    allTransactions
                        .groupBy { it.txid }
                        .map { (_, transactions) ->
                            val newest =
                                transactions.maxByOrNull {
                                    it.height
                                } ?: transactions.first()

                            BlockScanner.WalletTransaction(
                                txid = newest.txid,
                                height = newest.height,
                                netSatoshis = transactions.sumOf {
                                    it.netSatoshis
                                },
                                blockTime = newest.blockTime
                            )
                        }
                        .filter { it.netSatoshis != 0L }

                updateIncomingTransactionsAndNotify(
                    mergedTransactions
                )

                val cachedTransactions =
                    if (fullScanRequired) {
                        mergedTransactions
                    } else {
                        (
                            loadBackgroundTransactions(preferences) +
                                mergedTransactions
                        )
                            .groupBy { it.txid }
                            .map { (_, transactions) ->
                                transactions.maxByOrNull {
                                    it.height
                                } ?: transactions.first()
                            }
                    }
                        .sortedByDescending {
                            it.blockTime
                        }

                val editor = preferences.edit()

                editor.putStringSet(
                    PREF_BACKGROUND_TX_HISTORY,
                    encodeBackgroundTransactions(
                        cachedTransactions
                    )
                )

                for (
                    addressIndex in 0..highestAddressIndex
                ) {
                    editor.putStringSet(
                        PREF_BACKGROUND_UTXO_PREFIX +
                            addressIndex,
                        encodeBackgroundUtxos(
                            updatedUtxos[addressIndex]
                                ?: emptyList()
                        )
                    )
                }

                editor.putInt(
                    PREF_LAST_BACKGROUND_SCAN_HEIGHT,
                    localHeight
                )

                editor.putInt(
                    PREF_BACKGROUND_TX_HISTORY_VERSION,
                    BACKGROUND_TX_HISTORY_VERSION
                )

                editor.apply()
            } catch (_: Exception) {
            } finally {
                scanRunning = false
            }
        }.start()
    }

    private fun encodeBackgroundTransactions(
        transactions: List<BlockScanner.WalletTransaction>
    ): Set<String> =
        transactions.map { transaction ->
            listOf(
                transaction.txid,
                transaction.height.toString(),
                transaction.netSatoshis.toString(),
                transaction.blockTime.toString()
            ).joinToString("|")
        }.toSet()

    private fun loadBackgroundTransactions(
        preferences: android.content.SharedPreferences
    ): List<BlockScanner.WalletTransaction> {
        val values =
            preferences.getStringSet(
                PREF_BACKGROUND_TX_HISTORY,
                emptySet()
            ) ?: emptySet()

        return values.mapNotNull { value ->
            try {
                val parts = value.split("|")

                if (parts.size != 4) {
                    return@mapNotNull null
                }

                BlockScanner.WalletTransaction(
                    txid = parts[0],
                    height = parts[1].toInt(),
                    netSatoshis = parts[2].toLong(),
                    blockTime = parts[3].toLong()
                )
            } catch (_: Exception) {
                null
            }
        }
    }

    private fun updateIncomingTransactionsAndNotify(
        transactions: List<BlockScanner.WalletTransaction>
    ) {
        val preferences =
            getSharedPreferences(PREFS, MODE_PRIVATE)

        val incoming =
            transactions.filter { it.netSatoshis > 0L }

        val currentTxids =
            incoming.map { it.txid }.toSet()

        val initialized =
            preferences.getBoolean(
                PREF_TX_NOTIFICATIONS_INITIALIZED,
                false
            )

        if (!initialized) {
            preferences.edit()
                .putBoolean(
                    PREF_TX_NOTIFICATIONS_INITIALIZED,
                    true
                )
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

    private fun encodeBackgroundUtxos(
        utxos: List<BlockScanner.SpendableUtxo>
    ): Set<String> =
        utxos.map { utxo ->
            listOf(
                utxo.txid,
                utxo.outputIndex.toString(),
                utxo.value.toString(),
                utxo.height.toString(),
                utxo.addressIndex.toString()
            ).joinToString("|")
        }.toSet()

    private fun loadBackgroundUtxos(
        preferences: android.content.SharedPreferences,
        addressIndex: Int
    ): List<BlockScanner.SpendableUtxo> {
        val values =
            preferences.getStringSet(
                PREF_BACKGROUND_UTXO_PREFIX + addressIndex,
                emptySet()
            ) ?: emptySet()

        return values.mapNotNull { value ->
            try {
                val parts = value.split("|")

                if (parts.size != 5) {
                    return@mapNotNull null
                }

                BlockScanner.SpendableUtxo(
                    txid = parts[0],
                    outputIndex = parts[1].toLong(),
                    value = parts[2].toLong(),
                    height = parts[3].toInt(),
                    addressIndex = parts[4].toInt()
                )
            } catch (_: Exception) {
                null
            }
        }
    }

    private fun walletExists(): Boolean {
        val prefs =
            getSharedPreferences(PREFS, MODE_PRIVATE)

        return !prefs.getString(PREF_CIPHERTEXT, "")
            .isNullOrBlank() &&
            !prefs.getString(PREF_IV, "")
                .isNullOrBlank()
    }

    private fun loadMnemonic(): String {
        val prefs =
            getSharedPreferences(PREFS, MODE_PRIVATE)

        val ciphertext =
            android.util.Base64.decode(
                prefs.getString(PREF_CIPHERTEXT, "") ?: "",
                android.util.Base64.NO_WRAP
            )

        val iv =
            android.util.Base64.decode(
                prefs.getString(PREF_IV, "") ?: "",
                android.util.Base64.NO_WRAP
            )

        val keyStore =
            KeyStore.getInstance("AndroidKeyStore").apply {
                load(null)
            }

        val key =
            keyStore.getKey(KEY_ALIAS, null) as SecretKey

        val cipher =
            Cipher.getInstance("AES/GCM/NoPadding")

        cipher.init(
            Cipher.DECRYPT_MODE,
            key,
            GCMParameterSpec(128, iv)
        )

        return cipher.doFinal(ciphertext)
            .toString(Charsets.UTF_8)
    }

    private fun deriveWitnessScript(
        words: List<String>,
        addressIndex: Int
    ): ByteArray {
        MnemonicCode.INSTANCE.check(words)

        val seedBytes =
            MnemonicCode.toSeed(words, "")

        val masterKey =
            HDKeyDerivation.createMasterPrivateKey(seedBytes)

        val hierarchy =
            DeterministicHierarchy(masterKey)

        val path =
            listOf(
                ChildNumber(84, true),
                ChildNumber(0, true),
                ChildNumber(0, true),
                ChildNumber.ZERO,
                ChildNumber(addressIndex, false)
            )

        val key =
            hierarchy.get(path, true, true)

        val ecKey =
            ECKey.fromPrivate(
                key.privKeyBytes,
                true
            )

        val pubKeyHash =
            Utils.sha256hash160(ecKey.pubKey)

        return byteArrayOf(0x00, 0x14) + pubKeyHash
    }

    private fun createChannels() {
        val manager =
            getSystemService(
                Context.NOTIFICATION_SERVICE
            ) as NotificationManager

        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                "Wallet monitoring",
                NotificationManager.IMPORTANCE_LOW
            )
        )

        manager.createNotificationChannel(
            NotificationChannel(
                PAYMENT_CHANNEL_ID,
                "Incoming VTX payments",
                NotificationManager.IMPORTANCE_HIGH
            )
        )
    }

    private fun monitoringNotification(): Notification {
        val intent =
            Intent(this, WalletActivity::class.java)

        val pendingIntent =
            PendingIntent.getActivity(
                this,
                0,
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT or
                    PendingIntent.FLAG_IMMUTABLE
            )

        return Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(
                android.R.drawable.stat_notify_sync
            )
            .setContentTitle("Vexta Wallet")
            .setContentText("Monitoring active")
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setCategory(Notification.CATEGORY_SERVICE)
            .build()
    }
}
