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
        private const val PREF_MLDSA_ADDRESS_INDEX =
            "mldsa_address_index"
        private const val PREF_SLHDSA_ADDRESS_INDEX =
            "slhdsa_address_index"
        private const val PREF_MLDSA_ADDRESS_CREATED =
            "mldsa_address_created"
        private const val PREF_SLHDSA_ADDRESS_CREATED =
            "slhdsa_address_created"
        private const val PREF_KNOWN_INCOMING_TXIDS =
            "known_incoming_txids"
        private const val PREF_TX_NOTIFICATIONS_INITIALIZED =
            "tx_notifications_initialized"
        private const val PREF_LAST_BACKGROUND_SCAN_HEIGHT =
            "last_background_scan_height"
        private const val PREF_LAST_HEADER_HEIGHT =
            "last_header_height"
        private const val PREF_BACKGROUND_UTXO_PREFIX =
            "background_utxos_"
        private const val PREF_BACKGROUND_TX_HISTORY =
            "background_transaction_history"
        private const val PREF_BACKGROUND_TX_HISTORY_VERSION =
            "background_transaction_history_version"
        private const val BACKGROUND_TX_HISTORY_VERSION = 4
    }

    private fun backgroundUtxoKey(
        addressType: BlockScanner.AddressType,
        addressIndex: Int
    ): String {
        return PREF_BACKGROUND_UTXO_PREFIX +
            addressType.name +
            "_" +
            addressIndex
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

                val cachedTipHeightBeforeSync = chain.last().height
                val cachedTipHashBeforeSync = chain.last().hashDisplay
                var reorgDetected = false

                for (peer in listOf("87.106.99.23", "74.208.53.160")) {
                    try {
                        val result = HeaderSync.syncFromPeer(peer, chain)

                        if (cachedTipHeightBeforeSync > 0) {
                            val originalTipStillCanonical =
                                chain.getOrNull(cachedTipHeightBeforeSync)
                                    ?.hashDisplay == cachedTipHashBeforeSync

                            if (!originalTipStillCanonical) {
                                reorgDetected = true
                            }
                        }

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

                val highestMldsaAddressIndex =
                    preferences
                        .getInt(PREF_MLDSA_ADDRESS_INDEX, 0)
                        .coerceAtLeast(0)

                val highestSlhdsaAddressIndex =
                    preferences
                        .getInt(PREF_SLHDSA_ADDRESS_INDEX, 0)
                        .coerceAtLeast(0)

                val localHeight = chain.last().height

                preferences.edit()
                    .putInt(
                        PREF_LAST_HEADER_HEIGHT,
                        localHeight
                    )
                    .apply()

                val previousHeight =
                    preferences
                        .getInt(
                            PREF_LAST_BACKGROUND_SCAN_HEIGHT,
                            0
                        )
                        .coerceAtLeast(0)

                val standardCacheAvailable =
                    (0..highestAddressIndex).all { addressIndex ->
                        preferences.contains(
                            backgroundUtxoKey(
                                BlockScanner.AddressType.STANDARD,
                                addressIndex
                            )
                        ) ||
                            preferences.contains(
                                PREF_BACKGROUND_UTXO_PREFIX +
                                    addressIndex
                            )
                    }

                val mldsaCacheAvailable =
                    (0..highestMldsaAddressIndex).all { addressIndex ->
                        preferences.contains(
                            backgroundUtxoKey(
                                BlockScanner.AddressType.MLDSA,
                                addressIndex
                            )
                        )
                    }

                val slhdsaCacheAvailable =
                    (0..highestSlhdsaAddressIndex).all { addressIndex ->
                        preferences.contains(
                            backgroundUtxoKey(
                                BlockScanner.AddressType.SLHDSA,
                                addressIndex
                            )
                        )
                    }

                val backgroundCacheAvailable =
                    standardCacheAvailable &&
                        mldsaCacheAvailable &&
                        slhdsaCacheAvailable

                val transactionHistoryCurrent =
                    preferences.getInt(
                        PREF_BACKGROUND_TX_HISTORY_VERSION,
                        0
                    ) == BACKGROUND_TX_HISTORY_VERSION

                val fullScanRequired =
                    reorgDetected ||
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
                    linkedMapOf<
                        Pair<BlockScanner.AddressType, Int>,
                        List<BlockScanner.SpendableUtxo>
                    >()

                val scanTargets =
                    buildList {
                        for (addressIndex in 0..highestAddressIndex) {
                            add(
                                Triple(
                                    BlockScanner.AddressType.STANDARD,
                                    addressIndex,
                                    deriveWitnessScript(
                                        words,
                                        addressIndex
                                    )
                                )
                            )
                        }

                        if (
                            preferences.getBoolean(
                                PREF_MLDSA_ADDRESS_CREATED,
                                false
                            )
                        ) {
                            for (
                                addressIndex in
                                    0..highestMldsaAddressIndex
                            ) {
                                add(
                                    Triple(
                                        BlockScanner.AddressType.MLDSA,
                                        addressIndex,
                                        derivePqWitnessScript(
                                            words,
                                            BlockScanner.AddressType.MLDSA,
                                            addressIndex
                                        )
                                    )
                                )
                            }
                        }

                        if (
                            preferences.getBoolean(
                                PREF_SLHDSA_ADDRESS_CREATED,
                                false
                            )
                        ) {
                            for (
                                addressIndex in
                                    0..highestSlhdsaAddressIndex
                            ) {
                                add(
                                    Triple(
                                        BlockScanner.AddressType.SLHDSA,
                                        addressIndex,
                                        derivePqWitnessScript(
                                            words,
                                            BlockScanner.AddressType.SLHDSA,
                                            addressIndex
                                        )
                                    )
                                )
                            }
                        }
                    }

                for (
                    (addressType, addressIndex, script)
                    in scanTargets
                ) {
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
                                addressType,
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
                            addressType = addressType,
                            initialUtxos = initialUtxos
                        ) { _, _ -> }

                    allTransactions.addAll(blocks.transactions)

                    updatedUtxos[
                        addressType to addressIndex
                    ] = blocks.utxos
                }

                val mergedTransactions =
                    allTransactions
                        .distinctBy {
                            "${it.txid}:${it.height}:${it.netSatoshis}:${it.blockTime}"
                        }
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
                                blockTime = newest.blockTime,
                                isCoinbase = transactions.any {
                                    it.isCoinbase
                                }
                            )
                        }
                        .filter { it.netSatoshis != 0L }

                if (fullScanRequired) {
                    synchronizeKnownIncomingTransactions(
                        mergedTransactions
                    )
                } else {
                    updateIncomingTransactionsAndNotify(
                        mergedTransactions
                    )
                }

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
                    (target, utxos) in updatedUtxos
                ) {
                    val (addressType, addressIndex) = target

                    editor.putStringSet(
                        backgroundUtxoKey(
                            addressType,
                            addressIndex
                        ),
                        encodeBackgroundUtxos(utxos)
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
                transaction.blockTime.toString(),
                transaction.isCoinbase.toString()
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

                if (parts.size != 5) {
                    return@mapNotNull null
                }

                BlockScanner.WalletTransaction(
                    txid = parts[0],
                    height = parts[1].toInt(),
                    netSatoshis = parts[2].toLong(),
                    blockTime = parts[3].toLong(),
                    isCoinbase = parts[4].toBooleanStrict()
                )
            } catch (_: Exception) {
                null
            }
        }
    }

    private fun synchronizeKnownIncomingTransactions(
        transactions: List<BlockScanner.WalletTransaction>
    ) {
        val preferences =
            getSharedPreferences(PREFS, MODE_PRIVATE)

        val knownTxids =
            preferences.getStringSet(
                PREF_KNOWN_INCOMING_TXIDS,
                emptySet()
            )?.toMutableSet() ?: mutableSetOf()

        knownTxids.addAll(
            transactions
                .filter { it.netSatoshis > 0L }
                .map { it.txid }
        )

        preferences.edit()
            .putBoolean(
                PREF_TX_NOTIFICATIONS_INITIALIZED,
                true
            )
            .putStringSet(
                PREF_KNOWN_INCOMING_TXIDS,
                knownTxids
            )
            .apply()
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
            .distinctBy { it.txid }
            .filter { it.txid !in knownTxids }
            .sortedBy { it.height }
            .forEach { transaction ->
                knownTxids.add(transaction.txid)

                val saved =
                    preferences.edit()
                        .putStringSet(
                            PREF_KNOWN_INCOMING_TXIDS,
                            knownTxids.toSet()
                        )
                        .commit()

                if (saved) {
                    showIncomingPaymentNotification(
                        transaction.netSatoshis,
                        transaction.txid
                    )
                }
            }
    }

    private fun showIncomingPaymentNotification(
        receivedSatoshis: Long,
        txid: String
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
            txid.hashCode(),
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
                utxo.addressIndex.toString(),
                utxo.isCoinbase.toString(),
                utxo.addressType.name
            ).joinToString("|")
        }.toSet()

    private fun loadBackgroundUtxos(
        preferences: android.content.SharedPreferences,
        addressType: BlockScanner.AddressType,
        addressIndex: Int
    ): List<BlockScanner.SpendableUtxo> {
        val newKey =
            backgroundUtxoKey(
                addressType,
                addressIndex
            )

        val legacyKey =
            PREF_BACKGROUND_UTXO_PREFIX + addressIndex

        val values =
            if (preferences.contains(newKey)) {
                preferences.getStringSet(
                    newKey,
                    emptySet()
                ) ?: emptySet()
            } else if (
                addressType == BlockScanner.AddressType.STANDARD
            ) {
                preferences.getStringSet(
                    legacyKey,
                    emptySet()
                ) ?: emptySet()
            } else {
                emptySet()
            }

        return values.mapNotNull { value ->
            try {
                val parts = value.split("|")

                if (parts.size != 6 && parts.size != 7) {
                    return@mapNotNull null
                }

                BlockScanner.SpendableUtxo(
                    txid = parts[0],
                    outputIndex = parts[1].toLong(),
                    value = parts[2].toLong(),
                    height = parts[3].toInt(),
                    addressIndex = parts[4].toInt(),
                    isCoinbase = parts[5].toBooleanStrict(),
                    addressType =
                        if (parts.size == 7) {
                            BlockScanner.AddressType.valueOf(parts[6])
                        } else {
                            BlockScanner.AddressType.STANDARD
                        }
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

    private fun derivePqWitnessScript(
        words: List<String>,
        addressType: BlockScanner.AddressType,
        addressIndex: Int
    ): ByteArray {
        require(
            addressType == BlockScanner.AddressType.MLDSA ||
                addressType == BlockScanner.AddressType.SLHDSA
        )
        require(addressIndex >= 0)

        MnemonicCode.INSTANCE.check(words)

        val bip39Seed =
            MnemonicCode.toSeed(words, "")

        val masterKey =
            HDKeyDerivation.createMasterPrivateKey(
                bip39Seed
            )

        val walletSeed =
            masterKey.privKeyBytes

        val domain =
            "Vexta-PQ-HD-v1"
                .toByteArray(Charsets.US_ASCII)

        val data =
            ByteArray(domain.size + 1 + 4)

        System.arraycopy(
            domain,
            0,
            data,
            0,
            domain.size
        )

        var offset = domain.size

        data[offset++] =
            when (addressType) {
                BlockScanner.AddressType.MLDSA -> 2
                BlockScanner.AddressType.SLHDSA -> 3
                BlockScanner.AddressType.STANDARD ->
                    error("Standard address is not PQ")
            }.toByte()

        data[offset++] =
            ((addressIndex ushr 24) and 0xff).toByte()
        data[offset++] =
            ((addressIndex ushr 16) and 0xff).toByte()
        data[offset++] =
            ((addressIndex ushr 8) and 0xff).toByte()
        data[offset] =
            (addressIndex and 0xff).toByte()

        val mac =
            javax.crypto.Mac.getInstance(
                "HmacSHA512"
            )

        mac.init(
            javax.crypto.spec.SecretKeySpec(
                walletSeed,
                "HmacSHA512"
            )
        )

        val seedMaterial =
            mac.doFinal(data)

        val keyPair =
            when (addressType) {
                BlockScanner.AddressType.MLDSA ->
                    requireNotNull(
                        VextaPQ.mldsaKeypairFromSeed(
                            seedMaterial
                        )
                    )

                BlockScanner.AddressType.SLHDSA ->
                    requireNotNull(
                        VextaPQ.sphincsKeypairFromSeed(
                            seedMaterial
                        )
                    )

                BlockScanner.AddressType.STANDARD ->
                    error("Standard address is not PQ")
            }

        require(keyPair.size == 2)

        val publicKey = keyPair[0]
        val secretKey = keyPair[1]

        return try {
            val keyId =
                java.security.MessageDigest
                    .getInstance("SHA-256")
                    .digest(publicKey)

            byteArrayOf(
                if (
                    addressType ==
                        BlockScanner.AddressType.MLDSA
                ) {
                    0x52.toByte()
                } else {
                    0x53.toByte()
                },
                0x20
            ) + keyId
        } finally {
            secretKey.fill(0)
            seedMaterial.fill(0)
            walletSeed.fill(0)
            bip39Seed.fill(0)
        }
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
