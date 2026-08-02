package org.vextaproject.wallet

import android.content.Context
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.File
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import kotlin.random.Random

object BlockScanner {

    private val magic = byteArrayOf(0x56, 0x54, 0x58, 0x31)
    private const val port = 19333
    private const val protocolVersion = 70018
    private const val msgWitnessBlock = 0x40000002

    private const val genesisHash =
        "0000027626959d894ae1c8a6f9050cdcbdf58eb0037ab06345cb5502955370f1"

    data class SpendableUtxo(
        val txid: String,
        val outputIndex: Long,
        val value: Long,
        val height: Int,
        val addressIndex: Int
    )

    data class WalletTransaction(
        val txid: String,
        val height: Int,
        val netSatoshis: Long
    )

    data class Result(
        val downloadedBlocks: Int,
        val receivedTransactions: Int,
        val spentTransactions: Int,
        val utxoCount: Int,
        val balanceSatoshis: Long,
        val utxos: List<SpendableUtxo>,
        val transactions: List<WalletTransaction>
    )

    private data class Utxo(
        val txidWire: ByteArray,
        val outputIndex: Long,
        val value: Long,
        val height: Int,
        val addressIndex: Int
    )

    private data class ParsedTransaction(
        val txidWire: ByteArray,
        val inputs: List<OutPoint>,
        val outputs: List<TransactionOutput>
    )

    private data class OutPoint(
        val txidWire: ByteArray,
        val index: Long
    )

    private data class TransactionOutput(
        val index: Int,
        val value: Long,
        val script: ByteArray
    )

    fun scan(
        context: Context,
        peer: String,
        matchingHeights: List<Int>,
        walletScript: ByteArray,
        addressIndex: Int,
        progress: (Int, Int) -> Unit
    ): Result {
        if (matchingHeights.isEmpty()) {
            return Result(
                downloadedBlocks = 0,
                receivedTransactions = 0,
                spentTransactions = 0,
                utxoCount = 0,
                balanceSatoshis = 0,
                utxos = emptyList(),
                transactions = emptyList()
            )
        }

        val hashes = loadHeaderHashes(context)
        val requested = matchingHeights
            .distinct()
            .sorted()
            .associateWith { height ->
                hashes.getOrNull(height)
                    ?: throw IllegalStateException(
                        "Missing verified header at height $height"
                    )
            }

        val heightByHash = requested.entries.associate {
            it.value.toHex() to it.key
        }

        val utxos = linkedMapOf<String, Utxo>()
        var receivedTransactions = 0
        var spentTransactions = 0
        var downloadedBlocks = 0
        val walletTransactions = mutableListOf<WalletTransaction>()

        Socket().use { socket ->
            socket.soTimeout = 30000
            socket.connect(InetSocketAddress(peer, port), 5000)

            val input = DataInputStream(socket.getInputStream())
            val output = socket.getOutputStream()

            sendMessage(output, "version", createVersionPayload(peer))

            var gotVersion = false
            var gotVerack = false
            var requestedBlocks = false

            repeat(100000) {
                val (command, payload) = readMessage(input)

                when (command) {
                    "version" -> {
                        gotVersion = true
                        sendMessage(output, "verack", byteArrayOf())
                    }

                    "verack" -> gotVerack = true

                    "ping" -> sendMessage(output, "pong", payload)

                    "block" -> {
                        if (payload.size < 81) {
                            throw IllegalStateException("Short block payload")
                        }

                        val blockHeader = payload.copyOfRange(0, 80)
                        val blockHashWire = doubleSha256(blockHeader)
                        val height = heightByHash[blockHashWire.toHex()]
                            ?: throw IllegalStateException(
                                "Received an unrequested block"
                            )

                        parseBlock(payload, walletScript).forEach { transaction ->
                            var spentWalletValue = 0L

                            transaction.inputs.forEach { inputPoint ->
                                val key = outPointKey(
                                    inputPoint.txidWire,
                                    inputPoint.index
                                )

                                val spentOutput = utxos.remove(key)

                                if (spentOutput != null) {
                                    spentWalletValue += spentOutput.value
                                }
                            }

                            if (spentWalletValue > 0L) {
                                spentTransactions++
                            }

                            var receivedWalletValue = 0L

                            transaction.outputs.forEach { transactionOutput ->
                                if (
                                    transactionOutput.script.contentEquals(
                                        walletScript
                                    )
                                ) {
                                    val key = outPointKey(
                                        transaction.txidWire,
                                        transactionOutput.index.toLong()
                                    )

                                    utxos[key] = Utxo(
                                        txidWire = transaction.txidWire,
                                        outputIndex =
                                            transactionOutput.index.toLong(),
                                        value = transactionOutput.value,
                                        height = height,
                                        addressIndex = addressIndex
                                    )

                                    receivedWalletValue +=
                                        transactionOutput.value
                                }
                            }

                            if (receivedWalletValue > 0L) {
                                receivedTransactions++
                            }

                            val netSatoshis =
                                receivedWalletValue - spentWalletValue

                            if (netSatoshis != 0L) {
                                walletTransactions.add(
                                    WalletTransaction(
                                        txid = transaction.txidWire
                                            .reversedArray()
                                            .toHex(),
                                        height = height,
                                        netSatoshis = netSatoshis
                                    )
                                )
                            }
                        }

                        downloadedBlocks++
                        progress(downloadedBlocks, requested.size)

                        if (downloadedBlocks == requested.size) {
                            val spendable = utxos.values
                                .sortedWith(
                                    compareBy<Utxo> { it.height }
                                        .thenBy { it.txidWire.toHex() }
                                        .thenBy { it.outputIndex }
                                )
                                .map { utxo ->
                                    SpendableUtxo(
                                        txid = utxo.txidWire
                                            .reversedArray()
                                            .toHex(),
                                        outputIndex = utxo.outputIndex,
                                        value = utxo.value,
                                        height = utxo.height,
                                        addressIndex = utxo.addressIndex
                                    )
                                }

                            return Result(
                                downloadedBlocks = downloadedBlocks,
                                receivedTransactions = receivedTransactions,
                                spentTransactions = spentTransactions,
                                utxoCount = spendable.size,
                                balanceSatoshis = spendable.sumOf {
                                    it.value
                                },
                                utxos = spendable,
                                transactions = walletTransactions
                                    .sortedWith(
                                        compareByDescending<WalletTransaction> {
                                            it.height
                                        }.thenByDescending {
                                            it.txid
                                        }
                                    )
                            )
                        }
                    }

                    "notfound" -> {
                        throw IllegalStateException(
                            "Peer could not provide a requested block"
                        )
                    }
                }

                if (
                    gotVersion &&
                    gotVerack &&
                    !requestedBlocks
                ) {
                    sendMessage(
                        output,
                        "getdata",
                        createGetDataPayload(requested.values.toList())
                    )

                    requestedBlocks = true
                }
            }

            throw IllegalStateException("Block download did not complete")
        }
    }

    private fun parseBlock(
        payload: ByteArray,
        walletScript: ByteArray
    ): List<ParsedTransaction> {
        val cursor = Cursor(payload)
        cursor.skip(80)

        val transactionCount = cursor.readCompactSize()

        if (transactionCount > 1_000_000) {
            throw IllegalStateException("Invalid transaction count")
        }

        val transactions = ArrayList<ParsedTransaction>(
            transactionCount.toInt()
        )

        repeat(transactionCount.toInt()) {
            transactions.add(parseTransaction(cursor, walletScript))
        }

        if (!cursor.isFinished()) {
            throw IllegalStateException("Unexpected bytes after block")
        }

        return transactions
    }

    private fun parseTransaction(
        cursor: Cursor,
        walletScript: ByteArray
    ): ParsedTransaction {
        val stripped = ByteArrayOutputStream()

        val version = cursor.readBytes(4)
        stripped.write(version)

        var hasWitness = false

        if (
            cursor.remaining() >= 2 &&
            cursor.peekByte(0) == 0 &&
            cursor.peekByte(1) != 0
        ) {
            cursor.skip(2)
            hasWitness = true
        }

        val inputCount = cursor.readCompactSize()
        writeCompactSize(stripped, inputCount)

        val inputs = ArrayList<OutPoint>(inputCount.toInt())

        repeat(inputCount.toInt()) {
            val previousTxid = cursor.readBytes(32)
            val previousIndexBytes = cursor.readBytes(4)
            val previousIndex = ByteBuffer
                .wrap(previousIndexBytes)
                .order(ByteOrder.LITTLE_ENDIAN)
                .int
                .toLong() and 0xffffffffL

            val scriptLength = cursor.readCompactSize()
            val script = cursor.readBytes(scriptLength.toInt())
            val sequence = cursor.readBytes(4)

            stripped.write(previousTxid)
            stripped.write(previousIndexBytes)
            writeCompactSize(stripped, scriptLength)
            stripped.write(script)
            stripped.write(sequence)

            inputs.add(
                OutPoint(
                    txidWire = previousTxid,
                    index = previousIndex
                )
            )
        }

        val outputCount = cursor.readCompactSize()
        writeCompactSize(stripped, outputCount)

        val outputs = ArrayList<TransactionOutput>(outputCount.toInt())

        repeat(outputCount.toInt()) { outputIndex ->
            val valueBytes = cursor.readBytes(8)
            val value = ByteBuffer
                .wrap(valueBytes)
                .order(ByteOrder.LITTLE_ENDIAN)
                .long

            if (value < 0) {
                throw IllegalStateException("Negative transaction output")
            }

            val scriptLength = cursor.readCompactSize()
            val script = cursor.readBytes(scriptLength.toInt())

            stripped.write(valueBytes)
            writeCompactSize(stripped, scriptLength)
            stripped.write(script)

            if (script.contentEquals(walletScript)) {
                outputs.add(
                    TransactionOutput(
                        index = outputIndex,
                        value = value,
                        script = script
                    )
                )
            }
        }

        if (hasWitness) {
            repeat(inputCount.toInt()) {
                val itemCount = cursor.readCompactSize()

                repeat(itemCount.toInt()) {
                    val itemLength = cursor.readCompactSize()
                    cursor.skip(itemLength.toInt())
                }
            }
        }

        val lockTime = cursor.readBytes(4)
        stripped.write(lockTime)

        return ParsedTransaction(
            txidWire = doubleSha256(stripped.toByteArray()),
            inputs = inputs,
            outputs = outputs
        )
    }

    private fun createGetDataPayload(
        blockHashesWire: List<ByteArray>
    ): ByteArray {
        val output = ByteArrayOutputStream()

        writeCompactSize(output, blockHashesWire.size.toLong())

        blockHashesWire.forEach { hash ->
            writeInt32LE(output, msgWitnessBlock)
            output.write(hash)
        }

        return output.toByteArray()
    }

    private fun loadHeaderHashes(context: Context): List<ByteArray> {
        val hashes = mutableListOf(
            hashHexToWireBytes(genesisHash)
        )

        val file = File(context.filesDir, "vexta-headers.dat")

        if (!file.exists()) {
            return hashes
        }

        val data = file.readBytes()

        if (data.size % 80 != 0) {
            throw IllegalStateException(
                "Corrupt local block-header database"
            )
        }

        var offset = 0

        while (offset < data.size) {
            hashes.add(
                doubleSha256(
                    data.copyOfRange(offset, offset + 80)
                )
            )

            offset += 80
        }

        return hashes
    }

    private fun outPointKey(
        txidWire: ByteArray,
        index: Long
    ): String = "${txidWire.toHex()}:$index"

    private fun createVersionPayload(peerHost: String): ByteArray {
        val output = ByteArrayOutputStream()

        writeInt32LE(output, protocolVersion)
        writeInt64LE(output, 0)
        writeInt64LE(output, System.currentTimeMillis() / 1000)

        writeNetworkAddress(output, peerHost, port)
        writeNetworkAddress(output, "0.0.0.0", 0)

        writeInt64LE(output, Random.nextLong())
        writeVarString(output, "/VextaAndroidWallet:0.4.3/")
        writeInt32LE(output, 0)
        output.write(0)

        return output.toByteArray()
    }

    private fun readMessage(
        input: DataInputStream
    ): Pair<String, ByteArray> {
        val header = ByteArray(24)
        input.readFully(header)

        if (!header.copyOfRange(0, 4).contentEquals(magic)) {
            throw IllegalStateException("Invalid Vexta network magic")
        }

        val command = header.copyOfRange(4, 16)
            .takeWhile { it.toInt() != 0 }
            .toByteArray()
            .toString(Charsets.US_ASCII)

        val payloadLength = ByteBuffer
            .wrap(header, 16, 4)
            .order(ByteOrder.LITTLE_ENDIAN)
            .int

        if (payloadLength < 0 || payloadLength > 32_000_000) {
            throw IllegalStateException("Invalid P2P payload length")
        }

        val expectedChecksum = header.copyOfRange(20, 24)
        val payload = ByteArray(payloadLength)
        input.readFully(payload)

        val actualChecksum = doubleSha256(payload).copyOfRange(0, 4)

        if (!expectedChecksum.contentEquals(actualChecksum)) {
            throw IllegalStateException("Invalid P2P checksum")
        }

        return command to payload
    }

    private fun sendMessage(
        output: OutputStream,
        command: String,
        payload: ByteArray
    ) {
        val message = ByteArrayOutputStream()
        message.write(magic)

        val commandBytes = ByteArray(12)
        command.toByteArray(Charsets.US_ASCII).copyInto(
            commandBytes,
            endIndex = minOf(command.length, 12)
        )

        message.write(commandBytes)
        writeInt32LE(message, payload.size)
        message.write(doubleSha256(payload).copyOfRange(0, 4))
        message.write(payload)

        output.write(message.toByteArray())
        output.flush()
    }

    private fun writeNetworkAddress(
        output: ByteArrayOutputStream,
        host: String,
        port: Int
    ) {
        writeInt64LE(output, 0)

        val address = InetAddress.getByName(host).address
        val ipv6 = ByteArray(16)

        if (address.size == 4) {
            ipv6[10] = 0xff.toByte()
            ipv6[11] = 0xff.toByte()
            address.copyInto(ipv6, 12)
        } else {
            address.copyInto(ipv6)
        }

        output.write(ipv6)
        output.write((port shr 8) and 0xff)
        output.write(port and 0xff)
    }

    private fun writeVarString(
        output: ByteArrayOutputStream,
        value: String
    ) {
        val bytes = value.toByteArray(Charsets.UTF_8)
        writeCompactSize(output, bytes.size.toLong())
        output.write(bytes)
    }

    private fun writeCompactSize(
        output: ByteArrayOutputStream,
        value: Long
    ) {
        when {
            value < 253 -> output.write(value.toInt())

            value <= 0xffff -> {
                output.write(253)
                output.write((value and 0xff).toInt())
                output.write(((value shr 8) and 0xff).toInt())
            }

            value <= 0xffffffffL -> {
                output.write(254)

                repeat(4) { index ->
                    output.write(
                        ((value shr (8 * index)) and 0xff).toInt()
                    )
                }
            }

            else -> {
                output.write(255)

                repeat(8) { index ->
                    output.write(
                        ((value shr (8 * index)) and 0xff).toInt()
                    )
                }
            }
        }
    }

    private fun hashHexToWireBytes(hash: String): ByteArray =
        hash.chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
            .reversedArray()

    private fun ByteArray.toHex(): String =
        joinToString("") {
            "%02x".format(it.toInt() and 0xff)
        }

    private fun writeInt32LE(
        output: ByteArrayOutputStream,
        value: Int
    ) {
        output.write(
            ByteBuffer.allocate(4)
                .order(ByteOrder.LITTLE_ENDIAN)
                .putInt(value)
                .array()
        )
    }

    private fun writeInt64LE(
        output: ByteArrayOutputStream,
        value: Long
    ) {
        output.write(
            ByteBuffer.allocate(8)
                .order(ByteOrder.LITTLE_ENDIAN)
                .putLong(value)
                .array()
        )
    }

    private fun doubleSha256(data: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(digest.digest(data))
    }

    private class Cursor(
        private val data: ByteArray
    ) {
        private var offset = 0

        fun remaining(): Int = data.size - offset

        fun isFinished(): Boolean = offset == data.size

        fun peekByte(relativeOffset: Int): Int {
            require(offset + relativeOffset < data.size) {
                "Transaction data is truncated"
            }

            return data[offset + relativeOffset].toInt() and 0xff
        }

        fun readBytes(length: Int): ByteArray {
            require(length >= 0 && offset + length <= data.size) {
                "Transaction data is truncated"
            }

            val result = data.copyOfRange(offset, offset + length)
            offset += length
            return result
        }

        fun skip(length: Int) {
            require(length >= 0 && offset + length <= data.size) {
                "Transaction data is truncated"
            }

            offset += length
        }

        fun readCompactSize(): Long {
            val first = readBytes(1)[0].toInt() and 0xff

            return when (first) {
                in 0..252 -> first.toLong()

                253 -> {
                    val bytes = readBytes(2)

                    (bytes[0].toLong() and 0xff) or
                        ((bytes[1].toLong() and 0xff) shl 8)
                }

                254 -> {
                    val bytes = readBytes(4)
                    var value = 0L

                    repeat(4) { index ->
                        value = value or (
                            (bytes[index].toLong() and 0xff) shl
                                (8 * index)
                            )
                    }

                    value
                }

                else -> {
                    val bytes = readBytes(8)
                    var value = 0L

                    repeat(8) { index ->
                        value = value or (
                            (bytes[index].toLong() and 0xff) shl
                                (8 * index)
                            )
                    }

                    require(value >= 0) {
                        "CompactSize is too large"
                    }

                    value
                }
            }
        }
    }
}
