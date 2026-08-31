package org.vextaproject.wallet

import org.bitcoinj.core.ECKey
import org.bitcoinj.script.ScriptBuilder
import org.bitcoinj.params.MainNetParams
import org.bitcoinj.core.TransactionWitness
import org.bitcoinj.core.Utils
import org.bitcoinj.core.TransactionOutput
import org.bitcoinj.core.TransactionOutPoint
import org.bitcoinj.core.TransactionInput
import org.bitcoinj.core.Transaction
import org.bitcoinj.core.Coin
import org.bitcoinj.core.Sha256Hash
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import kotlin.random.Random

object VextaTransactionSender {

    private val magic = byteArrayOf(0x56, 0x54, 0x58, 0x31)
    private const val port = 19333
    private const val protocolVersion = 70018
    private const val sighashAll = 1L
    private const val sequence = 0xffffffffL
    private const val dustLimit = 546L
    private const val defaultFeeSatoshisPerKb = 100_000L

    data class CreatedTransaction(
        val rawTransaction: ByteArray,
        val txid: String,
        val amount: Long,
        val fee: Long,
        val change: Long,
        val inputCount: Int,
        val spentOutpoints: Set<String>
    )

    data class MaxSpend(
        val amount: Long,
        val fee: Long
    )

    private const val COINBASE_MATURITY = 100

    private fun validateCoinbaseMaturity(
        utxos: List<BlockScanner.SpendableUtxo>,
        chainHeight: Int
    ) {
        require(chainHeight >= 0) {
            "Invalid blockchain height"
        }

        val immatureCoinbase =
            utxos.firstOrNull { utxo ->
                utxo.isCoinbase &&
                    (
                        chainHeight < utxo.height ||
                            chainHeight - utxo.height + 1 <
                                COINBASE_MATURITY
                    )
            }

        require(immatureCoinbase == null) {
            "Immature mining reward cannot be spent before 100 confirmations"
        }
    }

    fun calculateMaxSpend(
        spendableUtxos: List<BlockScanner.SpendableUtxo>,
        chainHeight: Int
    ): MaxSpend {
        validateCoinbaseMaturity(
            spendableUtxos,
            chainHeight
        )

        require(spendableUtxos.isNotEmpty()) {
            "Wallet has no spendable outputs"
        }

        val total = spendableUtxos.fold(0L) { sum, utxo ->
            Math.addExact(sum, utxo.value)
        }

        val fee = estimateFee(
            inputCount = spendableUtxos.size,
            outputCount = 1
        )

        val amount = total - fee

        require(amount > 0L) {
            "Balance is too small to cover the transaction fee"
        }

        return MaxSpend(
            amount = amount,
            fee = fee
        )
    }

    fun createAndSign(
        spendableUtxos: List<BlockScanner.SpendableUtxo>,
        recipientAddress: String,
        amountSatoshis: Long,
        privateKeysByIndex: Map<Int, ECKey>,
        changePubKeyHash: ByteArray,
        chainHeight: Int
    ): CreatedTransaction {
        validateCoinbaseMaturity(
            spendableUtxos,
            chainHeight
        )
        require(amountSatoshis > 0L) {
            "Amount must be greater than zero"
        }

        require(changePubKeyHash.size == 20) {
            "Invalid change public-key hash"
        }

        require(privateKeysByIndex.isNotEmpty()) {
            "No wallet private keys supplied"
        }

        val recipientScript = addressToScript(recipientAddress)
        val changeScript =
            byteArrayOf(0x00, 0x14) + changePubKeyHash

        val orderedUtxos = spendableUtxos.sortedWith(
            compareBy<BlockScanner.SpendableUtxo> { it.height }
                .thenBy { it.txid }
                .thenBy { it.outputIndex }
        )

        val maxSpend =
            calculateMaxSpend(
                orderedUtxos,
                chainHeight
            )
        val sendingMaximum =
            amountSatoshis == maxSpend.amount

        val selected =
            mutableListOf<BlockScanner.SpendableUtxo>()

        var selectedValue = 0L
        var fee: Long
        var change: Long

        if (sendingMaximum) {
            selected.addAll(orderedUtxos)

            selectedValue = selected.fold(0L) { sum, utxo ->
                Math.addExact(sum, utxo.value)
            }

            fee = maxSpend.fee
            change = 0L
        } else {
            for (utxo in orderedUtxos) {
                selected.add(utxo)
                selectedValue =
                    Math.addExact(selectedValue, utxo.value)

                val estimatedFee = estimateFee(
                    inputCount = selected.size,
                    outputCount = 2
                )

                if (
                    selectedValue >=
                    amountSatoshis + estimatedFee
                ) {
                    break
                }
            }

            if (selected.isEmpty()) {
                throw IllegalStateException(
                    "Wallet has no spendable outputs"
                )
            }

            fee = estimateFee(
                inputCount = selected.size,
                outputCount = 2
            )

            if (selectedValue < amountSatoshis + fee) {
                throw IllegalStateException(
                    "Insufficient balance including transaction fee"
                )
            }

            change =
                selectedValue - amountSatoshis - fee
        }

        val outputs = mutableListOf(
            TransactionOutputData(
                value = amountSatoshis,
                script = recipientScript
            )
        )

        if (!sendingMaximum) {
            if (change >= dustLimit) {
                outputs.add(
                    TransactionOutputData(
                        value = change,
                        script = changeScript
                    )
                )
            } else {
                fee += change
                change = 0L
            }
        }

        /*
         * Network parameters do not affect transaction serialization or
         * SegWit signature hashing. Vexta uses Bitcoin-compatible transaction
         * and witness serialization, so bitcoinj's transaction implementation
         * can safely perform the BIP143 signature calculation.
         */
        val parameters = MainNetParams.get()
        val transaction = Transaction(parameters)
        transaction.setVersion(2)

        selected.forEach { utxo ->
            val outPoint = TransactionOutPoint(
                parameters,
                utxo.outputIndex,
                Sha256Hash.wrap(utxo.txid)
            )

            val input = TransactionInput(
                parameters,
                transaction,
                byteArrayOf(),
                outPoint,
                Coin.valueOf(utxo.value)
            )

            input.sequenceNumber = 0xffffffffL
            transaction.addInput(input)
        }

        outputs.forEach { output ->
            transaction.addOutput(
                TransactionOutput(
                    parameters,
                    transaction,
                    Coin.valueOf(output.value),
                    output.script
                )
            )
        }

        selected.forEachIndexed { index, utxo ->
            val privateKey =
                privateKeysByIndex[utxo.addressIndex]
                    ?: throw IllegalStateException(
                        "Missing private key for address index " +
                            utxo.addressIndex
                    )

            val walletPubKeyHash =
                Utils.sha256hash160(privateKey.pubKey)

            val scriptCode =
                ScriptBuilder.createP2PKHOutputScript(
                    walletPubKeyHash
                )

            val signature =
                transaction.calculateWitnessSignature(
                    index,
                    privateKey,
                    scriptCode,
                    Coin.valueOf(utxo.value),
                    Transaction.SigHash.ALL,
                    false
                )

            transaction.getInput(index.toLong()).setWitness(
                TransactionWitness.redeemP2WPKH(
                    signature,
                    privateKey
                )
            )
        }

        val rawTransaction =
            transaction.bitcoinSerialize()

        return CreatedTransaction(
            rawTransaction = rawTransaction,
            txid = transaction.txId.toString(),
            amount = amountSatoshis,
            fee = fee,
            change = change,
            inputCount = selected.size,
            spentOutpoints = selected.map {
                "${it.txid}:${it.outputIndex}"
            }.toSet()
        )
    }

    fun broadcast(
        transaction: CreatedTransaction,
        peers: List<String>
    ): Int {
        var successfulPeers = 0
        var lastError: Exception? = null

        peers.distinct().forEach { peer ->
            try {
                broadcastToPeer(peer, transaction.rawTransaction)
                successfulPeers++
            } catch (error: Exception) {
                lastError = error
            }
        }

        if (successfulPeers == 0) {
            throw lastError
                ?: IllegalStateException("Transaction broadcast failed")
        }

        return successfulPeers
    }

    private fun serializeTransaction(
        selected: List<BlockScanner.SpendableUtxo>,
        outputs: List<TransactionOutputData>,
        signatures: List<ByteArray>,
        publicKey: ByteArray,
        includeWitness: Boolean
    ): ByteArray {
        val output = ByteArrayOutputStream()

        writeInt32LE(output, 2)

        if (includeWitness) {
            output.write(0x00)
            output.write(0x01)
        }

        writeCompactSize(output, selected.size.toLong())

        selected.forEach { utxo ->
            output.write(hashDisplayToWire(utxo.txid))
            writeUInt32LE(output, utxo.outputIndex)
            output.write(0x00)
            writeUInt32LE(output, sequence)
        }

        output.write(serializeOutputs(outputs))

        if (includeWitness) {
            selected.indices.forEach { index ->
                output.write(0x02)

                val signature = signatures[index]
                writeCompactSize(output, signature.size.toLong())
                output.write(signature)

                writeCompactSize(output, publicKey.size.toLong())
                output.write(publicKey)
            }
        }

        writeUInt32LE(output, 0)
        return output.toByteArray()
    }

    private fun serializeOutputs(
        outputs: List<TransactionOutputData>
    ): ByteArray {
        return ByteArrayOutputStream().apply {
            writeCompactSize(this, outputs.size.toLong())

            outputs.forEach { transactionOutput ->
                writeInt64LE(this, transactionOutput.value)
                writeCompactSize(
                    this,
                    transactionOutput.script.size.toLong()
                )
                write(transactionOutput.script)
            }
        }.toByteArray()
    }

    private fun estimateFee(
        inputCount: Int,
        outputCount: Int
    ): Long {
        val virtualBytes =
            11L +
                inputCount * 69L +
                outputCount * 31L

        return (
            virtualBytes * defaultFeeSatoshisPerKb + 999L
        ) / 1_000L
    }

    private fun addressToScript(address: String): ByteArray {
        val value = address.trim()

        if (value.lowercase().startsWith("vtx1")) {
            val witnessProgram = decodeBech32Witness(value)

            require(witnessProgram.size == 20) {
                "Only Vexta P2WPKH addresses are supported"
            }

            return byteArrayOf(0x00, 0x14) + witnessProgram
        }

        val decoded = decodeBase58Check(value)

        require(decoded.size == 21) {
            "Invalid legacy Vexta address"
        }

        require((decoded[0].toInt() and 0xff) == 70) {
            "Wrong legacy Vexta address prefix"
        }

        val publicKeyHash = decoded.copyOfRange(1, 21)

        return byteArrayOf(
            0x76,
            0xa9.toByte(),
            0x14
        ) +
            publicKeyHash +
            byteArrayOf(
                0x88.toByte(),
                0xac.toByte()
            )
    }

    private fun decodeBech32Witness(address: String): ByteArray {
        require(address == address.lowercase()) {
            "Mixed-case Bech32 address"
        }

        val separator = address.lastIndexOf('1')

        require(separator > 0 && separator + 7 <= address.length) {
            "Invalid Bech32 address"
        }

        val hrp = address.substring(0, separator)
        require(hrp == "vtx") {
            "Wrong Bech32 network"
        }

        val charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
        val values = address.substring(separator + 1).map { character ->
            val index = charset.indexOf(character)
            require(index >= 0) {
                "Invalid Bech32 character"
            }
            index
        }

        require(bech32Polymod(expandHrp(hrp) + values) == 1) {
            "Invalid Bech32 checksum"
        }

        val data = values.dropLast(6)
        require(data.isNotEmpty() && data[0] == 0) {
            "Unsupported witness version"
        }

        return convertBits(
            data.drop(1),
            5,
            8,
            false
        ).map { it.toByte() }.toByteArray()
    }

    private fun convertBits(
        input: List<Int>,
        fromBits: Int,
        toBits: Int,
        pad: Boolean
    ): List<Int> {
        var accumulator = 0
        var bits = 0
        val result = mutableListOf<Int>()
        val maxValue = (1 shl toBits) - 1
        val maxAccumulator =
            (1 shl (fromBits + toBits - 1)) - 1

        input.forEach { value ->
            require(value >= 0 && value shr fromBits == 0) {
                "Invalid address data"
            }

            accumulator =
                ((accumulator shl fromBits) or value) and
                    maxAccumulator
            bits += fromBits

            while (bits >= toBits) {
                bits -= toBits
                result.add(
                    (accumulator shr bits) and maxValue
                )
            }
        }

        if (pad) {
            if (bits > 0) {
                result.add(
                    (accumulator shl (toBits - bits)) and
                        maxValue
                )
            }
        } else {
            require(bits < fromBits) {
                "Invalid address padding"
            }

            require(
                bits == 0 ||
                    ((accumulator shl (toBits - bits)) and
                        maxValue) == 0
            ) {
                "Non-zero address padding"
            }
        }

        return result
    }

    private fun expandHrp(hrp: String): List<Int> =
        hrp.map { it.code shr 5 } +
            listOf(0) +
            hrp.map { it.code and 31 }

    private fun bech32Polymod(values: List<Int>): Int {
        val generators = intArrayOf(
            0x3b6a57b2,
            0x26508e6d,
            0x1ea119fa,
            0x3d4233dd,
            0x2a1462b3
        )

        var checksum = 1

        values.forEach { value ->
            val top = checksum ushr 25
            checksum =
                ((checksum and 0x1ffffff) shl 5) xor value

            for (index in 0..4) {
                if (((top shr index) and 1) != 0) {
                    checksum =
                        checksum xor generators[index]
                }
            }
        }

        return checksum
    }

    private fun decodeBase58Check(value: String): ByteArray {
        val alphabet =
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

        var number = java.math.BigInteger.ZERO
        val base = java.math.BigInteger.valueOf(58)

        value.forEach { character ->
            val digit = alphabet.indexOf(character)

            require(digit >= 0) {
                "Invalid Base58 character"
            }

            number = number
                .multiply(base)
                .add(java.math.BigInteger.valueOf(digit.toLong()))
        }

        val rawNumber = number.toByteArray().let { bytes ->
            if (bytes.size > 1 && bytes[0].toInt() == 0) {
                bytes.copyOfRange(1, bytes.size)
            } else {
                bytes
            }
        }

        val leadingZeros = value.takeWhile { it == '1' }.length
        val decoded = ByteArray(leadingZeros) + rawNumber

        require(decoded.size >= 5) {
            "Invalid Base58 address"
        }

        val payload = decoded.copyOfRange(0, decoded.size - 4)
        val checksum = decoded.copyOfRange(
            decoded.size - 4,
            decoded.size
        )

        require(
            doubleSha256(payload)
                .copyOfRange(0, 4)
                .contentEquals(checksum)
        ) {
            "Invalid Base58 checksum"
        }

        return payload
    }

    private fun broadcastToPeer(
        peer: String,
        rawTransaction: ByteArray
    ) {
        Socket().use { socket ->
            socket.soTimeout = 5_000
            socket.connect(
                InetSocketAddress(peer, port),
                5_000
            )

            val input = DataInputStream(socket.getInputStream())
            val output = socket.getOutputStream()

            sendMessage(
                output,
                "version",
                createVersionPayload(peer)
            )

            var gotVersion = false
            var gotVerack = false
            var transactionSent = false

            repeat(100) {
                try {
                    val message = readMessage(input)

                    when (message.first) {
                        "version" -> {
                            gotVersion = true
                            sendMessage(
                                output,
                                "verack",
                                byteArrayOf()
                            )
                        }

                        "verack" -> gotVerack = true

                        "ping" -> sendMessage(
                            output,
                            "pong",
                            message.second
                        )

                        "reject" -> {
                            throw IllegalStateException(
                                parseRejectMessage(message.second)
                            )
                        }

                        "inv" -> {
                            if (transactionSent) {
                                return
                            }
                        }
                    }

                    if (
                        gotVersion &&
                        gotVerack &&
                        !transactionSent
                    ) {
                        sendMessage(
                            output,
                            "tx",
                            rawTransaction
                        )
                        transactionSent = true
                        socket.soTimeout = 5_000
                    }
                } catch (_: SocketTimeoutException) {
                    if (transactionSent) {
                        return
                    }

                    throw IllegalStateException(
                        "Peer handshake timed out"
                    )
                }
            }

            if (!transactionSent) {
                throw IllegalStateException(
                    "Peer handshake did not complete"
                )
            }
        }
    }

    private fun parseRejectMessage(
        payload: ByteArray
    ): String {
        return try {
            val buffer = ByteBuffer.wrap(payload)
                .order(ByteOrder.LITTLE_ENDIAN)

            val rejectedCommand =
                readRejectVarString(buffer)

            val code =
                if (buffer.hasRemaining()) {
                    buffer.get().toInt() and 0xff
                } else {
                    -1
                }

            val reason =
                if (buffer.hasRemaining()) {
                    readRejectVarString(buffer)
                } else {
                    "unknown reason"
                }

            "Peer rejected $rejectedCommand " +
                "(code $code): $reason"
        } catch (_: Exception) {
            "Peer rejected transaction"
        }
    }

    private fun readRejectVarString(
        buffer: ByteBuffer
    ): String {
        val length = readRejectCompactSize(buffer)

        require(
            length >= 0L &&
                length <= buffer.remaining().toLong() &&
                length <= 10_000L
        ) {
            "Invalid reject message"
        }

        val bytes = ByteArray(length.toInt())
        buffer.get(bytes)
        return bytes.toString(Charsets.UTF_8)
    }

    private fun readRejectCompactSize(
        buffer: ByteBuffer
    ): Long {
        val first = buffer.get().toInt() and 0xff

        return when (first) {
            253 -> buffer.short.toInt().and(0xffff).toLong()
            254 -> buffer.int.toLong().and(0xffffffffL)
            255 -> buffer.long
            else -> first.toLong()
        }
    }

    private fun createVersionPayload(
        peerHost: String
    ): ByteArray {
        return ByteArrayOutputStream().apply {
            writeInt32LE(this, protocolVersion)
            writeInt64LE(this, 0)
            writeInt64LE(
                this,
                System.currentTimeMillis() / 1000
            )
            writeNetworkAddress(this, peerHost, port)
            writeNetworkAddress(this, "0.0.0.0", 0)
            writeInt64LE(this, Random.nextLong())
            writeVarString(
                this,
                "/VextaAndroidWallet:0.4.3/"
            )
            writeInt32LE(this, 0)
            write(0)
        }.toByteArray()
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
        message.write(
            doubleSha256(payload).copyOfRange(0, 4)
        )
        message.write(payload)

        output.write(message.toByteArray())
        output.flush()
    }

    private fun readMessage(
        input: DataInputStream
    ): Pair<String, ByteArray> {
        val header = ByteArray(24)
        input.readFully(header)

        require(
            header.copyOfRange(0, 4)
                .contentEquals(magic)
        ) {
            "Invalid Vexta network message"
        }

        val command = header.copyOfRange(4, 16)
            .takeWhile { it.toInt() != 0 }
            .toByteArray()
            .toString(Charsets.US_ASCII)

        val payloadLength = ByteBuffer
            .wrap(header, 16, 4)
            .order(ByteOrder.LITTLE_ENDIAN)
            .int

        require(
            payloadLength in 0..4_000_000
        ) {
            "Invalid P2P payload length"
        }

        val payload = ByteArray(payloadLength)
        input.readFully(payload)

        val checksum = header.copyOfRange(20, 24)

        require(
            doubleSha256(payload)
                .copyOfRange(0, 4)
                .contentEquals(checksum)
        ) {
            "Invalid P2P checksum"
        }

        return command to payload
    }

    private fun writeNetworkAddress(
        output: ByteArrayOutputStream,
        host: String,
        targetPort: Int
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
        output.write((targetPort shr 8) and 0xff)
        output.write(targetPort and 0xff)
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
                output.write(
                    ((value shr 8) and 0xff).toInt()
                )
            }

            value <= 0xffffffffL -> {
                output.write(254)
                repeat(4) { index ->
                    output.write(
                        ((value shr (8 * index)) and 0xff)
                            .toInt()
                    )
                }
            }

            else -> {
                output.write(255)
                repeat(8) { index ->
                    output.write(
                        ((value shr (8 * index)) and 0xff)
                            .toInt()
                    )
                }
            }
        }
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

    private fun writeUInt32LE(
        output: ByteArrayOutputStream,
        value: Long
    ) {
        repeat(4) { index ->
            output.write(
                ((value shr (8 * index)) and 0xff)
                    .toInt()
            )
        }
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

    private fun hashDisplayToWire(
        hash: String
    ): ByteArray {
        require(hash.length == 64) {
            "Invalid transaction ID"
        }

        return hash.chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
            .reversedArray()
    }

    private fun doubleSha256(
        data: ByteArray
    ): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(digest.digest(data))
    }

    private fun ByteArray.toHex(): String =
        joinToString("") {
            "%02x".format(it.toInt() and 0xff)
        }

    private data class TransactionOutputData(
        val value: Long,
        val script: ByteArray
    )
}
