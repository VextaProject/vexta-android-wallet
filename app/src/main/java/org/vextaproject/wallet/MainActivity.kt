package org.vextaproject.wallet

import android.app.Activity
import android.graphics.Color
import android.os.Bundle
import android.view.Gravity
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.File
import java.io.OutputStream
import java.math.BigInteger
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import kotlin.random.Random

class MainActivity : Activity() {

    private lateinit var status: TextView

    companion object {
        private val MAGIC = byteArrayOf(0x56, 0x54, 0x58, 0x31)
        private const val PORT = 19333
        private const val PROTOCOL_VERSION = 70018

        private const val GENESIS_HASH =
            "0000027626959d894ae1c8a6f9050cdcbdf58eb0037ab06345cb5502955370f1"

        private const val GENESIS_TIME = 1782770400L
        private const val GENESIS_BITS = 0x1e0ffff0L

        private const val AVERAGING_WINDOW = 10
        private const val TARGET_SPACING = 600L
        private const val TARGET_TIMESPAN = AVERAGING_WINDOW * TARGET_SPACING
        private const val MIN_TIMESPAN = TARGET_TIMESPAN * 92 / 100
        private const val MAX_TIMESPAN = TARGET_TIMESPAN * 116 / 100

        private val POW_LIMIT =
            BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE).shiftRight(20)
    }

    data class VersionInfo(
        val protocol: Int,
        val height: Int,
        val userAgent: String
    )

    data class ChainHeader(
        val height: Int,
        val raw: ByteArray?,
        val hashWire: ByteArray,
        val hashDisplay: String,
        val time: Long,
        val bits: Long
    )

    data class SyncResult(
        val received: Int,
        val cachedBefore: Int,
        val chainHeight: Int,
        val lastHash: String
    )

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

        setContentView(ScrollView(this).apply { addView(layout) })

        startSync()
    }

    private fun startSync() {
        Thread {
            try {
                val chain = loadCachedChain()
                val cachedAtStart = chain.last().height

                val peers = listOf(
                    "87.106.99.23",
                    "74.208.53.160"
                )

                val results = mutableListOf<String>()
                var successfulPeerSyncs = 0

                for ((index, peer) in peers.withIndex()) {
                    try {
                        val result = syncFromPeer(peer, chain)

                        if (result.received > 0) {
                            saveChain(chain)
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
                            "$peer:$PORT\nFailed: ${e.message ?: e.javaClass.simpleName}"
                        )
                    }
                }

                runOnUiThread {
                    if (intent.getBooleanExtra("sync_only", false)) {
                        if (
                            successfulPeerSyncs > 0 &&
                            chain.last().height > 0
                        ) {
                            setResult(
                                RESULT_OK,
                                android.content.Intent().putExtra(
                                    "verified_height",
                                    chain.last().height
                                )
                            )
                        } else {
                            setResult(
                                RESULT_CANCELED,
                                android.content.Intent().putExtra(
                                    "sync_error",
                                    results.joinToString("\n\n")
                                )
                            )
                        }
                        finish()
                    } else {
                        status.text =
                            "\nVexta SPV verification\n\n" +
                            "Initial cached height: $cachedAtStart\n" +
                            "Stored header file: " +
                            "${chain.last().height} blocks\n\n" +
                            results.joinToString(
                                "\n\n--------------------\n\n"
                            )
                    }
                }
            } catch (e: Exception) {
                runOnUiThread {
                    if (intent.getBooleanExtra("sync_only", false)) {
                        setResult(RESULT_CANCELED)
                        finish()
                    } else {
                        status.text =
                            "\nVerification failed\n\n" +
                            (e.message ?: e.javaClass.simpleName)
                    }
                }
            }
        }.start()
    }

    private fun loadCachedChain(): MutableList<ChainHeader> {
        val chain = mutableListOf(
            ChainHeader(
                height = 0,
                raw = null,
                hashWire = hashHexToWireBytes(GENESIS_HASH),
                hashDisplay = GENESIS_HASH,
                time = GENESIS_TIME,
                bits = GENESIS_BITS
            )
        )

        val file = File(filesDir, "vexta-headers.dat")

        if (!file.exists()) {
            return chain
        }

        val data = file.readBytes()

        if (data.size % 80 != 0) {
            file.delete()
            return chain
        }

        try {
            var offset = 0

            while (offset < data.size) {
                val raw = data.copyOfRange(offset, offset + 80)
                appendVerifiedHeader(chain, raw)
                offset += 80
            }
        } catch (_: Exception) {
            file.delete()
            return mutableListOf(chain.first())
        }

        return chain
    }

    private fun saveChain(chain: List<ChainHeader>) {
        val file = File(filesDir, "vexta-headers.dat")
        val temporary = File(filesDir, "vexta-headers.tmp")

        temporary.outputStream().use { output ->
            chain.drop(1).forEach { header ->
                output.write(
                    header.raw
                        ?: throw IllegalStateException("missing stored header")
                )
            }
        }

        if (file.exists()) {
            file.delete()
        }

        if (!temporary.renameTo(file)) {
            throw IllegalStateException("unable to save header database")
        }
    }

    private fun syncFromPeer(
        host: String,
        chain: MutableList<ChainHeader>
    ): SyncResult {
        Socket().use { socket ->
            socket.soTimeout = 15000
            socket.connect(InetSocketAddress(host, PORT), 5000)

            val input = DataInputStream(socket.getInputStream())
            val output = socket.getOutputStream()

            sendMessage(output, "version", createVersionPayload(host))

            var versionInfo: VersionInfo? = null
            var gotVerack = false
            var requested = false
            var totalReceived = 0
            val cachedBefore = chain.last().height

            repeat(200) {
                val message = readMessage(input)

                when (message.first) {
                    "version" -> {
                        versionInfo = parseVersionPayload(message.second)
                        sendMessage(output, "verack", byteArrayOf())
                    }

                    "verack" -> gotVerack = true

                    "ping" -> sendMessage(output, "pong", message.second)

                    "headers" -> {
                        val received = parseHeaders(message.second, chain)
                        totalReceived += received

                        val remote = versionInfo
                            ?: throw IllegalStateException("missing node version")

                        if (chain.last().height > remote.height) {
                            throw IllegalStateException(
                                "local verified chain exceeds peer height"
                            )
                        }

                        if (chain.last().height < remote.height) {
                            if (received == 0) {
                                throw IllegalStateException(
                                    "peer advertises height ${remote.height} " +
                                        "but returned no additional headers"
                                )
                            }

                            sendMessage(
                                output,
                                "getheaders",
                                createGetHeadersPayload(chain)
                            )

                            return@repeat
                        }

                        return SyncResult(
                            received = totalReceived,
                            cachedBefore = cachedBefore,
                            chainHeight = chain.last().height,
                            lastHash = chain.last().hashDisplay
                        )
                    }
                }

                if (versionInfo != null && gotVerack && !requested) {
                    sendMessage(
                        output,
                        "getheaders",
                        createGetHeadersPayload(chain)
                    )
                    requested = true
                }
            }

            throw IllegalStateException("headers response timeout")
        }
    }

    private fun parseHeaders(
        payload: ByteArray,
        chain: MutableList<ChainHeader>
    ): Int {
        val buffer = ByteBuffer.wrap(payload).order(ByteOrder.LITTLE_ENDIAN)
        val count = readCompactSize(buffer)

        val maximumPossibleHeaders =
            buffer.remaining() / 81

        if (count < 0 || count > maximumPossibleHeaders) {
            throw IllegalStateException(
                "invalid headers count: $count"
            )
        }

        val receivedHeaders = mutableListOf<ByteArray>()

        repeat(count) {
            if (buffer.remaining() < 81) {
                throw IllegalStateException("truncated headers message")
            }

            val raw = ByteArray(80)
            buffer.get(raw)

            val transactionCount = readCompactSize(buffer)

            if (transactionCount != 0) {
                throw IllegalStateException(
                    "headers message contains transactions"
                )
            }

            receivedHeaders.add(raw)
        }

        if (receivedHeaders.isNotEmpty()) {
            val firstPreviousHash =
                receivedHeaders.first().copyOfRange(4, 36)

            if (!firstPreviousHash.contentEquals(chain.last().hashWire)) {
                val ancestorIndex =
                    chain.indexOfLast {
                        it.hashWire.contentEquals(firstPreviousHash)
                    }

                if (ancestorIndex < 0) {
                    throw IllegalStateException(
                        "peer returned headers with no common ancestor"
                    )
                }

                while (chain.lastIndex > ancestorIndex) {
                    chain.removeAt(chain.lastIndex)
                }
            }

            receivedHeaders.forEach { raw ->
                appendVerifiedHeader(chain, raw)
            }
        }

        return count
    }

    private fun appendVerifiedHeader(
        chain: MutableList<ChainHeader>,
        raw: ByteArray
    ) {
        val previous = chain.last()
        val previousHash = raw.copyOfRange(4, 36)

        if (!previousHash.contentEquals(previous.hashWire)) {
            throw IllegalStateException(
                "header linkage failed at height ${previous.height + 1}"
            )
        }

        val buffer = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN)
        val time = buffer.getInt(68).toLong() and 0xffffffffL
        val bits = buffer.getInt(72).toLong() and 0xffffffffL

        val target = compactToTarget(bits)

        if (target <= BigInteger.ZERO || target > POW_LIMIT) {
            throw IllegalStateException(
                "invalid target at height ${previous.height + 1}"
            )
        }

        val hashWire = doubleSha256(raw)
        val hashNumber = BigInteger(1, hashWire.reversedArray())

        if (hashNumber > target) {
            throw IllegalStateException(
                "proof of work failed at height ${previous.height + 1}"
            )
        }

        val expectedBits = expectedBits(chain)

        if (bits != expectedBits) {
            throw IllegalStateException(
                "difficulty mismatch at height ${previous.height + 1}: " +
                    "expected ${expectedBits.toString(16)}, " +
                    "received ${bits.toString(16)}"
            )
        }

        chain.add(
            ChainHeader(
                height = previous.height + 1,
                raw = raw,
                hashWire = hashWire,
                hashDisplay = hashWire.reversedArray().toHex(),
                time = time,
                bits = bits
            )
        )
    }

    private fun expectedBits(chain: List<ChainHeader>): Long {
        val last = chain.last()

        if (last.height < AVERAGING_WINDOW) {
            return targetToCompact(POW_LIMIT)
        }

        val first = chain[last.height - AVERAGING_WINDOW]

        var actualTimespan =
            medianTimePast(chain, last.height) -
                medianTimePast(chain, first.height)

        actualTimespan =
            TARGET_TIMESPAN +
                (actualTimespan - TARGET_TIMESPAN) / 4

        actualTimespan = actualTimespan.coerceIn(
            MIN_TIMESPAN,
            MAX_TIMESPAN
        )

        var newTarget =
            compactToTarget(last.bits)
                .multiply(BigInteger.valueOf(actualTimespan))
                .divide(BigInteger.valueOf(TARGET_TIMESPAN))

        if (newTarget > POW_LIMIT) {
            newTarget = POW_LIMIT
        }

        return targetToCompact(newTarget)
    }

    private fun medianTimePast(
        chain: List<ChainHeader>,
        height: Int
    ): Long {
        val start = maxOf(0, height - 10)
        val times = (start..height)
            .map { chain[it].time }
            .sorted()

        return times[times.size / 2]
    }

    private fun compactToTarget(compact: Long): BigInteger {
        val size = ((compact ushr 24) and 0xff).toInt()
        var word = compact and 0x007fffffL

        var value = BigInteger.valueOf(word)

        value = if (size <= 3) {
            value.shiftRight(8 * (3 - size))
        } else {
            value.shiftLeft(8 * (size - 3))
        }

        return if ((compact and 0x00800000L) != 0L) {
            value.negate()
        } else {
            value
        }
    }

    private fun targetToCompact(targetValue: BigInteger): Long {
        if (targetValue == BigInteger.ZERO) {
            return 0
        }

        val negative = targetValue.signum() < 0
        val target = targetValue.abs()

        var size = (target.bitLength() + 7) / 8

        var compact = if (size <= 3) {
            target.toLong() shl (8 * (3 - size))
        } else {
            target.shiftRight(8 * (size - 3)).toLong()
        }

        if ((compact and 0x00800000L) != 0L) {
            compact = compact ushr 8
            size++
        }

        compact = compact and 0x007fffffL
        compact = compact or (size.toLong() shl 24)

        if (negative && (compact and 0x007fffffL) != 0L) {
            compact = compact or 0x00800000L
        }

        return compact
    }

    private fun createGetHeadersPayload(chain: List<ChainHeader>): ByteArray {
        val out = ByteArrayOutputStream()
        val locator = mutableListOf<ByteArray>()

        var index = chain.lastIndex
        var step = 1

        while (index >= 0) {
            locator.add(chain[index].hashWire)

            if (index == 0) {
                break
            }

            index = (index - step).coerceAtLeast(0)

            if (locator.size >= 10) {
                step *= 2
            }
        }

        if (!locator.last().contentEquals(chain.first().hashWire)) {
            locator.add(chain.first().hashWire)
        }

        writeInt32LE(out, PROTOCOL_VERSION)
        writeCompactSize(out, locator.size)

        locator.forEach { hash ->
            out.write(hash)
        }

        out.write(ByteArray(32))

        return out.toByteArray()
    }

    private fun readMessage(input: DataInputStream): Pair<String, ByteArray> {
        val header = ByteArray(24)
        input.readFully(header)

        if (!header.copyOfRange(0, 4).contentEquals(MAGIC)) {
            throw IllegalStateException("invalid Vexta network magic")
        }

        val command = header.copyOfRange(4, 16)
            .takeWhile { it.toInt() != 0 }
            .toByteArray()
            .toString(Charsets.US_ASCII)

        val payloadLength = ByteBuffer.wrap(header, 16, 4)
            .order(ByteOrder.LITTLE_ENDIAN)
            .int

        if (payloadLength < 0 || payloadLength > 4_000_000) {
            throw IllegalStateException("invalid payload length")
        }

        val expectedChecksum = header.copyOfRange(20, 24)
        val payload = ByteArray(payloadLength)
        input.readFully(payload)

        val actualChecksum = doubleSha256(payload).copyOfRange(0, 4)

        if (!expectedChecksum.contentEquals(actualChecksum)) {
            throw IllegalStateException("invalid message checksum")
        }

        return command to payload
    }

    private fun createVersionPayload(peerHost: String): ByteArray {
        val out = ByteArrayOutputStream()

        writeInt32LE(out, PROTOCOL_VERSION)
        writeInt64LE(out, 0)
        writeInt64LE(out, System.currentTimeMillis() / 1000)

        writeNetworkAddress(out, peerHost, PORT)
        writeNetworkAddress(out, "0.0.0.0", 0)

        writeInt64LE(out, Random.nextLong())
        writeVarString(out, "/VextaAndroidWallet:0.1.0/")
        writeInt32LE(out, 0)
        out.write(0)

        return out.toByteArray()
    }

    private fun parseVersionPayload(payload: ByteArray): VersionInfo {
        val buffer = ByteBuffer.wrap(payload).order(ByteOrder.LITTLE_ENDIAN)

        if (payload.size < 80) {
            throw IllegalStateException("short version payload")
        }

        val version = buffer.int
        buffer.long
        buffer.long
        buffer.position(buffer.position() + 26)
        buffer.position(buffer.position() + 26)
        buffer.long

        val userAgent = readVarString(buffer)
        val height = if (buffer.remaining() >= 4) buffer.int else 0

        return VersionInfo(version, height, userAgent)
    }

    private fun sendMessage(
        output: OutputStream,
        command: String,
        payload: ByteArray
    ) {
        val message = ByteArrayOutputStream()

        message.write(MAGIC)

        val commandBytes = ByteArray(12)
        command.toByteArray(Charsets.US_ASCII).copyInto(
            destination = commandBytes,
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
        out: ByteArrayOutputStream,
        host: String,
        port: Int
    ) {
        writeInt64LE(out, 0)

        val address = InetAddress.getByName(host).address
        val ipv6 = ByteArray(16)

        if (address.size == 4) {
            ipv6[10] = 0xff.toByte()
            ipv6[11] = 0xff.toByte()
            address.copyInto(ipv6, 12)
        } else {
            address.copyInto(ipv6)
        }

        out.write(ipv6)
        out.write((port shr 8) and 0xff)
        out.write(port and 0xff)
    }

    private fun writeVarString(out: ByteArrayOutputStream, value: String) {
        val bytes = value.toByteArray(Charsets.UTF_8)
        writeCompactSize(out, bytes.size)
        out.write(bytes)
    }

    private fun readVarString(buffer: ByteBuffer): String {
        val length = readCompactSize(buffer)

        if (length > buffer.remaining()) {
            throw IllegalStateException("invalid string length")
        }

        val bytes = ByteArray(length)
        buffer.get(bytes)

        return bytes.toString(Charsets.UTF_8)
    }

    private fun writeCompactSize(out: ByteArrayOutputStream, value: Int) {
        when {
            value < 253 -> out.write(value)

            value <= 0xffff -> {
                out.write(253)
                out.write(value and 0xff)
                out.write((value shr 8) and 0xff)
            }

            else -> {
                out.write(254)
                writeInt32LE(out, value)
            }
        }
    }

    private fun readCompactSize(buffer: ByteBuffer): Int {
        if (!buffer.hasRemaining()) {
            throw IllegalStateException("missing compact size")
        }

        return when (val first = buffer.get().toInt() and 0xff) {
            253 -> buffer.short.toInt() and 0xffff
            254 -> buffer.int

            255 -> {
                val value = buffer.long

                if (value < 0 || value > Int.MAX_VALUE) {
                    throw IllegalStateException("compact size too large")
                }

                value.toInt()
            }

            else -> first
        }
    }

    private fun hashHexToWireBytes(hash: String): ByteArray =
        hash.removePrefix("0x")
            .chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
            .reversedArray()

    private fun ByteArray.toHex(): String =
        joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun writeInt32LE(out: ByteArrayOutputStream, value: Int) {
        out.write(
            ByteBuffer.allocate(4)
                .order(ByteOrder.LITTLE_ENDIAN)
                .putInt(value)
                .array()
        )
    }

    private fun writeInt64LE(out: ByteArrayOutputStream, value: Long) {
        out.write(
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
}
