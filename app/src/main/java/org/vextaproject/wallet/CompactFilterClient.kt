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

object CompactFilterClient {

    private val magic = byteArrayOf(0x56, 0x54, 0x58, 0x31)
    private const val port = 19333
    private const val protocolVersion = 70018
    private const val compactFiltersService = 1L shl 6
    private const val maxFiltersPerRequest = 1000

    private const val genesisHash =
        "0000027626959d894ae1c8a6f9050cdcbdf58eb0037ab06345cb5502955370f1"

    data class AvailabilityResult(
        val peer: String,
        val servicesCompactFilters: Boolean,
        val filterHashesReceived: Int
    )

    data class ScanResult(
        val peer: String,
        val scannedFilters: Int,
        val matchingHeights: List<Int>,
        val localHeaderHeight: Int
    )

    fun check(peer: String): AvailabilityResult {
        Socket().use { socket ->
            socket.soTimeout = 15000
            socket.connect(InetSocketAddress(peer, port), 5000)

            val input = DataInputStream(socket.getInputStream())
            val output = socket.getOutputStream()

            sendMessage(output, "version", createVersionPayload(peer))

            var compactFiltersAvailable = false
            var gotVersion = false
            var gotVerack = false
            var requested = false

            repeat(100) {
                val (command, payload) = readMessage(input)

                when (command) {
                    "version" -> {
                        val services = parseServices(payload)
                        compactFiltersAvailable =
                            (services and compactFiltersService) != 0L

                        gotVersion = true
                        sendMessage(output, "verack", byteArrayOf())
                    }

                    "verack" -> gotVerack = true
                    "ping" -> sendMessage(output, "pong", payload)

                    "cfheaders" -> {
                        if (payload.size < 66) {
                            throw IllegalStateException(
                                "short cfheaders payload"
                            )
                        }

                        val buffer = ByteBuffer.wrap(payload)
                            .order(ByteOrder.LITTLE_ENDIAN)

                        val filterType = buffer.get().toInt() and 0xff

                        if (filterType != 0) {
                            throw IllegalStateException(
                                "unexpected filter type $filterType"
                            )
                        }

                        buffer.position(buffer.position() + 64)
                        val count = readCompactSize(buffer)

                        return AvailabilityResult(
                            peer,
                            compactFiltersAvailable,
                            count
                        )
                    }
                }

                if (
                    gotVersion &&
                    gotVerack &&
                    compactFiltersAvailable &&
                    !requested
                ) {
                    sendMessage(
                        output,
                        "getcfheaders",
                        createGetCfHeadersPayload()
                    )
                    requested = true
                }

                if (
                    gotVersion &&
                    gotVerack &&
                    !compactFiltersAvailable
                ) {
                    return AvailabilityResult(peer, false, 0)
                }
            }

            throw IllegalStateException("compact filter response timeout")
        }
    }

    fun scan(
        context: Context,
        peer: String,
        scriptPubKey: ByteArray,
        progress: (Int, Int) -> Unit
    ): ScanResult {
        val headerHashes = loadHeaderHashes(context)
        val localHeight = headerHashes.lastIndex

        if (localHeight < 1) {
            throw IllegalStateException(
                "No locally verified block headers available"
            )
        }

        Socket().use { socket ->
            socket.soTimeout = 30000
            socket.connect(InetSocketAddress(peer, port), 5000)

            val input = DataInputStream(socket.getInputStream())
            val output = socket.getOutputStream()

            sendMessage(output, "version", createVersionPayload(peer))

            var compactFiltersAvailable = false
            var gotVersion = false
            var gotVerack = false
            var nextHeight = 1
            var requestedEndHeight = 0
            var receivedInBatch = 0
            var totalScanned = 0
            val matches = mutableListOf<Int>()

            repeat(100000) {
                val (command, payload) = readMessage(input)

                when (command) {
                    "version" -> {
                        val services = parseServices(payload)
                        compactFiltersAvailable =
                            (services and compactFiltersService) != 0L

                        gotVersion = true
                        sendMessage(output, "verack", byteArrayOf())
                    }

                    "verack" -> gotVerack = true
                    "ping" -> sendMessage(output, "pong", payload)

                    "cfilter" -> {
                        val filter = parseCFilter(payload)
                        val expectedHeight = nextHeight + receivedInBatch
                        val expectedHash = headerHashes[expectedHeight]

                        if (!filter.blockHashWire.contentEquals(expectedHash)) {
                            throw IllegalStateException(
                                "Unexpected filter block hash at height " +
                                    expectedHeight
                            )
                        }

                        if (
                            GcsFilter.matches(
                                filter.encodedFilter,
                                filter.blockHashWire,
                                scriptPubKey
                            )
                        ) {
                            matches.add(expectedHeight)
                        }

                        receivedInBatch++
                        totalScanned++
                        progress(totalScanned, localHeight)

                        if (
                            nextHeight + receivedInBatch - 1 ==
                            requestedEndHeight
                        ) {
                            nextHeight = requestedEndHeight + 1
                            receivedInBatch = 0

                            if (nextHeight > localHeight) {
                                return ScanResult(
                                    peer,
                                    totalScanned,
                                    matches,
                                    localHeight
                                )
                            }

                            requestedEndHeight = minOf(
                                nextHeight + maxFiltersPerRequest - 1,
                                localHeight
                            )

                            sendMessage(
                                output,
                                "getcfilters",
                                createGetCFiltersPayload(
                                    nextHeight,
                                    headerHashes[requestedEndHeight]
                                )
                            )
                        }
                    }
                }

                if (
                    gotVersion &&
                    gotVerack &&
                    compactFiltersAvailable &&
                    requestedEndHeight == 0
                ) {
                    requestedEndHeight = minOf(
                        maxFiltersPerRequest,
                        localHeight
                    )

                    sendMessage(
                        output,
                        "getcfilters",
                        createGetCFiltersPayload(
                            nextHeight,
                            headerHashes[requestedEndHeight]
                        )
                    )
                }

                if (
                    gotVersion &&
                    gotVerack &&
                    !compactFiltersAvailable
                ) {
                    throw IllegalStateException(
                        "Peer does not provide compact filters"
                    )
                }
            }

            throw IllegalStateException("filter scan did not complete")
        }
    }

    private data class ParsedCFilter(
        val blockHashWire: ByteArray,
        val encodedFilter: ByteArray
    )

    private fun parseCFilter(payload: ByteArray): ParsedCFilter {
        if (payload.size < 34) {
            throw IllegalStateException("short cfilter payload")
        }

        val filterType = payload[0].toInt() and 0xff

        if (filterType != 0) {
            throw IllegalStateException(
                "unexpected filter type $filterType"
            )
        }

        val blockHashWire = payload.copyOfRange(1, 33)
        val buffer = ByteBuffer.wrap(payload)
            .order(ByteOrder.LITTLE_ENDIAN)

        buffer.position(33)
        val filterLength = readCompactSize(buffer)

        if (filterLength < 0 || filterLength > buffer.remaining()) {
            throw IllegalStateException("invalid cfilter length")
        }

        val encodedFilter = ByteArray(filterLength)
        buffer.get(encodedFilter)

        return ParsedCFilter(blockHashWire, encodedFilter)
    }

    private fun loadHeaderHashes(context: Context): List<ByteArray> {
        val result = mutableListOf(
            hashHexToWireBytes(genesisHash)
        )

        val file = File(context.filesDir, "vexta-headers.dat")

        if (!file.exists()) {
            return result
        }

        val data = file.readBytes()

        if (data.size % 80 != 0) {
            throw IllegalStateException("Corrupt local header database")
        }

        var offset = 0

        while (offset < data.size) {
            val header = data.copyOfRange(offset, offset + 80)
            result.add(doubleSha256(header))
            offset += 80
        }

        return result
    }

    private fun createGetCFiltersPayload(
        startHeight: Int,
        stopHashWire: ByteArray
    ): ByteArray {
        val output = ByteArrayOutputStream()

        output.write(0)
        writeInt32LE(output, startHeight)
        output.write(stopHashWire)

        return output.toByteArray()
    }

    private fun createGetCfHeadersPayload(): ByteArray {
        val output = ByteArrayOutputStream()

        output.write(0)
        writeInt32LE(output, 0)
        output.write(hashHexToWireBytes(genesisHash))

        return output.toByteArray()
    }

    private fun parseServices(payload: ByteArray): Long {
        if (payload.size < 12) {
            throw IllegalStateException("short version payload")
        }

        return ByteBuffer.wrap(payload)
            .order(ByteOrder.LITTLE_ENDIAN)
            .apply { int }
            .long
    }

    private fun createVersionPayload(peerHost: String): ByteArray {
        val output = ByteArrayOutputStream()

        writeInt32LE(output, protocolVersion)
        writeInt64LE(output, 0)
        writeInt64LE(output, System.currentTimeMillis() / 1000)

        writeNetworkAddress(output, peerHost, port)
        writeNetworkAddress(output, "0.0.0.0", 0)

        writeInt64LE(output, Random.nextLong())
        writeVarString(output, "/VextaAndroidWallet:0.1.0/")
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
        writeCompactSize(output, bytes.size)
        output.write(bytes)
    }

    private fun writeCompactSize(
        output: ByteArrayOutputStream,
        value: Int
    ) {
        when {
            value < 253 -> output.write(value)

            value <= 0xffff -> {
                output.write(253)
                output.write(value and 0xff)
                output.write((value shr 8) and 0xff)
            }

            else -> {
                output.write(254)
                writeInt32LE(output, value)
            }
        }
    }

    private fun readCompactSize(buffer: ByteBuffer): Int {
        if (!buffer.hasRemaining()) {
            throw IllegalStateException("missing CompactSize")
        }

        return when (val first = buffer.get().toInt() and 0xff) {
            253 -> buffer.short.toInt() and 0xffff
            254 -> buffer.int

            255 -> {
                val value = buffer.long

                if (value < 0 || value > Int.MAX_VALUE) {
                    throw IllegalStateException(
                        "CompactSize too large"
                    )
                }

                value.toInt()
            }

            else -> first
        }
    }

    private fun hashHexToWireBytes(hash: String): ByteArray =
        hash.chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
            .reversedArray()

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
}
