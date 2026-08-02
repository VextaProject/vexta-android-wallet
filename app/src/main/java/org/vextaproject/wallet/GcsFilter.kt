package org.vextaproject.wallet

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder

object GcsFilter {

    private const val P = 19
    private const val M = 784931L

    fun matches(
        encodedFilter: ByteArray,
        blockHashWire: ByteArray,
        element: ByteArray
    ): Boolean {
        require(blockHashWire.size == 32) {
            "Block hash must contain 32 bytes"
        }

        val compactSize = readCompactSize(encodedFilter, 0)
        val count = compactSize.first

        if (count == 0L) {
            return false
        }

        if (count > Int.MAX_VALUE) {
            throw IllegalArgumentException("Filter contains too many elements")
        }

        val key0 = readInt64LE(blockHashWire, 0)
        val key1 = readInt64LE(blockHashWire, 8)

        val range = BigInteger.valueOf(count)
            .multiply(BigInteger.valueOf(M))

        val sipHash = sipHash24(key0, key1, element)
        val query = mapIntoRange(sipHash, range)

        val reader = BitReader(
            encodedFilter,
            compactSize.second
        )

        var value = BigInteger.ZERO

        repeat(count.toInt()) {
            val quotient = reader.readUnary()
            val remainder = reader.readBits(P)

            val delta = BigInteger.valueOf(quotient)
                .shiftLeft(P)
                .add(BigInteger.valueOf(remainder))

            value = value.add(delta)

            val comparison = value.compareTo(query)

            if (comparison == 0) {
                return true
            }

            if (comparison > 0) {
                return false
            }
        }

        return false
    }

    private fun mapIntoRange(
        hash: Long,
        range: BigInteger
    ): BigInteger {
        val unsignedHash = if (hash >= 0) {
            BigInteger.valueOf(hash)
        } else {
            BigInteger.valueOf(hash and Long.MAX_VALUE)
                .setBit(63)
        }

        return unsignedHash
            .multiply(range)
            .shiftRight(64)
    }

    private fun readCompactSize(
        data: ByteArray,
        offset: Int
    ): Pair<Long, Int> {
        if (offset >= data.size) {
            throw IllegalArgumentException("Missing CompactSize")
        }

        val first = data[offset].toInt() and 0xff

        return when (first) {
            in 0..252 -> first.toLong() to offset + 1

            253 -> {
                require(offset + 3 <= data.size) {
                    "Truncated CompactSize"
                }

                val value =
                    (data[offset + 1].toLong() and 0xff) or
                        ((data[offset + 2].toLong() and 0xff) shl 8)

                value to offset + 3
            }

            254 -> {
                require(offset + 5 <= data.size) {
                    "Truncated CompactSize"
                }

                var value = 0L

                for (index in 0 until 4) {
                    value = value or (
                        (data[offset + 1 + index].toLong() and 0xff) shl
                            (8 * index)
                        )
                }

                value to offset + 5
            }

            else -> {
                require(offset + 9 <= data.size) {
                    "Truncated CompactSize"
                }

                var value = 0L

                for (index in 0 until 8) {
                    value = value or (
                        (data[offset + 1 + index].toLong() and 0xff) shl
                            (8 * index)
                        )
                }

                require(value >= 0) {
                    "CompactSize exceeds signed Long range"
                }

                value to offset + 9
            }
        }
    }

    private fun readInt64LE(
        data: ByteArray,
        offset: Int
    ): Long {
        return ByteBuffer.wrap(data, offset, 8)
            .order(ByteOrder.LITTLE_ENDIAN)
            .long
    }

    private fun sipHash24(
        key0: Long,
        key1: Long,
        data: ByteArray
    ): Long {
        var v0 = key0 xor 0x736f6d6570736575L
        var v1 = key1 xor 0x646f72616e646f6dL
        var v2 = key0 xor 0x6c7967656e657261L
        var v3 = key1 xor 0x7465646279746573L

        var offset = 0

        while (offset + 8 <= data.size) {
            val message = readInt64LE(data, offset)
            v3 = v3 xor message

            repeat(2) {
                val result = sipRound(v0, v1, v2, v3)
                v0 = result[0]
                v1 = result[1]
                v2 = result[2]
                v3 = result[3]
            }

            v0 = v0 xor message
            offset += 8
        }

        var finalBlock = data.size.toLong() shl 56
        var shift = 0

        while (offset < data.size) {
            finalBlock = finalBlock or (
                (data[offset].toLong() and 0xff) shl shift
                )

            shift += 8
            offset++
        }

        v3 = v3 xor finalBlock

        repeat(2) {
            val result = sipRound(v0, v1, v2, v3)
            v0 = result[0]
            v1 = result[1]
            v2 = result[2]
            v3 = result[3]
        }

        v0 = v0 xor finalBlock
        v2 = v2 xor 0xffL

        repeat(4) {
            val result = sipRound(v0, v1, v2, v3)
            v0 = result[0]
            v1 = result[1]
            v2 = result[2]
            v3 = result[3]
        }

        return v0 xor v1 xor v2 xor v3
    }

    private fun sipRound(
        input0: Long,
        input1: Long,
        input2: Long,
        input3: Long
    ): LongArray {
        var v0 = input0
        var v1 = input1
        var v2 = input2
        var v3 = input3

        v0 += v1
        v1 = java.lang.Long.rotateLeft(v1, 13)
        v1 = v1 xor v0
        v0 = java.lang.Long.rotateLeft(v0, 32)

        v2 += v3
        v3 = java.lang.Long.rotateLeft(v3, 16)
        v3 = v3 xor v2

        v0 += v3
        v3 = java.lang.Long.rotateLeft(v3, 21)
        v3 = v3 xor v0

        v2 += v1
        v1 = java.lang.Long.rotateLeft(v1, 17)
        v1 = v1 xor v2
        v2 = java.lang.Long.rotateLeft(v2, 32)

        return longArrayOf(v0, v1, v2, v3)
    }

    private class BitReader(
        private val data: ByteArray,
        startOffset: Int
    ) {
        private var byteOffset = startOffset
        private var bitOffset = 0

        fun readUnary(): Long {
            var value = 0L

            while (readBit()) {
                value++

                if (value > Int.MAX_VALUE) {
                    throw IllegalArgumentException(
                        "Invalid Golomb-Rice quotient"
                    )
                }
            }

            return value
        }

        fun readBits(count: Int): Long {
            var value = 0L

            repeat(count) {
                value = (value shl 1) or
                    if (readBit()) 1L else 0L
            }

            return value
        }

        private fun readBit(): Boolean {
            if (byteOffset >= data.size) {
                throw IllegalArgumentException(
                    "Unexpected end of GCS filter"
                )
            }

            val bit =
                (data[byteOffset].toInt() ushr (7 - bitOffset)) and 1

            bitOffset++

            if (bitOffset == 8) {
                bitOffset = 0
                byteOffset++
            }

            return bit == 1
        }
    }
}
