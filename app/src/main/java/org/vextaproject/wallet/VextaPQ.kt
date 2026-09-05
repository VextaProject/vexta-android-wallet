package org.vextaproject.wallet

object VextaPQ {
    init {
        System.loadLibrary("vextapq")
    }

    external fun nativeVersion(): String

    external fun mldsaKeypairFromSeed(
        seed: ByteArray
    ): Array<ByteArray>?

    external fun sphincsKeypairFromSeed(
        seed: ByteArray
    ): Array<ByteArray>?

    external fun mldsaSign(
        message: ByteArray,
        secretKey: ByteArray
    ): ByteArray?

    external fun mldsaVerify(
        signature: ByteArray,
        message: ByteArray,
        publicKey: ByteArray
    ): Boolean

    external fun sphincsSign(
        message: ByteArray,
        secretKey: ByteArray
    ): ByteArray?

    external fun sphincsVerify(
        signature: ByteArray,
        message: ByteArray,
        publicKey: ByteArray
    ): Boolean
}
