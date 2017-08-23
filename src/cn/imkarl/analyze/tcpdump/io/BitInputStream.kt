package cn.imkarl.analyze.tcpdump.io

import cn.imkarl.analyze.utils.ConvertUtils
import cn.imkarl.analyze.utils.intValue
import java.io.Closeable
import java.io.IOException
import java.io.InputStream

/**
 * 按位(bit)读取的输入流
 */
open class BitInputStream(private val stream: InputStream): Closeable {

    companion object {
        private val LENGTH_BYTE_BY_BIT = 8
        private val MAX_SKIP_BUFFER_SIZE = 2048
    }


    private var tempValue: Int? = null  // 临时变量，用于存储按bit读取时，缓冲的单个字节
    private var next: Int = -1

    /**
     * 读取一个bit，值为1或0
     * @return -1表示结束
     */
    fun readBit(): Int {
        if (next == -1) {
            next = 7
            tempValue = stream.read()
            if (tempValue == -1) {
                return -1
            }
        }
        return (tempValue!! and (1 shl next)).ushr(next--)
    }

    /**
     * 读取多个bit
     * @return -1表示结束
     */
    fun readBitArray(bits: ByteArray): Int {
        if (bits.isEmpty()) {
            throw IndexOutOfBoundsException()
        }

        var b: Int
        var i = 0
        while (i < bits.size) {
            b = readBit()
            if (b == -1) {
                return -1
            }
            bits[i++] = b.toByte()
        }

        return i
    }
    /**
     * 读取多个bit
     * @throws IOException 无法读取，输入流已结束
     */
    fun readBits(size: Int): ByteArray {
        val result = ByteArray(size)
        if (readBitArray(result) == -1) {
            throw IOException()
        }
        return result
    }


    /**
     * 读取一个byte
     * @return -1表示结束
     */
    fun readByte(): Int {
        // 优化：如果没有缓冲的bit数据，直接操作原始stream
        if (next == -1) {
            return stream.read()
        }

        val result = ByteArray(LENGTH_BYTE_BY_BIT)
        if (readBitArray(result) == -1) {
            return -1
        }
        return ConvertUtils.bitToByte(result).intValue()
    }


    /**
     * 读取多个byte
     * @return -1表示结束
     */
    fun readByteArray(bytes: ByteArray): Int {
        if (bytes.isEmpty()) {
            return 0
        }

        // 优化：如果没有缓冲的bit数据，直接操作原始stream
        if (next == -1) {
            return stream.read(bytes)
        }

        var b: Int
        var i = 0
        while (i < bytes.size) {
            b = readByte()
            if (b == -1) {
                return -1
            }
            bytes[i] = b.toByte()
            i++
        }

        return i
    }
    /**
     * 读取多个byte
     * @throws IOException 无法读取，输入流已结束
     */
    fun readBytes(size: Int): ByteArray {
        val result = ByteArray(size)
        if (readByteArray(result) == -1) {
            throw IOException()
        }
        return result
    }


    /**
     * 跳过多个bit
     */
    fun skipBits(len: Int): Int {
        var remaining = len
        var nr: Int

        if (len <= 0) {
            return 0
        }

        val size = Math.min(MAX_SKIP_BUFFER_SIZE, remaining)
        val skipBuffer = ByteArray(size)
        while (remaining > 0) {
            nr = readBitArray(skipBuffer)
            if (nr < 0) {
                break
            }
            remaining -= nr
        }

        return len - remaining
    }

    /**
     * 跳过多个byte
     */
    fun skipBytes(len: Int): Int {
        var remaining = len
        var nr: Int

        if (len <= 0) {
            return 0
        }

        val size = Math.min(MAX_SKIP_BUFFER_SIZE, remaining)
        val skipBuffer = ByteArray(size)
        while (remaining > 0) {
            nr = readByteArray(skipBuffer)
            if (nr < 0) {
                break
            }
            remaining -= nr
        }

        return (len - remaining) + skipBytes(remaining)
    }


    override fun close() {
        tempValue = null
        next = -1
    }

}