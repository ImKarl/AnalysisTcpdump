package cn.imkarl.analyze.tcpdump.io

import cn.imkarl.analyze.utils.*
import java.io.InputStream

/**
 * 拓展InputStream支持更多高级用法
 */
class AdvancedInputStream(stream: InputStream): BitInputStream(stream) {

    companion object {
        private val LENGTH_SHORT_BY_BYTE = 2
        private val LENGTH_INT_BY_BYTE = 4
    }


    fun readShort(): Int {
        val result = ByteArray(LENGTH_SHORT_BY_BYTE)
        if (super.readByteArray(result) == -1) {
            return -1
        }
        return result.toShort().intValue()
    }
    fun readShortReversal(): Int {
        val result = ByteArray(LENGTH_SHORT_BY_BYTE)
        if (super.readByteArray(result) == -1) {
            return -1
        }
        return result.toShortReversal().intValue()
    }

    fun readInt(): Int {
        val result = ByteArray(LENGTH_INT_BY_BYTE)
        if (super.readByteArray(result) == -1) {
            return -1
        }
        return result.toInt()
    }
    fun readIntReversal(): Int {
        val result = ByteArray(LENGTH_INT_BY_BYTE)
        if (super.readByteArray(result) == -1) {
            return -1
        }
        return result.toIntReversal()
    }

}