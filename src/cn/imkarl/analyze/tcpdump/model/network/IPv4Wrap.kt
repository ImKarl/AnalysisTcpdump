package cn.imkarl.analyze.tcpdump.model.network

import cn.imkarl.analyze.tcpdump.enums.IPProtocol
import cn.imkarl.analyze.tcpdump.enums.IPVersion
import cn.imkarl.analyze.tcpdump.io.AdvancedInputStream
import cn.imkarl.analyze.utils.intValue
import cn.imkarl.analyze.utils.toShort

/**
 * IPv4-包头
 */
data class IPv4Wrap(
        /**
         * 协议版本号(4 bit)及包头长度(4bit) =（1 字节）
         * IP包头最小长度为20字节
         */
        val version: IPVersion,  // 协议版本号 (4 bit)
        val headerLen: Int,  // 包头长度，一般的值为0101 (4 bit)

        val tos: Byte,  // Type of  Service：服务类型，（1 字节）
        val totalLen: Int,  // 总长度（2 字节）
        val identification: Int,  // 标识（2 字节）
        val flagSegment: Short,  // 标志与偏移量（2 字节）
        val ttl: Byte,  // Time to Live：生存周期（1 字节）
        val protocol: IPProtocol,  // 协议类型（1 字节）
        val checkSum: Int,  // 头部校验和（2 字节）
        val srcIP: String,  // 源 IP（4 字节）
        val dstIP: String  // 目的 IP（4 字节）
): NetworkLayer {

    companion object {
        private fun getIPString(ip: ByteArray): String {
            return "${ip[0].intValue()}.${ip[1].intValue()}.${ip[2].intValue()}.${ip[3].intValue()}"
        }

        private fun bits2Int(bits: ByteArray): Int {
            val size = bits.size
            var sum = 0
            for (i in 0..size-1) {
                sum += bits[(size-1-i)] * Math.pow(2.0, i.toDouble()).toInt()
            }
            return sum
        }
    }

    constructor(stream: AdvancedInputStream):this(
            IPVersion.valueOf(bits2Int(stream.readBits(4)).toByte())!!,
            bits2Int(stream.readBits(4)),
            stream.readByte().toByte(),
            stream.readBytes(2).toShort().intValue(),
            stream.readBytes(2).toShort().intValue(),
            stream.readShort().toShort(),
            stream.readByte().toByte(),
            IPProtocol.valueOf(stream.readByte().toByte()),
            stream.readBytes(2).toShort().intValue(),
            getIPString(stream.readBytes(4)),
            getIPString(stream.readBytes(4))
    )

    override fun length(): Int {
        return 20
    }

}
