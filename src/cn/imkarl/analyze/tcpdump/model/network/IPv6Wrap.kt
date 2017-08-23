package cn.imkarl.analyze.tcpdump.model.network

import cn.imkarl.analyze.tcpdump.enums.IPVersion
import cn.imkarl.analyze.tcpdump.io.AdvancedInputStream
import cn.imkarl.analyze.utils.toHex

/**
 * IPv6-包头
 */
data class IPv6Wrap(
        /**
         * 协议版本号(4 bit)及包头长度(4bit) =（1 字节）
         * IP包头最小长度为20字节
         */
        val version: IPVersion,  // 协议版本号 (4 bit)
        /**
         * 可用于源节点或转寄路由器标识和区分IPV6包中的不同类别或优先级；类似于实现IPV4的TOS/DIFF
         */
        val trafficClass: Int,  // 传输类别 (8 bit)
        /**
         * 数据流是指从某特定的源节点向某特定的目的节点发送的数据包序列。
         * 当源节点希望中间的路由器对数据包进行一些特殊处理时，就可以使用数据流标签，不支持数据流标签的可以赋值为0；
         */
        val flowLabel: Int,  // 流标签 (20 bit)
        /**
         * ipv6的载荷长度，首部以外的长度(包括扩展首部)
         */
        val payloadLength: Int,  // 载荷长度 unsigned integer (2 字节)
        /**
         * 指明紧跟IP首部后面的下一个首部的类型
         */
        val nextHeader: Byte,  // (1 字节)
        /**
         * 在每个传输此包的节点处减1，如果跳数限制减到0，就抛弃此包
         */
        val hopLimit: Byte,  // unsigned integer (1 字节)

        val sourceAddress: String,  // 源地址（16 字节）
        val dstnationAddress: String  // 目的地址（16 字节）
): NetworkLayer {

    companion object {
        private fun getAddressString(mac: ByteArray): String {
            return "${mac[0].toHex()}${mac[1].toHex()}:${mac[8].toHex()}${mac[9].toHex()}:${mac[10].toHex()}${mac[11].toHex()}:${mac[12].toHex()}${mac[13].toHex()}:${mac[14].toHex()}${mac[15].toHex()}"
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
            bits2Int(stream.readBits(8)),
            bits2Int(stream.readBits(20)),
            stream.readShort(),
            stream.readByte().toByte(),
            stream.readByte().toByte(),
            getAddressString(stream.readBytes(16)),
            getAddressString(stream.readBytes(16))
    )

    override fun length(): Int {
        return 40
    }

}
