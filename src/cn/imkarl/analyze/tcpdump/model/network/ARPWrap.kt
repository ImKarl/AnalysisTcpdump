package cn.imkarl.analyze.tcpdump.model.network

import cn.imkarl.analyze.tcpdump.enums.EtherType
import cn.imkarl.analyze.tcpdump.io.AdvancedInputStream
import cn.imkarl.analyze.utils.intValue
import cn.imkarl.analyze.utils.toHex

/**
 * ARP-包头
 *
 * <a href="http://blog.csdn.net/tigerjibo/article/details/7351992">ARP协议分析</a>
 */
data class ARPWrap(
        /**
         * 1: 以太网
         */
        val hardwareType: Int,  // 硬件类型 (2 字节)
        /**
         * 0800: IP
         */
        val protocol: EtherType,  // 协议类型（2 字节）
        val hardwareSize: Int,  // 硬件长度 (1 字节)
        val protocolSize: Int,  // 协议长度 (1 字节)
        /**
         * 1: ARP请求
         * 2: ARP应答
         */
        val opcode: Int,  // 操作类型 (2 字节)
        val srcMac: String,  // 源 MAC地址（6 字节）
        val srcIP: String,  // 源 IP地址（4 字节）
        val dstMac: String,  // 目的 MAC地址（6 字节）
        val dstIP: String  // 目的 MAC地址（4 字节）
): NetworkLayer {

    companion object {
        private fun getMacString(mac: ByteArray): String {
            return "${mac[0].toHex()}:${mac[1].toHex()}:${mac[2].toHex()}:${mac[3].toHex()}:${mac[4].toHex()}:${mac[5].toHex()}"
        }
        private fun getIPString(ip: ByteArray): String {
            return "${ip[0].intValue()}.${ip[1].intValue()}.${ip[2].intValue()}.${ip[3].intValue()}"
        }
    }

    constructor(stream: AdvancedInputStream):this(
            stream.readShort(),
            EtherType.valueOf(stream.readShortReversal().toShort())!!,
            stream.readByte(),
            stream.readByte(),
            stream.readShort(),
            getMacString(stream.readBytes(6)),
            getIPString(stream.readBytes(4)),
            getMacString(stream.readBytes(6)),
            getIPString(stream.readBytes(4))
    )

    override fun length(): Int {
        return 28
    }

}