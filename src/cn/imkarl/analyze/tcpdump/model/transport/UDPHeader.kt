package cn.imkarl.analyze.tcpdump.model.transport

import cn.imkarl.analyze.tcpdump.io.AdvancedInputStream

/**
 * UDP-包头（8 字节）
 * 由4个域组成，每个域各占用2个字节
 */
data class UDPHeader(
        override val srcPort: Int,  // 源端口（2 字节）
        override val dstPort: Int,  // 目的端口（2 字节）
        override val checkSum: Int,   // 校验和（2 字节）
        val length: Int // 数据包长（2 字节）
) : TransportLayer(srcPort, dstPort, checkSum) {

    constructor(stream: AdvancedInputStream):this(
            stream.readShort(),
            stream.readShort(),
            stream.readShort(),
            stream.readShort()
    )

    override fun length(): Int {
        return 8
    }

}
