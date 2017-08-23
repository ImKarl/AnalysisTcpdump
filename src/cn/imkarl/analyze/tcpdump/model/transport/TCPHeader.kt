package cn.imkarl.analyze.tcpdump.model.transport

import cn.imkarl.analyze.tcpdump.io.AdvancedInputStream

/**
 * TCP-包头（20 字节）
 */
data class TCPHeader(
        override val srcPort: Int,  // 源端口（2 字节）
        override val dstPort: Int,  // 目的端口（2 字节）

        val sequenceNumber: Int,  // 发送数据包中的第一个字节的序列号（4 字节）
        val ackNumber: Int,  // 确认序列号（4 字节）
        /**
         * 数据报头的长度(4 bit) + 保留(4 bit) = 1 byte
         */
        val headerLen: Int,  // 数据报头的长度（4 bit）
        val flags: Byte,  // 标识TCP不同的控制消息（1 字节）
        val window: Short,  // 接收缓冲区的空闲空间，用来告诉TCP连接对端自己能够接收的最大数据长度（2 字节）
        override val checkSum: Int,   // 校验和（2 字节）
        val urgentPointer: Short,   // 紧急指针（2 字节）
        val options: ByteArray  // 选项部分（可变长度）
) : TransportLayer(srcPort, dstPort, checkSum) {

    companion object {
        // 固定部分长度
        private val LEN_FIXED = 20

        private fun bits2Int(bits: ByteArray): Int {
            val size = bits.size
            var sum = 0
            for (i in 0..size-1) {
                sum += bits[(size-1-i)] * Math.pow(2.0, i.toDouble()).toInt()
            }
            return sum
        }

        private fun readAndSkipBits(stream: AdvancedInputStream, readLen: Int, skipLen: Int): ByteArray {
            val readBits = stream.readBits(readLen)
            stream.skipBits(skipLen)
            return readBits
        }
    }

    constructor(stream: AdvancedInputStream):this(
            stream.readShort(),
            stream.readShort(),
            stream.readIntReversal(),
            stream.readIntReversal(),
            bits2Int(readAndSkipBits(stream, 4, 4)) * 4,
            stream
    )

    // TODO 不够优雅，此处只是为了多次使用headerLen
    private constructor(srcPort: Int, dstPort: Int, sequenceNumber: Int, ackNumber: Int,
                        headerLen: Int,
                        stream: AdvancedInputStream):this(
            srcPort,
            dstPort,
            sequenceNumber,
            ackNumber,
            headerLen,
            stream.readByte().toByte(),
            stream.readShortReversal().toShort(),
            stream.readShortReversal(),
            stream.readShortReversal().toShort(),
            stream.readBytes(headerLen - LEN_FIXED)
    )

    override fun length(): Int {
        return headerLen
    }

}
