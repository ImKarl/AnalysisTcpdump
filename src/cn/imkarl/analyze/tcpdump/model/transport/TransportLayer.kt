package cn.imkarl.analyze.tcpdump.model.transport

import cn.imkarl.analyze.tcpdump.enums.IPProtocol
import cn.imkarl.analyze.tcpdump.io.AdvancedInputStream
import cn.imkarl.analyze.tcpdump.model.ILayer

/**
 * 传输层
 */
abstract class TransportLayer(
    open val srcPort: Int,   // 源端口（2 字节）
    open val dstPort: Int,   // 目的端口（2 字节）
    open val checkSum: Int   // 校验和（2 字节）
): ILayer {

    companion object {

        private val MAPPING: Map<IPProtocol, Class<out TransportLayer>> = mapOf(
                Pair(IPProtocol.TCP, TCPHeader::class.java),
                Pair(IPProtocol.UDP, UDPHeader::class.java)
        )

        fun parse(protocol: IPProtocol, stream: AdvancedInputStream): TransportLayer {
            val dataClass = MAPPING.get(protocol) ?: throw UnsupportedOperationException("IPProtocol is not supported. protocol: "+protocol)
            return dataClass.getConstructor(AdvancedInputStream::class.java).newInstance(stream)
        }

    }

}