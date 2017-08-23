package cn.imkarl.analyze.tcpdump.model.network

import cn.imkarl.analyze.tcpdump.enums.EtherType
import cn.imkarl.analyze.tcpdump.io.AdvancedInputStream
import cn.imkarl.analyze.tcpdump.model.ILayer

interface NetworkLayer: ILayer {

    companion object {

        private val MAPPING: Map<EtherType, Class<out NetworkLayer>> = mapOf(
                Pair(EtherType.IPv4, IPv4Wrap::class.java),
                Pair(EtherType.IPv6, IPv6Wrap::class.java),
                Pair(EtherType.ARP, ARPWrap::class.java)
        )

        fun parse(etherType: EtherType, stream: AdvancedInputStream): NetworkLayer {
            val dataClass = MAPPING.get(etherType) ?: throw UnsupportedOperationException("EtherType is not supported. etherType: "+etherType)
            return dataClass.getConstructor(AdvancedInputStream::class.java).newInstance(stream)
        }

    }

}
