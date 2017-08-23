package cn.imkarl.analyze.tcpdump.enums

import cn.imkarl.analyze.utils.log

/**
 * IP协议
 */
enum class IPProtocol(val code: Byte) {

    ICMP(1),
    IGMP(2),
    TCP(6),
    UDP(17),
    UNKNOW(0);

    companion object {
        fun valueOf(code: Byte): IPProtocol {
            for (protocol in values()) {
                if (protocol.code == code) {
                    return protocol
                }
            }
            "IPProtocol.code=$code".log()
            return UNKNOW;
        }
    }

}