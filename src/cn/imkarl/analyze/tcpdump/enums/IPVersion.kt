package cn.imkarl.analyze.tcpdump.enums

/**
 * IP协议版本：
 * 0100     IPv4
 * 0110     IPv6
 */
enum class IPVersion(val code: Byte) {

    IPv4(4),
    IPv6(6);

    companion object {
        fun valueOf(code: Byte): IPVersion? {
            for (item in values()) {
                if (item.code == code) {
                    return item
                }
            }
            return null;
        }
    }

}