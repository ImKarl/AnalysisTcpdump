package cn.imkarl.analyze.tcpdump.enums

/**
 * 以太网类型
 * 0x0200   ETHERTYPE_PUP       /* Xerox PUP */
 * 0x0800   ETHERTYPE_IP        /* IP */
 * 0x0806   ETHERTYPE_ARP       /* Address resolution */
 * 0x8035   ETHERTYPE_REVARP    /* Reverse ARP */
 */
enum class EtherType(val code: Short) {
    IPv4(8),
    IPv6(-8826),
    ARP(1544);

    companion object {
        fun valueOf(code: Short): EtherType? {
            for (item in EtherType.values()) {
                if (item.code == code) {
                    return item
                }
            }
            return null;
        }
    }

}