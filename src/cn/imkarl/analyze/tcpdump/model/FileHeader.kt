package cn.imkarl.analyze.tcpdump.model

import cn.imkarl.analyze.tcpdump.io.AdvancedInputStream

/**
 * 文件头信息
 */
data class FileHeader(
        val mainVersion: Int,       // 主版本号（2个字节）
        val subVersion: Int,        // 副版本号（2个字节）
        val timezone: Int,          // 区域时间（4个字节）
        val sigfigs: Int,           // 精确时间戳（4个字节）
        val snaplen: Int,           // 数据包最大长度（4个字节）
        val linktype: Int           // 链路层类型（4个字节）
) {
    constructor(stream: AdvancedInputStream) : this(
            stream.readShortReversal(),
            stream.readShortReversal(),
            stream.readIntReversal(),
            stream.readIntReversal(),
            stream.readIntReversal(),
            stream.readIntReversal()
    )
}
