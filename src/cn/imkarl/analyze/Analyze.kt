package cn.imkarl.analyze

import cn.imkarl.analyze.tcpdump.enums.EtherType
import cn.imkarl.analyze.tcpdump.enums.IPProtocol
import cn.imkarl.analyze.tcpdump.io.AdvancedInputStream
import cn.imkarl.analyze.tcpdump.model.FileHeader
import cn.imkarl.analyze.tcpdump.model.network.IPv4Wrap
import cn.imkarl.analyze.tcpdump.model.network.NetworkLayer
import cn.imkarl.analyze.tcpdump.model.transport.TransportLayer
import cn.imkarl.analyze.utils.log
import cn.imkarl.analyze.utils.toFormatString
import cn.imkarl.analyze.utils.toHex
import java.io.File
import java.io.FileInputStream
import java.nio.charset.Charset
import java.util.*

/**
 * Tcpdump文件解析
 */
object Analyze {

    // 是否调试模式（打印日志）
    private val DEBUG = false

    // 文件类型
    private val FILE_MARK_BYTE = byteArrayOf(0xd4.toByte(), 0xc3.toByte(), 0xb2.toByte(), 0xa1.toByte())
    private val FILE_MARK_LENGTH = 4

    // 文件名后缀
    private val FILE_EXTENSION = "cap"

    // 私有端口(最小值)
    private val PRIVATE_PORT_MIN = 49152

    private fun getMacString(mac: ByteArray): String {
        return "${mac[0].toHex()}:${mac[1].toHex()}:${mac[2].toHex()}:${mac[3].toHex()}:${mac[4].toHex()}:${mac[5].toHex()}"
    }


    fun analyze(dir: File) {
        if (!dir.exists()) {
            "dir not exists".log()
            return
        }
        if (dir.isDirectory) {
            dir.listFiles().forEach {
                analyze(it)
            }
        }
        if (dir.isFile) {
            if (!dir.name.toLowerCase().endsWith(FILE_EXTENSION)) {
                return
            }


            "analyze file: ${dir.absolutePath}".log()
            "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~".log()

            val stream = AdvancedInputStream(FileInputStream(dir))

            // 鉴别文件格式
            val headByte = stream.readBytes(FILE_MARK_LENGTH)
            if (!Arrays.equals(headByte, FILE_MARK_BYTE)) {
                if (DEBUG) {
                    "The input stream is not tcpdump.".log()
                }
            }

            val time = System.currentTimeMillis()
            analyzeFile(stream)
            val duration = System.currentTimeMillis() - time

            "analyze duration: ${duration}ms".log()
            "~~~~~~~~~~~~~~~~~~~~~~~~~~~ analyze over ~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n".log()
        }
    }

    private fun analyzeFile(stream: AdvancedInputStream) {
        // fileHeader 文件头信息
        FileHeader(stream).log()

        var network: NetworkLayer       // （网络层）   「Packet」
        var transport: TransportLayer   // （传输层）   「Segment」

        var index = 0
        while (true) {
            /*
             * 以下为一个数据片段
             */

            val sTime = stream.readIntReversal()
            if (sTime <= 0) {
                break
            }
            index++

            // item 数据包信息
            val timestamp = sTime * 1000L + stream.readIntReversal()
            val caplen = stream.readIntReversal()
            val len = stream.readIntReversal()
            if (DEBUG) {
                "~~~~~ ${Date(timestamp).toFormatString()}  caplen=$caplen  len=$len ~~~~~".log()
            }

            // 数据内容长度（包括所有header信息）
            var dataLength = caplen

            // Frame 数据链路层
            val ether_dhost = getMacString(stream.readBytes(6))
            val ether_shost = getMacString(stream.readBytes(6))
            val ether_type_code = stream.readShortReversal().toShort()
            val ether_type = EtherType.valueOf(ether_type_code)
            if (DEBUG) {
                "ether_dhost=$ether_dhost  ether_shost=$ether_shost  ether_type=$ether_type".log()
            }

            dataLength -= 14

            if (ether_type != null) {
                // Packet 网络层
                network = NetworkLayer.parse(ether_type, stream)
                dataLength -= network.length()

                if (network is IPv4Wrap) {
                    if (network.protocol == IPProtocol.TCP
                            || network.protocol == IPProtocol.UDP) {
                        // Segment 传输层
                        transport = TransportLayer.parse(network.protocol, stream)
                        dataLength -= transport.length()

                        // Application 应用层
                        if (transport.dstPort < PRIVATE_PORT_MIN) {
                            val bytes = stream.readBytes(dataLength)
                            if (bytes.isNotEmpty() && bytes.size > 25) {
                                val content = bytes.toString(Charset.forName("UTF-8"))
                                if (content.startsWith("GET ")
                                        || content.startsWith("POST ")) {
                                    // HTTP
                                    "index=$index  ${content.substring(0, content.indexOf("\n"))}".log()
                                } else {
                                    //"index=$index   content=${content}".log()
                                }
                            }
                            dataLength = 0
                        }
                    }
                }
            }

            // 确保跳过整个 packet
            stream.skipBytes(dataLength)

        }
        "\nanalyze count=$index".log()
    }

}