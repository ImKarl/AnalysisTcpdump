package cn.imkarl.analyze.utils

import java.text.SimpleDateFormat
import java.util.*

fun Any.log() {
    if (this is Throwable) {
        printStackTrace(System.err)
        return
    }
    if (this is ByteArray) {
        val str = Arrays.toString(this)
        System.out.println("ByteArray:${str}");
        return
    }
    System.out.println(this);
}

fun ByteArray.toInt(): Int {
    return ConvertUtils.bytes2Int(this)
}
fun ByteArray.toIntReversal(): Int {
    return ConvertUtils.bytes2IntReversal(this)
}

fun ByteArray.toShort(): Short {
    return ConvertUtils.bytes2Short(this)
}
fun ByteArray.toShortReversal(): Short {
    return ConvertUtils.bytes2ShortReversal(this)
}

fun Byte.toHex(): String {
    return ConvertUtils.bytes2Hex(this)
}


fun Byte.intValue(): Int {
    return this.toInt() and 0xFF
}
fun Short.intValue(): Int {
    return this.toInt() and 0xFFFF
}


fun java.util.Date.format(pattern: String): String {
    return SimpleDateFormat(pattern).format(this)
}
fun java.util.Date.toFormatString(): String {
    return this.format("yyyy-MM-dd HH:mm:ss")
}
