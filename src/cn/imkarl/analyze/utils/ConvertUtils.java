package cn.imkarl.analyze.utils;

/**
 * 转换相关的工具类
 */
public class ConvertUtils {

    private static final char[] HEX_DIGITS = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

    private ConvertUtils() {
    }

    public static int bytes2Int(byte[] src) {
        return ((src[0] & 0xFF)<<24)
                |((src[1] & 0xFF)<<16)
                |((src[2] & 0xFF)<<8)
                |(src[3] & 0xFF);
    }
    public static int bytes2IntReversal(byte[] src) {
        return (src[0] & 0xFF)
                |((src[1] & 0xFF)<<8)
                |((src[2] & 0xFF)<<16)
                |((src[3] & 0xFF)<<24);
    }

    public static short bytes2Short(byte[] src) {
        return (short) (((src[0] & 0xFF)<<8)
                        |(src[1] & 0xFF));
    }
    public static short bytes2ShortReversal(byte[] src) {
        return (short) ((src[0] & 0xFF)
                        |((src[1] & 0xFF)<<8));
    }

    /**
     * byte转hex字符串，一个byte转为2个hex字符
     */
    public static String bytes2Hex(byte src){
        char[] res = new char[2];
        res[0] = HEX_DIGITS[src >>>4 & 0x0f];
        res[1] = HEX_DIGITS[src & 0x0f];
        return new String(res);
    }
    /**
     * bit转byte
     */
    public static byte bitToByte(byte[] bits) {
        return (byte) ((bits[0] << 7)
                | (bits[1] << 6)
                | (bits[2] << 5)
                | (bits[3] << 4)
                | (bits[4] << 3)
                | (bits[5] << 2)
                | (bits[6] << 1)
                | bits[7]);
    }

}
