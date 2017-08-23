package cn.imkarl.analyze.tcpdump.model

interface ILayer {

    /**
     * 占用的数据长度
     */
    fun length(): Int

}