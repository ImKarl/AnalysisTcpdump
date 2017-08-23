package cn.imkarl.analyze

import java.io.File

/**
 * 程序主入口
 * Created by imkarl on 2017/8/5.
 */
object Main {

    private var DIR = File(Analyze::class.java.getResource("/").path)

    @JvmStatic fun main(args: Array<String>) {

        Analyze.analyze(DIR)

    }

}
