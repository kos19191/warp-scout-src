package dev.warpscout.app.tunnel

import android.content.Context
import java.io.File

/**
 * Последняя конфигурация, на которой туннель реально поднялся, — для автоподъёма.
 *
 * Зачем свой файл, а не `Prefs.lastConfigText`. Настройки пишет интерфейс, и после того как
 * сервис сам сменил точку (прежняя замолчала), в них остаётся уже мёртвый адрес, пока экран не
 * откроют. Этот файл пишет сам сервис в момент удачного подъёма, поэтому в нём всегда ровно та
 * точка, через которую туннель работал последним. Его читают сервис (перезапуск системой,
 * «Постоянный VPN») и приёмник загрузки/обновления ([TunnelAutoStart]).
 *
 * Запись атомарная (временный файл + переименование): после внезапного выключения телефона на
 * месте окажется либо прежний конфиг, либо новый, но не половина строки.
 */
object TunnelLastConfig {

    private const val FILE = "tunnel-last.conf"

    private val lock = Any()

    fun save(context: Context, text: String) {
        if (text.isBlank()) return
        synchronized(lock) {
            runCatching {
                val target = File(context.applicationContext.filesDir, FILE)
                if (target.isFile && runCatching { target.readText() }.getOrNull() == text) return
                val tmp = File(target.parentFile, target.name + ".tmp")
                tmp.writeText(text)
                if (!tmp.renameTo(target)) {
                    target.delete()
                    if (!tmp.renameTo(target)) tmp.copyTo(target, overwrite = true)
                }
            }
        }
    }

    /** Текст конфига или null, если туннель ещё ни разу не поднимался в этой версии. */
    fun load(context: Context): String? = runCatching {
        val f = File(context.applicationContext.filesDir, FILE)
        if (!f.isFile) null else f.readText().takeIf { it.contains("PrivateKey") }
    }.getOrNull()
}
